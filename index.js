const fbadmin  = require('firebase-admin');
const async    = require('async');
const express  = require('express');
const Webtask  = require('webtask-tools');
const app      = express();
const Request  = require('request');
//Request.debug = true;
const memoizer = require('lru-memoizer');
const NestedError = require('nested-error-stacks');
const crypto   = require('crypto');

function md5(str, raw) {
	var hash = crypto.createHash('md5').update(str);
	if (raw)
		return hash.digest();
	return hash.digest('hex');
}

function lastLogCheckpoint(req, res) {
  let ctx               = req.webtaskContext;
  let required_settings = ['AUTH0_DOMAIN', 'AUTH0_CLIENT_ID', 'AUTH0_CLIENT_SECRET', 'FIREBASE_SECRET_KEY'];
  let missing_settings  = required_settings.filter((setting) => !ctx.data[setting]);

  if (missing_settings.length) {
    return res.status(400).send({ message: 'Missing settings: ' + missing_settings.join(', ') });
  }

  var secretKey;
  try {
    secretKey = fbadmin.credential.cert(JSON.parse(ctx.data.FIREBASE_SECRET_KEY));
  } catch (err) {
    console.log("Error parsing FIREBASE_SECRET_KEY json: ", err);
    return callback(new NestedError('Error parsing FIREBASE_SECRET_KEY json: ', err));
  }
  fbadmin.initializeApp({
    credential: secretKey
  });
  secretKey = null;
  // If this is a scheduled task, we'll get the last log checkpoint from the previous run and continue from there.
  req.webtaskContext.storage.get((err, data) => {
    if (err) {
      console.log("StatusCode: " + err.output.statusCode);
      console.log("Code: " + err.code);
      console.log("Error: ", err);
    }
    if (err && err.output.statusCode !== 404) return res.status(err.code).send(err);

    let startCheckpointId = typeof data === 'undefined' ? null : data.checkpointId;

    // Start the process.
    async.waterfall([
      (callback) => {
        const getLogs = (context) => {
          const handleLogs = (err, logs) => {
            if (err) {
              console.log('Error getting logs from Auth0', err);
              return callback(new NestedError('Error getting logs from Auth0: ', err));
            }

            if (logs && logs.length) {
              logs.forEach((l) => context.logs.push(l));
              context.checkpointId = context.logs[context.logs.length - 1]._id;
            }

            console.log(`Total logs: ${context.logs.length}.`);
            return callback(null, context);
          };
          console.log(`Logs from: ${context.checkpointId || 'Start'}.`);
          let take = Number.parseInt(ctx.data.BATCH_SIZE);
          context.logs = context.logs || [];
          if (!context.checkpointId)
            getInitialLogsFromAuth0(req.webtaskContext.data.AUTH0_DOMAIN, req.access_token, take, handleLogs);
          else
            getLogsFromAuth0(req.webtaskContext.data.AUTH0_DOMAIN, req.access_token, take, context.checkpointId, handleLogs);
        };
        getLogs({ checkpointId: startCheckpointId });
      },
      (context, callback) => {
        // sdu successful user deletion
        context.logs = context.logs
          .filter(l => l.type === 'sdu' || l.type === 'ss' || (l.type === 'sapi' && l.description === 'Delete a user'));

        callback(null, context);
      },
      (context, callback) => {
        context.matches = {};
        if (!context.logs.length) {
          return callback(null, context);
        }

        const errors = [];
        context.logs.forEach(log => {
          var userId, type = '';
          if (log.type === 'sapi') {
            var apiCall;
            if (log.details && log.details.request)
              apiCall = log.details.request.path;
            if (apiCall) {
              userId = decodeURIComponent(/\/([^\/]+)$/.exec(apiCall)[1] || '');
              if (userId)
                type = 'sdu';
            }
          } else {
            type = log.type;
            userId = log.type === 'sdu' ? /user_id:\s+(.+)/.exec(log.description)[1] : log.user_id;
          }
          if (!userId) {
            console.log("Missing description from log entry: ", log);
            errors.push("Missing userId from description: " + log.description);
          } else if (type === 'sdu') {
            context.matches[userId] = true;
          } else if (type === 'ss') {
            if (context.matches[userId])
              delete context.matches[userId];
          }
        });
        var err = null;
        if (errors.length)
          err = new Error(errors.join("; "));
        callback(err, context);
      },
      (context, callback) => {
        const concurrent_calls = 3;
        const errors = [];

        const deleteMatches = Object.keys(context.matches);
        if (deleteMatches.length === 0)
          return callback(null, context);

        async.eachLimit(deleteMatches, concurrent_calls, function (userId, cb) {
          auth0UserExists(req.webtaskContext.data.AUTH0_DOMAIN, req.access_token, userId, (err, userExists) => {
            if (err) {
              console.log("Error from userExists: ", err);
              errors.push("" + err);
            }
            if (!userExists && !err) {
              deleteFirebaseUser(userId, (err) => {
                if (err) {
                  errors.push("" + err);
                }
                cb();
              });
            } else {
              cb();
            }
          });
        }, (err) => {
          if (!err && errors.length) 
            err = new Error(errors.join("; "));
          callback(err, context);
        });
      }
    ], (err, context) => {
      if (err) {
        console.log('Job failed: ', err);

        return req.webtaskContext.storage.set({checkpointId: startCheckpointId}, {force: 1}, (error) => {
          if (error) {
            console.log('Error storing startCheckpoint', error);
            return res.status(500).send({ error: new NestedError('Error storing startCheckpoint: ', error)});
          }

          res.status(500).send({
            error: err
          });
        });
      }

      console.log('Job complete.');

      return req.webtaskContext.storage.set({
        checkpointId: context.checkpointId,
        totalLogsProcessed: context.logs.length
      }, {force: 1}, (error) => {
        if (error) {
          console.log('Error storing checkpoint', error);
          return res.status(500).send({ error: new NestedError('Error storing checkpoint: ', error)});
        }

        res.sendStatus(200);
      });
    });
  });
}

function deleteFirebaseUser(userId, cb) {
  var uid = md5(userId);
  console.log("Delete Firebase User " + userId + ' -> ' + uid);
  fbadmin.auth().deleteUser(uid)
    .then(() => cb(null))
    .catch(e => {
      if (e.errorInfo && e.errorInfo.code === 'auth/user-not-found')
        cb(null);
      else {
        console.log("Error delete: ", e);
        cb(e);
      }
    });
}

function auth0UserExists(domain, token, userId, cb) {
  var url = `https://${domain}/api/v2/users/${userId}`;
  Request({
    method: 'GET',
    url: url,
    json: true,
    qs: {
      fields: 'email'
    },
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json'
    }
  }, (err, res, body) => {
    if (err) {
      console.log("statusCode: " + res.statusCode);
      console.log("Error getting user " + userId + ": ", err);
      cb(err, res.statusCode !== 404);
    } else {
      cb(null, res.statusCode !== 404);
    }
  })

}

function getPageOfLogsFromAuth0 (domain, token, take, from, cb) {
  var url = `https://${domain}/api/v2/logs`;

  Request({
    method: 'GET',
    url: url,
    json: true,
    qs: {
      take: take,
      from: from,
      sort: 'date:1',
      per_page: take
    },
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json'
    }
  }, (err, res, body) => {
    if (err) {
      console.log('Error getting logs', err);
      cb(new NestedError('Error getting logs: ', err));
    } else {
      cb(null, body);
    }
  });
}

function getInitialLogsFromAuth0(domain, token, take, cb) {
  console.log("Fetch initial logs: take: " + take);
  var url = `https://${domain}/api/v2/logs`;

  Request({
    method: 'GET',
    url: url,
    json: true,
    qs: {
      take: take,
      from: null,
      sort: 'date:-1',
      per_page: take
    },
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json'
    }
  }, (err, res, body) => {
    if (err) {
      console.log('Error getting logs', err);
      cb(new NestedError('Error getting logs: ', err));
    } else {
      cb(null, body);
    }
  });
}

function getLogsFromAuth0(domain, token, take, from, cb) {
  var accumulator = [];

  var test = function() {
    return take > 0;
  };

  var iterator = function(iteratorCb) {
    var pageTake = take > 100 ? 100 : take;
    getPageOfLogsFromAuth0(domain, token, pageTake, from, function(err, logs) {
      if (err) {
        iteratorCb(err);
      } else {
        accumulator = accumulator.concat(logs);
        if (pageTake === logs.length) {
          take -= logs.length;
          from = logs[logs.length - 1]._id;
        } else {
          take = 0;
        }
        iteratorCb();
      }
    });
  };

  async.whilst(test, iterator, function(err) {
    if (err) {
      cb(err);
    } else {
      cb(null, accumulator);
    }
  });
}

const getTokenCached = memoizer({
  load: (apiUrl, audience, clientId, clientSecret, cb) => {
    Request({
      method: 'POST',
      url: apiUrl,
      json: true,
      body: {
        audience: audience,
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: clientSecret
      }
    }, (err, res, body) => {
      if (err) {
        cb(null, err);
      } else {
        cb(body.access_token);
      }
    });
  },
  hash: (apiUrl) => apiUrl,
  max: 100,
  maxAge: 1000 * 60 * 60
});

app.use(function (req, res, next) {
  var apiUrl       = `https://${req.webtaskContext.data.AUTH0_DOMAIN}/oauth/token`;
  var audience     = `https://${req.webtaskContext.data.AUTH0_DOMAIN}/api/v2/`;
  var clientId     = req.webtaskContext.data.AUTH0_CLIENT_ID;
  var clientSecret = req.webtaskContext.data.AUTH0_CLIENT_SECRET;

  console.log("GetTokenCached");
  getTokenCached(apiUrl, audience, clientId, clientSecret, function (access_token, err) {
    if (err) {
      console.log('Error getting access_token', err);
      return next(new NestedError('Error getting access_token: ', err));
    }

    req.access_token = access_token;
    next();
  });
});

app.get ('/', lastLogCheckpoint);
app.post('/', lastLogCheckpoint);

module.exports = Webtask.fromExpress(app);
