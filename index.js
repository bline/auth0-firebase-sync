const fbadmin  = require('firebase-admin');
const async    = require('async');
const express  = require('express');
const Webtask  = require('webtask-tools');
const app      = express();
const Request  = require('request');
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
  console.log("in lastLogCheckpoint");

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
    if (err && err.output.statusCode !== 404) return res.status(err.code).send(err);

    let startCheckpointId = typeof data === 'undefined' ? null : data.checkpointId;

    // Start the process.
    async.waterfall([
      (callback) => {
        const getLogs = (context) => {
          console.log(`Logs from: ${context.checkpointId || 'Start'}.`);

          let take = Number.parseInt(ctx.data.BATCH_SIZE);

          context.logs = context.logs || [];

          getLogsFromAuth0(req.webtaskContext.data.AUTH0_DOMAIN, req.access_token, take, context.checkpointId, (err, logs) => {
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
          });
        };

        getLogs({ checkpointId: startCheckpointId });
      },
      (context, callback) => {
        // sdu successful user deletion
        context.logs = context.logs
          .filter(l => l.type === 'sdu' || l.type == 'ss');

        callback(null, context);
      },
      (context, callback) => {
        console.log("Logs: " + context.logs.length);
        if (!context.logs.length) {
          return callback(null, context);
        }


        context.userDeleteMatches = {};
        var errors = [];
        context.logs.forEach(log => {
          console.log("Log: ", log);
          const userId = log.description.split(/:\s+/, 1)[1];
          if (!userId) {
            console.log("Missing description from log entry: ", log);
            errors.push("Missing userId from description: " + log.description);
          } else if (log.type === 'sdu') {
            context.userDeleteMatches[userId] = true;
          } else if (log.type === 'ss') {
            delete context.userDeleteMatches[userId];
          }
        });
        callback(err, context);
      },
      (context, callback) => {
        const concurrent_calls = 3;
        const errors = [];

        if (context.userDeleteMatches.keys().length === 0)
          return callback(null, context);

        console.log("UserDeleteMatches: ", context.userDeleteMatches);
        async.eachLimit(context.userDeleteMatches.keys(), concurrent_calls, function (userId, cb) {
          userExists(userId, (err, email) => {
            if (err) {
              errors.push("" + err);
            }
            if (!email && !err) {
              deleteFirebaseUser(userId, (err) => {
                if (err) {
                  errors.push("" + err);
                }
                cb();
              });
            }
          });
        }, (err) => {
          if (!err && errors) 
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
  console.log("Delete Firbase User " + userId);
  fbadmin.auth().deleteUser(userId)
    .then(() => cb(null))
    .catch(e => cb(e));
}

function userExits(userId, cb) {
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
      console.log("Error getting user " + userId + ": ", err);
      cb(null, false);
    } else {
      cb(null, true);
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
