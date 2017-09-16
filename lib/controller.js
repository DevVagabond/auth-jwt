var jwt = require('jwt-simple'),
  JWT = require('./schema').JWT,
  async = require('async');

/**
 * [Function to generate token]
 * @param  {Object}   cfg  [config object]
 * @param  {Function} done [callback]
 * @return {Object}        [Token object]
 */
var generateToken = function(cfg, done) {
  async.waterfall([
      function(cb) {
        if (!cfg && cfg.secret) {
          return cb("no config object found");
        }
        var createdAt = new Date().getTime(),
          exp = cfg.exp || 1 * 24 * 60 * 60 * 1000;

        //creating the payload for token
        var payload = {
          'iss': 'auth-jwt',
          'sub': 'authentication',
          'role': 'user',
          'aud': '',
          'iat': createdAt,
          'ext': exp
        };

        payload.aud = (cfg.user) ? cfg.user : 'user';
        if (cfg.role) {
          payload.role = cfg.role;
        }

        if (cfg.hierarchyLevel) {
          payload.hierarchyLevel = cfg.hierarchyLevel;
        }
        var token = jwt.encode(payload, cfg.secret); //token encryption
        var jwtToken = new JWT();
        jwtToken.token = token;
        jwtToken.ext = exp; //token expire time
        cb(null, jwtToken);
      },
      function(jwtToken, cb) {
        jwtToken.save(function(err, data) {
          if (err)
            return cb(err);
          cb(null, data);
        });
      }

    ],
    function(err, data) {
      if (err)
        return done(err);
      done(null, data);
    });
};

/**
 * [Function to authenticate the token]
 * @param  {Object}   cfg  [config object]
 * @param  {Function} done [callback]
 * @return {Object}        [decoded authentic token object]
 */
var authToken = function(cfg, done) {
  console.log(cfg)
  async.waterfall([
      function(cb) {
        if (!cfg || !cfg.token || !cfg.secret)
          return cb("configuration object not found");
        cb(null, cfg);
      },
      function(cfg, cb) {
        JWT.findOne({
          'token': cfg.token
        }, function(err, doc) {
          if (err)
            return cb(err);
          if (!doc)
            return cb("Token not found");
          cb(null, doc, cfg);
        });
      },
      function(doc, cfg, cb) {
        var DbDecode = jwt.decode(doc.token, cfg.secret); //decryption of the token

        var currentDate = new Date();
        if (currentDate.getTime() > doc.exp) {
          deleteToken(doc, cb);
          return cb("Authentication error");
        } else {
          doc.exp = currentDate.getTime() + DbDecode.ext;
          cb(null, doc, DbDecode);
        }
      },
      function(doc, DbDecode, cb) {
        doc.save(function(err, data) {
          if (err) {
            return cb("Authentication error");
          } else {
            cb(null, {
              'data': data,
              'aud': DbDecode.aud
            });
          }
        });
      }

    ],
    function(err, data) {
      if (err)
        return done(err);
      done(null, data);
    });
};



/**
 * [Function to remove token from database]
 * @param  {Object}   doc [token document]
 * @param  {Function} cb  [Callback function]
 * @return {String}       [message]
 */
function deleteToken(doc, cb) {

  JWT.remove({
    '_id': doc._id
  }, function(err, doc) {
    if (err) {
      doc.valid = false;
      doc.save(function(err, data) {
        if (err) {
          return cb(err);
        } else {
          return cb(null, "status changed");
        }
      });
    } else {
      return cb(null, "deleted");
    }
  });

};

/**
 * [Function to destroy the token]
 * @param  {Object}   obj [description]
 * @param  {Function} cb  [Callback function]
 */
var destroyToken = function(obj, cb) {
  authToken(obj, function(err, doc) {
    if (err) {
      return cb("Authentication error");
    } else {
      deleteToken(doc, cb);
    }
  });
};


/**
 * [Function to generate role-base token for role management]
 * @param  {Object}   obj [config object]
 * @param  {Function} cb  [callback]
 */
function generateRoleToken(obj, cb) {
  if (obj && obj.secret && obj.role) {
    generateToken(obj, cb);
  } else {
    cb("Invalid config Object");
  }
};


/**
 * [Function to authenticate the role-based token]
 * @param  {Array}   roles [description]
 * @param  {Object}   obj   [Config object]
 * @param  {Function} cb    [callback]
 */
function authRoleToken(roles, obj, cb) {
  // console.log(arguments);
  async.waterfall([
    function(done) {
      if (!roles || !Array.isArray(roles) || !roles.length)
        return done("roles array missing");
      done(null, roles, obj)
    },
    function(roles, obj, done) { // decoding the token 
      authToken(obj, function(err, doc) {
        var DbDecode = jwt.decode(doc.data.token, obj.secret);
        if (err) {
          console.log('auth error');
          return done("Authentication error");
        } else {
          return done(null, DbDecode, roles, doc);
        }
      });
    },
    function(DbDecode, roles, doc, done) { // authenticating the roles
      if (roles.some(function(role, index) {
          return role === DbDecode.role;
        })) {
        return done(null, doc);
      } else {
        return done("Authentication error");
      }
    }
  ], function(err, data) {
    if (err)
      return cb(err);
    cb(null, data);
  });
};


/**
 * [Function to generate hierarchy-based token]
 * @param  {Object}   obj [Config object]
 * @param  {Function} cb  [callback function]
 */
function generateHierarchyToken(obj, cb) {
  if (obj && obj.secret && obj.hierarchyLevel) {
    generateToken(obj, cb);
  } else {
    cb(new Error("Invalid config Object"));
  }
};


/**
 * [Function to authenticate the hierarchy-based token]
 * @param  {Number}   hierarchyLevel [hierarchyLevel of the user]
 * @param  {Object}   obj   [Config object]
 * @param  {Function} cb    [callback]
 */
function authHierarchyToken(hierarchyLevel, obj, cb) {
  async.waterfall([
    function(done) {
      if (!hierarchyLevel)
        return done("hierarchyLevel missing");
      done(null, hierarchyLevel, obj);
    },
    function(hierarchyLevel, obj, done) {
      authToken(obj, function(err, doc) {
        if (err)
          return done("Authentication error");
        done(null, hierarchyLevel, obj, doc)
      });
    },
    function(hierarchyLevel, obj, doc, done) { //hierarchy level checking
      var DbDecode = jwt.decode(doc.data.token, obj.secret);
      console.log(hierarchyLevel, DbDecode);
      if (DbDecode.hierarchyLevel && DbDecode.hierarchyLevel >= hierarchyLevel) {
        done(null, doc);
      } else {
        done(new Error("Authentication error"));
        console.log('auth error-1');
      }
    }
  ], function(err, data) {
    if (err)
      return cb(err);
    cb(null, data);
  });
};


/**
 * revealing the functions
 */
exports.generateToken = generateToken;
exports.authToken = authToken;
exports.destroyToken = destroyToken;
exports.generateRoleToken = generateRoleToken;
exports.authRoleToken = authRoleToken;
exports.generateHierarchyToken = generateHierarchyToken;
exports.authHierarchyToken = authHierarchyToken;