var jwt = require('jwt-simple'),
  JWT = require('./schema').JWT,
  async = require('async');

var generateToken = function (cfg, done) {
  async.waterfall([
    function (cb) {
      if (!cfg && cfg.secret) {
        return cb("no config object found");
      }
      var createdAt = new Date().getTime(),
        exp = cfg.exp || 1 * 24 * 60 * 60 * 1000;
      // console.log(createdAt,exp + createdAt);
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
      var token = jwt.encode(payload, cfg.secret);
      var jwtToken = new JWT();
      jwtToken.token = token;
      jwtToken.ext = exp;
      // console.log(1, jwtToken)
      cb(null, jwtToken);
    },
    function (jwtToken, cb) {
      jwtToken.save(function (err, data) {
        if (err)
          return cb(err);
        cb(null, data);
      });
    }

  ],
    function (err, data) {
      if (err)
        return done(err);
      done(null, data);
    });
}

var authToken = function (cfg, done) {
  console.log(cfg)
  async.waterfall([
    function (cb) {
      console.log(1)
      if (!cfg || !cfg.token || !cfg.secret)
        return cb("configuration object not found");
      cb(null, cfg);
    },
    function (cfg, cb) {
      console.log(2)
      JWT.findOne({ 'token': cfg.token }, function (err, doc) {
        if (err)
          return cb(err);
        if (!doc)
          return cb("Token not found");
        cb(null, doc, cfg);
      });
    },
    function (doc, cfg, cb) {
      console.log(3)
      console.log(doc);
      var DbDecode = jwt.decode(doc.token, cfg.secret);

      var currentDate = new Date();
      if (currentDate.getTime() > doc.exp) {
        deleteToken(doc, cb);
        return cb("Authentication error");
      } else {
        doc.exp = currentDate.getTime() + DbDecode.ext;
        cb(null, doc, DbDecode);
      }
    },
    function (doc, DbDecode, cb) {
      console.log(4)
      doc.save(function (err, data) {
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
    function (err, data) {
      if (err)
        return done(err);
      done(null, data);
    });
}

//// new coding to start


function deleteToken(doc, cb) {

  JWT.remove({ '_id': doc._id }, function (err, doc) {
    if (err) {
      doc.valid = false;
      doc.save(function (err, data) {
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

}

var destroyToken = function (obj, cb) {
  authToken(obj, function (err, doc) {
    if (err) {
      return cb("Authentication error");
    } else {
      deleteToken(doc, cb);
    }
  });
}

function generateRoleToken(obj, cb) {
  if (obj && obj.secret && obj.role) {
    generateToken(obj, cb);
  } else {
    cb("Invalid config Object");
  }
}


function authRoleToken(roles, obj, cb) {
  // console.log(arguments);
  async.waterfall([
    function (done) {
      if (!roles || !Array.isArray(roles) || !roles.length)
        return done("roles array missing");
      done(null, roles,obj)
    },
    function (roles,obj, done) {
      authToken(obj, function (err, doc) {
      console.log('a1',doc);
        var DbDecode = jwt.decode(doc.data.token, obj.secret);
        if (err) {
          console.log('auth error');
          return done("Authentication error");
        } else {
          return done(null, DbDecode, roles, doc);
        }
      });
    },
    function (DbDecode, roles, doc, done) {
      if (roles.some(function (role, index) {
        return role === DbDecode.role;
      })) {
        return done(null, doc);
      } else {
        console.log('auth error-1');
        return done("Authentication error");
      }
    }
  ], function (err, data) {
    if (err)
      return cb(err);
    cb(null, data);
  });
}


function generateHierarchyToken(obj, cb) {
  if (obj && obj.secret && obj.hierarchyLevel) {
    generateToken(obj, cb);
  } else {
    cb(new Error("Invalid config Object"));
  }
}

function authHierarchyToken(hierarchyLevel, obj, cb) {
  async.waterfall([
    function (done) {
      if (!hierarchyLevel)
        return done("hierarchyLevel missing");
      done(null, hierarchyLevel,obj);
    },
    function ( hierarchyLevel,obj, done) {
      authToken(obj, function (err, doc) {
        if (err)
          return done("Authentication error");
        done(null,  hierarchyLevel,obj,doc)
      });
    },
    function ( hierarchyLevel,obj,doc,done) {
      var DbDecode = jwt.decode(doc.data.token, obj.secret);
      console.log(hierarchyLevel, DbDecode);
      if (DbDecode.hierarchyLevel && DbDecode.hierarchyLevel >= hierarchyLevel) {
        done(null, doc);
      } else {
        done(new Error("Authentication error"));
        console.log('auth error-1');
      }
    }
  ], function (err, data) {
    if (err)
      return cb(err);
    cb(null, data);
  });

}

exports.generateToken = generateToken;
exports.authToken = authToken;
exports.destroyToken = destroyToken;
exports.generateRoleToken = generateRoleToken;
exports.authRoleToken = authRoleToken;
exports.generateHierarchyToken = generateHierarchyToken;
exports.authHierarchyToken = authHierarchyToken;
