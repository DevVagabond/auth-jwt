var jwt = require('jwt-simple');
var JWT = require('./schema').JWT;


var generateToken = function(obj, cb) {

  if (obj && obj.secret) {

    var createdAt = new Date().getTime(),
      exp = obj.exp || 1 * 24 * 60 * 60 * 1000;
    // console.log(createdAt,exp + createdAt);
    var payload = {
      'role': 'user',
      'createdAt': createdAt,
      'ext': exp,
      'exp': createdAt + exp,
      'valid': true,
      'id': '@@@@@@@########'
    };

    if (obj.role) {
      payload.role = obj.role;
    }

    if (obj.hierarchyLevel) {
      payload.hierarchyLevel = obj.hierarchyLevel;
    }


    // encode 
    var token = jwt.encode(payload, obj.secret);
    var jwtToken = new JWT({ 'token': token });

    jwtToken.save(function(err, doc) {
      if (err) {
        cb(err);
      } else {

        var id = doc._id;
        var decode = jwt.decode(doc.token, obj.secret);
        decode.id = id;
        var newPayload = decode;
        var newToken = jwt.encode(newPayload, obj.secret);


        JWT.findOne({ '_id': doc._id }, function(err, data) {
          data.token = newToken;
          data.save(function(err, doc) {
            if (err) {
              cb(err);
            } else {
              cb(null, doc);
            }
          });
        });
      }
    });
  } else {
    cb(new Error("Please provide cofig object"));
  }
}

var authToken = function(obj, cb) {
  if (obj && obj.token && obj.secret) {
    var decoded = jwt.decode(obj.token, obj.secret),
      id = decoded.id;

    JWT.findOne({ '_id': id }, function(err, doc) {
      if (err) {
        cb(err);
      } else {

        if (doc) {
          var DbDecode = jwt.decode(doc.token, obj.secret);
          if (DbDecode.valid) {

            console.log(new Date().getTime(), DbDecode.exp);

            if (new Date().getTime() > DbDecode.exp) {
              deleteToken(doc);
              cb(new Error("Authentication error"));
            } else {
              console.log("time before", DbDecode.exp);
              DbDecode.exp = new Date().getTime() + DbDecode.ext;
              console.log("time afetr", DbDecode.exp);
              doc.token = jwt.encode(DbDecode, obj.secret);
              doc.save(function() {
                if (err) {
                  cb(new Error("Authentication error"));
                } else {
                  cb(null, doc);
                }
              })
            }
          } else {
            cb(new Error("Authentication error"));
          }
        } else {
          cb(new Error("Authentication error"));
        }
      }
    });


  } else {
    if (!obj) {
      console.log(new Error("Please provide cofig object"));
      cb(new Error("Please provide cofig object"));
    } else if (!obj.token) {
      cb(new Error("Please provide token"));
    } else if (!obj.secret) {
      cb(new Error("Please provide secret key"));
    }
  }
}

function deleteToken(doc) {

  JWT.remove({ '_id': doc._id }, function(err, doc) {
    if (err) {
      doc.valid = false;

      doc.save(function(err, data) {
        if (err) {
          console.log("error while deleting");
        } else {
          console.log("saved");
        }
      });
    } else {
      console.log("deleted");
    }
  });

}

var destroyToken = function(obj, cb) {
  authToken(obj, function(err, doc) {
    if (err) {
      cb(new Error("Authentication error"));
    } else {
      deleteToken(doc, cb);
    }
  });
}

function generateRoleToken(obj, cb) {
  if (obj && obj.secret && obj.role) {
    generateToken(obj, cb);
  } else {
    cb(new Error("Invalid config Object"));
  }
}

function authRoleToken(roles, obj, cb) {
  // console.log(arguments);

  if (roles && Array.isArray(roles) && roles.length) {

    authToken(obj, function(err, doc) {
      var DbDecode = jwt.decode(doc.token, obj.secret);
      if (err) {
        cb(new Error("Authentication error"));
        console.log('auth error');
      } else {
        if (roles.some(function(elem, index) {
            return elem === DbDecode.role;
          })) {
          cb(null, doc);
        } else {
          cb(new Error("Authentication error"));
          console.log('auth error-1');
        }
      }

    });
  } else {
    cb(new Error("Roles array missing"));
  }
}


function generateHierarchyToken(obj, cb) {
  if (obj && obj.secret && obj.hierarchyLevel) {
    generateToken(obj, cb);
  } else {
    cb(new Error("Invalid config Object"));
  }
}

function authHierarchyToken(hierarchyLevel, obj, cb) {
  if (!hierarchyLevel) {
    cb(new Error("hierarchyLevel missing"));
  } else {
    authToken(obj, function(err, doc) {
      if (err) {
        cb(new Error("Authentication error"));
        console.log('auth error');
      } else {
        var DbDecode = jwt.decode(doc.token, obj.secret);
        console.log(hierarchyLevel, DbDecode);
        if (DbDecode.hierarchyLevel && DbDecode.hierarchyLevel >= hierarchyLevel) {
          cb(null, doc);
        } else {
          cb(new Error("Authentication error"));
          console.log('auth error-1');
        }
      }
    });
  }
}

exports.generateToken = generateToken;
exports.authToken = authToken;
exports.destroyToken = destroyToken;
exports.generateRoleToken = generateRoleToken;
exports.authRoleToken = authRoleToken;
exports.generateHierarchyToken = generateHierarchyToken;
exports.authHierarchyToken = authHierarchyToken;
