var mongoose = require('mongoose');

var JWT = {
  'token': {
    type: String,
    required: true,
    default: '@@@@@@!#############'
  },
  'ext': {
    type: Number
  },
  'valid': {
    type: Boolean,
    default: true
  }
}

var JWT = mongoose.Schema(JWT, {
  versionKey: false
});

exports.JWT = mongoose.model('JWT', JWT);
