var mongoose = require('mongoose');

var JWT = {
    'token': {
        type: String,
        required: true,
        default: '@@@@@@!#############'
    },
    "uid" : {
        type: mongoose.Schema.Types.ObjectId
    }

}

var JWT = mongoose.Schema(JWT);

exports.JWT = mongoose.model('JWT', JWT);
