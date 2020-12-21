const Mongo = require('../');

let user = {
    email: {
        type: String,
        required: true
    },
    nickname: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    registerDate: {
        type: Date,
        default: Date.now
    },
    reportCount: {
        type: Number,
        default: 0
    },
    groups: {
        type: Array,
        default: []
    }
}

module.exports = Mongo.model('User', user);