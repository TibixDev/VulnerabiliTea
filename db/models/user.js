const Mongo = require('../');

let user = {
    username: {
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
    bio: {
        type: String,
        default: 'It appears that nothing is here.'
    }
}

module.exports = Mongo.model('User', user);