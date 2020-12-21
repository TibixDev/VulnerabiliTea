const Mongo = require('../');

let group = {
    name: String,
    members: [{
        name: String
    }]
}

module.exports = Mongo.model('Group', group);