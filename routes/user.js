// Imports
const express = require('express'),
    router = express.Router(),
    helpers = require('../helpers/helpers.js'),
    User = require('../db/models/user.js');
    Vulnerability = require('../db/models/vulnerability.js');

router.get('/profile', helpers.isLoggedIn, async (req, res) => {
    let user = await User.findOne({
        _id: req.session.user
    });
    let vulns = await Vulnerability.findOne({
        author: req.session.user
    });
    res.render('user/profile.pug', { user, vulns });
});

/* 
    Profile Infos
        - Name
        - User Icon / Custom Profile Picture
        - Vulnerability Count
        - Registration Date
        - Bio
*/

module.exports = router;