// Imports
const express = require('express'),
    router = express.Router(),
    helpers = require('../helpers/helpers.js'),
    User = require('../db/models/user.js'),
    Vulnerability = require('../db/models/vulnerability.js');

router.get('/profile', helpers.isLoggedIn, async (req, res) => {
    let user = await User.findById(req.session.user);
    let vulns = await Vulnerability.find({
        author: req.session.user
    });
    res.render('user/profile.pug', { user, vulns, ownProfile: true });
});

router.get('/profile/:id', helpers.isLoggedIn, async (req, res) => {
    if (req.params.id.length != 24) {
        return helpers.sendError(res, 400);
    }
    let user = await User.findById(req.params.id).lean();
    if (!user) {
        return helpers.sendError(res, 400);
    }
    let vulns = await Vulnerability.find({
        public: true,
        author: req.params.id
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