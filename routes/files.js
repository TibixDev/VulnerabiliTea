// Imports
const express = require('express'),
    router = express.Router(),
    helpers = require('../helpers/helpers.js'),
    User = require('../db/models/user.js'),
    Vulnerability = require('../db/models/vulnerability.js'),
    path = require('path');

// Handle: Serve uploads to users with permission
router.use('/:vtid/:file', async (req, res, next) => {
    let vuln = await Vulnerability.findOne({vtid: req.params.vtid}, 'author public tokens').lean();
    if (!vuln) {
        return helpers.sendError(res, 400);
    }
    if (vuln.author != req.session.user) {
        if (!vuln.public) {
            if (req.query.token) {
                if (!await helpers.tokenValid(vuln, req.query.token)) {
                    console.log('Whoops, token check on file DL failed.');
                    return helpers.sendError(res, 403);
                }
            } else {
                return helpers.sendError(res, 403);
            }
        }
    }
    next();
});

router.use((req, _, next) => {
    // For autistic browsers
    req.url = req.url.replace(/\/$/, '');
    next();
});

router.use(express.static(path.join(__dirname, '../files')));

module.exports = router;