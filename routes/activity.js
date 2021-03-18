// Imports
const express = require("express"),
    router = express.Router(),
    helpers = require("../helpers/helpers.js"),
    User = require("../db/models/user.js"),
    Vulnerability = require("../db/models/vulnerability.js"),
    Config = require('../config/config.json');

// Handle: Show Activity
router.get("/", async (req, res) => {
    res.render("activity");
});

router.post("/getActivity", async (req, res) => {
    if (req.body.skipCount) {
        skipCount = 0;
    }
    let vulns = await Vulnerability.find({
        public: true,
    })  .lean()
        .sort({ dateReported: -1 })
        .skip(req.body.skipCount * Config.activity.vulnsPerRequest)
        .limit(Config.activity.vulnsPerRequest);

    if (vulns.length == 0) {
        return res.status(400).json({
            status: "failed",
            err: "endReached"
        });
    }

    for (vuln of vulns) {
        let authorObj = await User.findById(vuln.author);
        vuln.authorName = authorObj.username;
    }
    return res.json({
        status: "success",
        vulns: vulns
    });
});

// TODO: Finish voting procedure (both client-, and server.)
router.post("/processVote", async (req, res) => {
    if (!req.session.user) {
        return res.status(403).json({
            status: "failed",
            err: "notLoggedIn"
        });
    }

    if (!req.body.vtid) {
        return res.status(400).json({
            status: "failed",
            err: "novtid"
        });
    }
    
    let vuln = await Vulnerability.findById(req.body.vtid);

    if (!vuln) {
        return res.status(400).json({
            status: "failed",
            err: "novuln"
        });
    }

    if (!vuln.public) {
        return res.status(403).json({
            status: "failed",
            err: "illegalVoteException"
        });
    }

    
});

module.exports = router;
