// Imports
const express = require("express"),
    router = express.Router(),
    helpers = require("../helpers/helpers.js"),
    User = require("../db/models/user.js"),
    Vulnerability = require("../db/models/vulnerability.js"),
    Config = require('../config/config.json'),
    { body, validationResult } = require("express-validator");

// Handle: Show Activity
router.get("/", async (req, res) => {
    res.render("activity");
});

// Handle: Get Activity
router.post("/getActivity", async (req, res) => {
    if (req.body.skipCount) {
        skipCount = 0;
    }
    let vulns = await Vulnerability.find({
        public: true,
    }, 'author vtid cvss type affectedProduct affectedFeature votes')
        .lean()
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
        let voteScore = 0;
        let ownVote = 'NONE';
        for (vote of vuln.votes || []) {
            if (vote.uid == req.session.user) {
                ownVote = vote.voteStatus;
            }
            if (vote.voteStatus == 'UP') {
                voteScore++;
            } else {
                voteScore--;
            }
        }
        vuln.voteScore = voteScore;
        vuln.ownVote = ownVote;
    }

    for (vuln of vulns) {
        let authorObj = await User.findById(vuln.author, 'username').lean();
        vuln.authorName = authorObj.username;
    }
    return res.json({
        status: "success",
        vulns: vulns
    });
});

router.post("/processVote", helpers.isLoggedInPOST, [
    body("vtid").exists().withMessage({
        text: "There was no VTID specified.",
        type: "noVTID"
    }),
    body("voteType")
        .exists()
        .withMessage({
            text: "There was no vote type specified.",
            type: "noVoteType"
        })
        .isIn(['UP', 'DOWN', 'CANCEL'])
        .withMessage({
            text: "Vote Type was not part of [UP, DOWN, CANCEL].",
            type: "invalidVoteType"
        })
    ], helpers.processValidationErrs, async (req, res) => {
        let vuln = await Vulnerability.findOne({vtid: req.body.vtid}, 'votes public');
    
        if (!vuln) {
            return helpers.sendStyledJSONErr(res,
                {
                    msg: "A vulnerability matching the supplied VTID wasn't found.",
                    type: "notFound",
                },
            400);
        }

        if (!vuln.public) {
            return helpers.sendStyledJSONErr(res,
                {
                    msg: "A vote can only be processed for public vulnerabilities.",
                    type: "illegalVoteException",
                },
            400);
        }

        async function ProcessVote(voteType) {
            if (!vuln.votes.filter(vote => vote.uid == req.session.user).length > 0) {
                vuln.votes.push({uid: req.session.user, voteStatus: voteType});
                await vuln.save();
            } else {
                vuln.votes.map(vote => vote.uid == req.session.user ? vote.voteStatus = voteType : vote);
                await vuln.save();
            }
            res.json({status: 'success'})
        }

        switch (req.body.voteType) {
            case 'UP':
                    ProcessVote('UP');
                break;
            case 'DOWN':
                    ProcessVote('DOWN');
                break;
            case 'CANCEL':
                    vuln.votes = vuln.votes.filter(vote => vote.uid != req.session.user);
                    await vuln.save();
                    res.json({status: 'success'})
                break;
        }
});

module.exports = router;
