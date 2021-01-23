// Imports
const express = require("express"),
    router = express.Router(),
    helpers = require("../helpers/helpers.js"),
    multer = require("multer"),
    upload = multer(),
    { body, validationResult } = require("express-validator"),
    crypto = require("crypto");

// Model Imports
const User = require("../db/models/user.js");
const Vulnerability = require("../db/models/vulnerability.js");

// Handle: Vulnerability Management
router.get("/", helpers.isLoggedIn, async (req, res) => {
    let vulns = await Vulnerability.find({ author: req.session.user });
    res.render("vuln/vuln", { vulns, ownEntries: 'true' });
});

router.get("/add", helpers.isLoggedIn, (req, res) => {
    res.render("vuln/vuln-add");
});

/* We respond with JSON for the client to parse
    instead of rendering, because trumbowyg can only
    provide multipart-form-data (kms) */
router.post(
    ["/add", "/edit"],
    helpers.isLoggedIn,
    upload.none(),
    [
        body("affectedProduct")
            .exists()
            .withMessage("There was no affected product specified.")
            .isLength({ min: 3, max: 32 })
            .withMessage(
                "The affected product specified didn't match the desired length (3-32 Characters)"
            ),
        body("affectedFeature")
            .exists()
            .withMessage("There was no affected feature specified.")
            .isLength({ min: 3, max: 32 })
            .withMessage(
                "The affected feature specified didn't match the desired length (3-32 Characters)"
            ),
        body("vulnType")
            .exists()
            .withMessage("There was no vulnerability type specified.")
            .isIn([
                "Reflective XSS",
                "Stored XSS",
                "SSRF",
                "RCE",
                "CSRF",
                "Other",
            ])
            .withMessage("The vulnerability type specified was invalid"),
        body("cvssScore")
            .exists()
            .withMessage("There was no CVSS score specified.")
            .isFloat({ min: 1.0, max: 10.0 })
            .withMessage(
                "The CVSS score specified was non-numeric, or invalid."
            ),
        body("description")
            .exists()
            .withMessage("There was no description specified.")
            .isLength({ min: 10 })
            .withMessage(
                "The description specified didn't match the desired minimum length (10+ Characters)"
            ),
        body("bountyAmount")
            .isFloat()
            .withMessage("The bounty specified was not a number."),
    ],
    async (req, res) => {
        const validationErrors = validationResult(req);
        if (!validationErrors.isEmpty()) {
            let errList = [];
            for (err of validationErrors.array()) {
                errList.push({
                    noteType: "note-danger",
                    pretext: "Error ",
                    value: err.msg,
                });
            }
            return res.json({ status: "failed", msgs: errList });
        }
        // TODO: Strip slashes from the url, it's easier to compare it that way
        switch (req.url) {
            case '/add/':
                let vulnerability = new Vulnerability({
                    vtid: "vt-" + crypto.randomBytes(3).toString("hex"),
                    cvss: req.body.cvssScore,
                    type: req.body.vulnType,
                    affectedProduct: req.body.affectedProduct,
                    affectedFeature: req.body.affectedFeature,
                    status: req.body.status,
                    author: req.session.user,
                    description: req.body.description,
                    bounty: req.body.bountyAmount || 0,
                });
                await vulnerability.save();
                res.json({ status: "success" });
                break;
            case '/edit/':
                if (!req.body.vtid) {
                    return res.status(400).json({
                        status: 'failed',
                        error: 'emptyvtid'
                    });
                }
                let editableVulnerability = await Vulnerability.findOne({
                    vtid: req.body.vtid
                });
                if (!editableVulnerability) {
                    return res.status(400).json({
                        status: 'failed',
                        error: 'novuln'
                    });
                }
                if (editableVulnerability.author == req.session.user) {
                    editableVulnerability.cvss = req.body.cvssScore;
                    editableVulnerability.type = req.body.vulnType;
                    editableVulnerability.affectedProduct = req.body.affectedProduct;
                    editableVulnerability.affectedFeature = req.body.affectedFeature;
                    editableVulnerability.status = req.body.status;
                    editableVulnerability.author = req.session.user;
                    editableVulnerability.description = req.body.description;
                    editableVulnerability.bounty = req.body.bountyAmount || 0;
                    await editableVulnerability.save();
                    return res.json({ status: "success" });
                }
                return res.status(403).json({
                    status: 'failed',
                    error: 'nopermission'
                });
        }
    }
);

router.get("/id/:vulnID", async (req, res) => {
    let vuln = await Vulnerability.findOne({
        vtid: req.params.vulnID,
    });
    if (vuln) {
        if (vuln.author == req.session.user) {
            //TabID -> Content AriaLabeledBy
            //TabHREF -> TabAriaControls -> Content ID
            let author = await User.findOne({
                _id: req.session.user,
            });
            vuln.author = author.username;
            return res.render("vuln/vuln-view", { vuln });
        } else {
            return helpers.sendError(res, 403);
        }
    }
    return helpers.sendError(res, 400);
});

router.get("/edit/:vulnID", async (req, res) => {
    let vuln = await Vulnerability.findOne({
        vtid: req.params.vulnID,
    });
    if (vuln) {
        if (vuln.author == req.session.user) {
            //TabID -> Content AriaLabeledBy
            //TabHREF -> TabAriaControls -> Content ID
            let author = await User.findOne({
                _id: req.session.user,
            });
            vuln.author = author.username;
            return res.render("vuln/vuln-edit", { vuln });
        } else {
            return helpers.sendError(res, 403);
        }
    }
    return helpers.sendError(res, 400);
});

/*  We need this because we use AJAX to get the vulnerability description
    We could use inline scripts in the Pug template but it's hacky and ugly */
router.post("/desc", async (req, res) => {
    if (!req.body.vtid) {
        return res.status(400).json({
            status: 'failed',
            error: 'emptyvtid'
        });
    }
    let vuln = await Vulnerability.findOne({
        vtid: req.body.vtid
    })
    if (!vuln) {
        return res.status(400).json({
            status: 'failed',
            error: 'novuln'
        });
    }
    if (vuln.author == req.session.user) {
        return res.json({
            status: 'success',
            description: vuln.description
        });
    }
    return res.status(403).json({
        status: 'failed',
        error: 'nopermission'
    });
})

module.exports = router;
