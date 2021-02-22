// Imports
const express = require("express"),
    router = express.Router(),
    helpers = require("../helpers/helpers.js"),
    fileUpload = require("express-fileupload"),
    { body, validationResult } = require("express-validator"),
    crypto = require("crypto"),
    Config = require("../config/config.json"),
    fs = require("fs"),
    fileType = require("file-type");

// Model Imports
const User = require("../db/models/user.js");
const Vulnerability = require("../db/models/vulnerability.js");

// Enable Uploads
router.use(
    fileUpload({
        limits: {
            fileSize: Config.upload.maxFileSizeInMB * 1024 * 1024,
        },
        abortOnLimit: true,
        createParentPath: true,
        safeFileNames: true,
        preserveExtension: true,
    })
);

// Handle: Vulnerability Management

// View all entries belonging to the user
router.get("/", helpers.isLoggedIn, async (req, res) => {
    let vulns = await Vulnerability.find({ author: req.session.user });
    res.render("vuln/vuln", { vulns, ownEntries: "true" });
});

router.get("/add", helpers.isLoggedIn, (req, res) => {
    res.render("vuln/vuln-add");
});

// View Vulnerability (template)
router.get("/id/:vulnID", async (req, res) => {
    let vuln = await Vulnerability.findOne({
        vtid: req.params.vulnID,
    });
    if (vuln) {
        if (vuln.author == req.session.user || vuln.public) {
            //TabID -> Content AriaLabeledBy
            //TabHREF -> TabAriaControls -> Content ID
            let author = await User.findOne({
                _id: vuln.author,
            });
            vuln.author = author.username;
            return res.render("vuln/vuln-view", { vuln });
        } else {
            return helpers.sendError(res, 403);
        }
    }
    return helpers.sendError(res, 400);
});

// Edit a vulnerability template if it belongs to the logged-in user (template)
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

/* 
    Vulnerability adding and editing (processing)

    We respond with JSON for the client to parse
    instead of rendering, because trumbowyg can only
    provide multipart-form-data (kms) */
router.post(
    ["/add", "/edit"],
    helpers.isLoggedIn,
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
                "SQL Injection",
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
        let errors = [];

        const validationErrors = validationResult(req);
        if (!validationErrors.isEmpty()) {
            errors = validationErrors.array();
        }

        async function uploadVulnAttachment(file, vtid) {
            let ft = await fileType.fromBuffer(file.data);
            if (ft && ft.ext == 'zip') {
                file.mv(`files/${vtid}/${file.name}`);
            }
            else {
                errors.push({
                    noteType: "note-danger",
                    pretext: "Error ",
                    msg: "Invalid file type"
                });
            }
        }

        if (errors.length > 0) {
            return helpers.sendStyledJSONErr(res, errors);
        }

        let public = req.body.isPublic ? true : false;

        // TODO: Strip slashes from the url, it's easier to compare it that way
        switch (req.url) {
            case "/add/":
                let generatedVtid =
                    "vt-" + crypto.randomBytes(3).toString("hex");
                if (req.files.vulnAttachment) {
                    await uploadVulnAttachment(
                        req.files.vulnAttachment,
                        generatedVtid
                    );
                    if (errors.length > 0) {
                        return helpers.sendStyledJSONErr(res, errors);
                    }
                }
                let vulnerability = new Vulnerability({
                    vtid: generatedVtid,
                    cvss: req.body.cvssScore,
                    type: req.body.vulnType,
                    affectedProduct: req.body.affectedProduct,
                    affectedFeature: req.body.affectedFeature,
                    status: req.body.status,
                    author: req.session.user,
                    description: req.body.description,
                    bounty: req.body.bountyAmount || 0,
                    public: public,
                });
                await vulnerability.save();
                res.json({ status: "success" });
                break;
            case "/edit/":
                if (!req.body.vtid) {
                    return res.status(400).json({
                        status: "failed",
                        error: "emptyvtid",
                    });
                }
                let editableVulnerability = await Vulnerability.findOne({
                    vtid: req.body.vtid,
                });
                if (!editableVulnerability) {
                    return res.status(400).json({
                        status: "failed",
                        error: "novuln",
                    });
                }
                if (editableVulnerability.author == req.session.user) {
                    editableVulnerability.cvss = req.body.cvssScore;
                    editableVulnerability.type = req.body.vulnType;
                    editableVulnerability.affectedProduct =
                        req.body.affectedProduct;
                    editableVulnerability.affectedFeature =
                        req.body.affectedFeature;
                    editableVulnerability.status = req.body.status;
                    editableVulnerability.author = req.session.user;
                    editableVulnerability.description = req.body.description;
                    editableVulnerability.bounty = req.body.bountyAmount || 0;
                    editableVulnerability.public = public;
                    await editableVulnerability.save();
                    return res.json({ status: "success" });
                }
                return res.status(403).json({
                    status: "failed",
                    error: "nopermission",
                });
        }
    }
);

// Delete Vulnerabity (processing)
router.delete("/delete", helpers.isLoggedIn, async (req, res) => {
    if (!req.body.vtid) {
        return res.status(400).json({
            status: "failed",
            error: "novtid",
        });
    }
    let vuln = await Vulnerability.findOne({
        vtid: req.body.vtid,
    });
    if (!vuln) {
        return res.status(400).json({
            status: "failed",
            error: "notfound",
        });
    }
    if (vuln.author != req.session.user) {
        return res.status(403).json({
            status: "failed",
            error: "forbidden",
        });
    }

    // TODO: Fix vuln folder deletion on vuln deletion
    fs.access(`files/${vuln.vtid}/`, (err) => {
        console.log(err);
        if (!err) {
            fs.rmdir(`files/${vuln.vtid}`, { recursive: true }, (err) => {
                console.log(err);
            });
        }
    });
    await vuln.delete();
    return res.json({
        status: "success",
    });
});

/*  Return Vulnerability details as JSON (processing)

    We need this because we use AJAX to get the vulnerability description
    We could use inline scripts in the Pug template but it's hacky and ugly */
router.post("/data", async (req, res) => {
    if (!req.body.vtid) {
        return res.status(400).json({
            status: "failed",
            error: "emptyvtid",
        });
    }
    let vuln = await Vulnerability.findOne({
        vtid: req.body.vtid,
    });
    if (!vuln) {
        return res.status(400).json({
            status: "failed",
            error: "novuln",
        });
    }
    if (vuln.author == req.session.user || vuln.public) {
        return res.json({
            status: "success",
            vuln: vuln,
        });
    }
    return res.status(403).json({
        status: "failed",
        error: "nopermission",
    });
});

module.exports = router;
