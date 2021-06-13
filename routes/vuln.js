// Imports
const express = require("express"),
    router = express.Router(),
    helpers = require("../helpers/helpers.js"),
    fileUpload = require("express-fileupload"),
    { body, validationResult } = require("express-validator"),
    crypto = require("crypto"),
    Config = require("../config/config.json"),
    fs = require("fs"),
    fileType = require("file-type"),
    path = require("path");

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
    let vulns = await Vulnerability.find({author: req.session.user}, "-description -attachments");
    res.render("vuln/vuln", {vulns, ownEntries: "true"});
});

router.get("/add", helpers.isLoggedIn, (req, res) => {
    res.render("vuln/vuln-add");
});

// View Vulnerability (template)
router.get("/id/:vulnID", async (req, res) => {
    let vuln = await Vulnerability.findOne({vtid: req.params.vulnID}).lean();
    if (vuln) {
        let author = await User.findById(vuln.author, "username").lean();
        vuln.authorName = author.username;
        if (vuln.author == req.session.user || vuln.public) {
            //TabID -> Content AriaLabeledBy
            //TabHREF -> TabAriaControls -> Content ID
            return res.render("vuln/vuln-view", {vuln});
        }

        if (req.query.token && !vuln.public) {
            if (await helpers.tokenValid(vuln, req.query.token)) {
                return res.render("vuln/vuln-view", {vuln, token: req.query.token});
            }
        }
        return helpers.sendError(res, 403);
    }
    return helpers.sendError(res, 400);
});

// Edit a vulnerability template if it belongs to the logged-in user (template)
router.get("/edit/:vulnID", async (req, res) => {
    let vuln = await Vulnerability.findOne({vtid: req.params.vulnID}).lean();
    if (vuln) {
        if (vuln.author == req.session.user) {
            //TabID -> Content AriaLabeledBy
            //TabHREF -> TabAriaControls -> Content ID
            let author = await User.findById(req.session.user, "username").lean();
            vuln.author = author.username;
            return res.render("vuln/vuln-edit", {vuln});
        } else {
            return helpers.sendError(res, 403);
        }
    }
    return helpers.sendError(res, 400);
});

//  Vulnerability adding and editing (processing)
router.post(
    ["/add", "/edit"],
    helpers.isLoggedInPOST,
    [
        body("affectedProduct")
            .exists()
            .withMessage({
                text: "There was no affected product specified.",
                type: "noAffectedProduct",
            })
            .isLength({
                min: 3,
                max: 32,
            })
            .withMessage({
                text: "The affected product specified didn't match the desired length (3-32 Characters)",
                type: "affectedProductCharLimitMismatch",
            }),
        body("affectedFeature")
            .exists()
            .withMessage({
                text: "There was no affected feature specified.",
                type: "noAffectedFeature",
            })
            .isLength({
                min: 3,
                max: 32,
            })
            .withMessage({
                text: "The affected feature specified didn't match the desired length (3-32 Characters)",
                type: "affectedFeatureCharLimitMismatch",
            }),
        body("vulnType")
            .exists()
            .withMessage({
                text: "There was no vulnerability type specified.",
                type: "noVulnType",
            })
            .isIn([
                "Reflective XSS",
                "Stored XSS",
                "SQL Injection",
                "SSRF",
                "RCE",
                "CSRF",
                "Other",
            ])
            .withMessage({
                text: "The vulnerability type specified was invalid",
                type: "invalidVulnType",
            }),
        body("cvssScore")
            .exists()
            .withMessage({
                text: "There was no CVSS score specified.",
                type: "noCVSS",
            })
            .isFloat({
                min: 1.0,
                max: 10.0,
            })
            .withMessage({
                text: "The CVSS score specified was non-numeric, or invalid.",
                type: "invalidCVSS",
            }),
        body("description")
            .exists()
            .withMessage({
                text: "There was no description specified.",
                type: "noDescription",
            })
            .isLength({
                min: 10,
            })
            .withMessage({
                text: "The description specified didn't match the desired minimum length (10+ Characters)",
                type: "descriptionCharLimitMismatch",
            }),
        body("bountyAmount").isFloat().withMessage({
            text: "The bounty specified was not a number.",
            type: "bountyNaN",
        }),
    ],
    async (req, res) => {
        let errors = [];
        let fileDBEntries = [];

        const validationErrors = validationResult(req);
        if (!validationErrors.isEmpty()) {
            errors = validationErrors.array();
        }

        async function uploadVulnAttachment(file, vtid) {
            let ft = await fileType.fromBuffer(file.data);
            if (ft && ft.ext == "zip") {
                file.mv(`files/${vtid}/${file.name}`);
                console.log(`Current fileDBEntries: ${JSON.stringify(fileDBEntries)}\nFile: ${file.name}\nSize: ${file.size}`);
                console.log(`Current fileDBEntries: ${JSON.stringify(fileDBEntries)}`);
                return {
                    file: file.name,
                    size: file.size,
                };
            } else {
                errors.push({
                    noteType: "note-danger",
                    pretext: "Error ",
                    msg: `[${file.name}] Invalid file type (zip expected, received ${ft.ext})`,
                });
            }
        }

        if (errors.length > 0) {
            return helpers.sendStyledJSONErr(res, errors, 400);
        }

        let public = req.body.isPublic ? true : false;

        req.url = req.url.replace(/\//g, "");
        switch (req.url) {
            case "add":
                let generatedVtid =
                    "vt-" + crypto.randomBytes(3).toString("hex");
                if (req.files) {
                    // We have to handle single and multiple uploads seperately,
                    // Because otherwise it doesn't work
                    if (req.files.vulnAttachment instanceof Array) {
                        for (let i = 0; i < req.files.vulnAttachment.length; i++) {
                            fileDBEntries.push(await uploadVulnAttachment(req.files.vulnAttachment[i], generatedVtid));
                        }
                    } else {
                        fileDBEntries.push(await uploadVulnAttachment(req.files.vulnAttachment, generatedVtid));
                    }

                    // This is not good practice, someone could theoretically
                    // fill the server with garbage without any VTID relations
                    // TODO: Implement a warning system, fix this function
                    if (errors.length > 0) {
                        return helpers.sendStyledJSONErr(res, errors, 400);
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
                    attachments: fileDBEntries,
                    public: public,
                    votes: [{uid: req.session.user, voteStatus: "UP"}]
                });
                await vulnerability.save();
                res.json({status: "success",});
                break;
            case "edit":
                if (!req.body.vtid) {
                    return helpers.sendStyledJSONErr(res,
                        {
                            msg: "A vulnerability matching the supplied VTID wasn't found.",
                            type: "notFound",
                        }, 
                    400);
                }
                let editableVulnerability = await Vulnerability.findOne({
                    vtid: req.body.vtid,
                });
                if (!editableVulnerability) {
                    return helpers.sendStyledJSONErr(res,
                        {
                            msg: "A vulnerability matching the supplied VTID wasn't found.",
                            type: "notFound",
                        },
                    400);
                }

                if (req.body.deletionQueue) {
                    req.body.deletionQueue = JSON.parse(req.body.deletionQueue);
                    if (editableVulnerability.attachments.length > 0) {
                        for (queueEntry of req.body.deletionQueue) {
                            for (attachmentEntry of editableVulnerability.attachments) {
                                if (attachmentEntry.file == queueEntry) {
                                    editableVulnerability.attachments.splice(attachmentEntry, 1);
                                    await fs.unlink(path.join(__dirname, `../files/${req.body.vtid}/${queueEntry}`),
                                        (err) => {
                                            if (err) {
                                                console.log(`Error deleting attachment ${queueEntry} of ${req.body.vtid}`);
                                            }
                                        }
                                    );
                                    await editableVulnerability.save();
                                }
                            }
                        }
                    }
                }

                if (req.files) {
                    if (req.files.vulnAttachment instanceof Array) {
                        for (let i = 0; i < req.files.vulnAttachment.length; i++) {
                            fileDBEntries.push(
                                await uploadVulnAttachment(req.files.vulnAttachment[i], editableVulnerability.vtid)
                            );
                        }
                    } else {
                        fileDBEntries.push(
                            await uploadVulnAttachment(req.files.vulnAttachment, editableVulnerability.vtid)
                        );
                    }
                }

                if (errors.length > 0) {
                    return helpers.sendStyledJSONErr(res, errors, 400);
                }

                if (fileDBEntries.length > 0) {
                    // Avoid duplicates and outdated information
                    for (entry of fileDBEntries) {
                        for (existingEntry of editableVulnerability.attachments) {
                            if (existingEntry.name == entry.name) {
                                editableVulnerability.attachments.splice(editableVulnerability.attachments.indexOf(existingEntry), 1);
                            }
                        }
                    }
                    // ... is needed because if we want to push something with multiple entries then we must spread it with ...
                    editableVulnerability.attachments.push(...fileDBEntries);
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
                    editableVulnerability.public = public;
                    await editableVulnerability.save();
                    return res.json({
                        status: "success",
                    });
                }
                return helpers.sendStyledJSONErr(res,
                    {
                        msg: "You do not have permission to modify this vulnerability.",
                        type: "fordidden",
                    },
                403);
        }
    }
);

// Delete Vulnerabity (processing)
router.delete(
    "/delete",
    helpers.isLoggedIn,
    [
        body("vtid")
            .exists()
            .withMessage({
                text: "There was no VTID specified.",
                type: "noVTID",
            }),
    ],
    helpers.processValidationErrs,
    async (req, res) => {
        let vuln = await Vulnerability.findOne({vtid: req.body.vtid}, "author vtid");
        if (!vuln) {
            return helpers.sendStyledJSONErr(res,
                {
                    msg:
                        "A vulnerability matching the supplied VTID wasn't found.",
                    type: "notFound",
                },
            400);
        }
        if (vuln.author != req.session.user) {
            return helpers.sendStyledJSONErr(res,
                {
                    msg: "You do not have permission to modify this vulnerability.",
                    type: "fordidden",
                },
            403);
        }

        // TODO: Fix vuln folder deletion on vuln deletion
        fs.access(`files/${vuln.vtid}/`, (err) => {
            if (!err) {
                fs.rmdir(`files/${vuln.vtid}`,{recursive: true}, (err) => {
                    console.log(err);
                });
            }
        });
        await vuln.delete();
        return res.json({status: "success"});
    }
);

// Return Vulnerability description as JSON
router.post(
    "/data",
    [
        body("vtid")
            .exists()
            .withMessage({
                text: "There was no VTID specified.",
                type: "noVTID",
            }),
    ],
    helpers.processValidationErrs,
    async (req, res) => {
        let vuln = await Vulnerability.findOne({vtid: req.body.vtid}, "author description public tokens").lean();
        if (!vuln) {
            return helpers.sendStyledJSONErr(res,
                {
                    msg: "A vulnerability matching the supplied VTID wasn't found.",
                    type: "notFound",
                },
            400);
        }
        if (vuln.author == req.session.user || vuln.public) {
            return res.json({status: "success", vuln: vuln});
        }
        if (req.body.token && !vuln.public) {
            if (await helpers.tokenValid(vuln, req.body.token)) {
                return res.json({status: "success", vuln: vuln});
            }
        }
        return helpers.sendStyledJSONErr(res,
            {
                msg: "You do not have permission to view this vulnerability.",
                type: "fordidden",
            },
        403);
    }
);

// Share routes
router.get("/share/:vtid", async (req, res) => {
    let vuln = await Vulnerability.findOne({vtid: req.params.vtid,}, "vtid author public tokens");
    if (vuln) {
        if (!vuln.author == req.session.user) {
            return helpers.sendError(res, 403);
        }
        if (vuln.public) {
            return helpers.sendError(res, 400);
        }
        let tokenDelCount = 0;
        vuln.tokens.forEach((token, i) => {
            console.log(`Token: ${token.code} [ExpDate: ${token.expiryDate.getTime()} | Now: ${Date.now()}]`);
            if (token.expiryDate.getTime() < Date.now()) {
                vuln.tokens.filter((t) => t.code != token.code);
                tokenDelCount++;
            }
        });
        console.log("TokenDelCount: " + tokenDelCount);
        if (tokenDelCount > 0) {
            vuln.save();
        }
        return res.render("vuln/vuln-share", {vuln});
    }
    return helpers.sendError(res, 400);
});

router.post(
    "/share/createToken",
    [
        body("vtid")
            .exists()
            .withMessage({
                text: "There was no VTID specified.",
                type: "noVTID",
            }),
        body("expiryDate")
            .exists()
            .withMessage({
                text: "There was no token expiry date specified.",
                type: "noTokenExpDate",
            })
            .matches(/^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/)
            .withMessage({
                text: "The token date specified was in an invalid format.",
                type: "invalidTokenExpDate",
            })
            // TODO: Monitor date check for errors
    ], helpers.processValidationErrs,
    async (req, res) => {
        let vuln = await Vulnerability.findOne({vtid: req.body.vtid}, "author vtid tokens public");
        if (!vuln) {
            return helpers.sendStyledJSONErr(res,
                {
                    msg: "A vulnerability with the specified VTID couldn't be found.",
                    type: "vulnnotfound",
                },
            400);
        }
        if (vuln.author != req.session.user) {
            return helpers.sendStyledJSONErr(res,
                {
                    msg: "You do not have access to this resource.",
                    type: "forbidden",
                },
            403);
        }
        if (vuln.public) {
            return helpers.sendStyledJSONErr(res,
                {
                    msg: "You cannot generate tokens for a public discovery.",
                    type: "vulnnotprivate",
                },
            400);
        }
        let newToken = {
            code: crypto.randomBytes(5).toString("hex"),
            expiryDate: req.body.expiryDate,
            creationDate: Date.now(),
        };
        vuln.tokens.push(newToken);
        await vuln.save();
        return res.json({status: "success", token: newToken});
    }
);

router.post(
    "/share/deleteToken",
    [
        body("vtid")
        .exists()
        .withMessage({
            text: "There was no VTID specified.",
            type: "noVTID",
        }),
        body("token")
            .exists()
            .withMessage({
                text: "There was no token specified for deletion.",
                type: "noToken",
            }),
    ], helpers.processValidationErrs,
    async (req, res) => {
        let vuln = await Vulnerability.findOne({vtid: req.body.vtid}, "author vtid tokens public");
        if (!vuln) {
            return helpers.sendStyledJSONErr(res,
                {
                    msg: "A vulnerability with the specified VTID couldn't be found",
                    type: "vulnnotfound",
                },
            400);
        }
        if (vuln.author != req.session.user) {
            return helpers.sendStyledJSONErr(res,
                {
                    msg: "You do not have access to this resource.",
                    type: "forbidden",
                },
            403);
        }
        if (vuln.public) {
            return helpers.sendStyledJSONErr(res,
                {
                    msg: "Token management is not available for public vulnerabilities.",
                    type: "vulnnotprivate",
                },
            400);
        }

        let l = vuln.tokens.length;
        vuln.tokens = vuln.tokens.filter((v) => v.code != req.body.token);
        if (vuln.tokens.length < l) {
            await vuln.save();
            return res.json({status: "success"});
        } else {
            return helpers.sendStyledJSONErr(res,
                {
                    msg: "No matching entry found for the specified token.",
                    type: "tokennotfound",
                },
            400);
        }
    }
);

module.exports = router;
