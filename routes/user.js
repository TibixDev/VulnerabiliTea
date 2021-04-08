// Imports
const express = require("express"),
    router = express.Router(),
    helpers = require("../helpers/helpers.js"),
    User = require("../db/models/user.js"),
    Vulnerability = require("../db/models/vulnerability.js"),
    { body, validationResult } = require("express-validator"),
    fileUpload = require("express-fileupload"),
    Config = require("../config/config.json");

// Enable Multipart-Form-Data and Uploads
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

// Display logged-in user profile
router.get("/profile", helpers.isLoggedIn, async (req, res) => {
    let user = await User.findById(req.session.user, "-email -password -bio");
    let vulns = await Vulnerability.find(
        {
            author: req.session.user,
        },
        "-description -attachments"
    );
    res.render("user/profile.pug", { user, vulns, ownProfile: true });
});

// Get profile bio
router.post(
    "/profile/bio",
    [
        body("uid")
            .exists()
            .withMessage({
                text: "There was no UID specified.",
                type: "noUID",
            })
            .isLength(24)
            .withMessage({
                text: "The UID specified wasn't 24 characters long.",
                type: "uidCharLimitMismatch",
            })
    ], helpers.processValidationErrs,
    async (req, res) => {
        let errors = [];
        let user = await User.findById(req.body.uid, "bio").lean();
        if (!user) {
            helpers.sendStyledJSONErr([{
                msg: "No user corresponding to the specified UID was found.",
                type: "notFound",
            }])
        }
        res.send({status: 'success', bio: user.bio})
    }
);

// Render profile editing template
router.get("/profile/edit", helpers.isLoggedIn, async (req, res) => {
    let user = await User.findById(req.session.user, "bio, _id").lean();
    res.render("user/profile_edit.pug", { user });
});

// Process profile edits
router.post(
    "/profile/edit",
    helpers.isLoggedInPOST,
    [
        body("bio")
            .exists()
            .withMessage({
                text: "There was no bio specified.",
                type: "noBio",
            })
            .isLength({ min: 15, max: 4096 })
            .withMessage({
                text:
                    "The bio specified didn't match the desired length. (15 - 4096 characters)",
                type: "bioCharLimitMismatch",
            }),
    ],
    async (req, res) => {
        let errors = [];
        const validationErrors = validationResult(req);
        if (!validationErrors.isEmpty()) {
            errors = validationErrors.array();
        }
        if (errors.length > 0) {
            return helpers.sendStyledJSONErr(res, errors, 400);
        }
        let user = await User.findById(req.session.user);
        user.bio = req.body.bio;
        await user.save();
        res.json({ status: "success" });
    }
);

// Display profile by ID
router.get("/profile/:id", async (req, res) => {
    if (req.params.id.length != 24) {
        return helpers.sendError(res, 400);
    }
    let user = await User.findById(req.params.id, "-email -password -bio").lean();
    if (!user) {
        return helpers.sendError(res, 400);
    }
    let vulns = await Vulnerability.find(
        {
            public: true,
            author: req.params.id,
        },
        "-description -attachments"
    );
    res.render("user/profile.pug", { user, vulns });
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
