// Imports
const express = require("express"),
    router = express.Router(),
    { body, validationResult } = require("express-validator"),
    bcrypt = require("bcrypt");

// Global vars
const saltRounds = 10;

// Model Imports
const User = require("../db/models/user.js");

// Handle: Static Home, Register, Login, Logout, About
router.get("/", (req, res) => {
    res.render("index");
});

router.get("/about", (req, res) => {
    res.render("about");
});

// Debug Purposes (Remove on release)
router.get("/base", (req, res) => {
    res.render("base");
});

router.get("/login", (req, res) => {
    if (req.session.user) {
        return res.redirect("vuln");
    }
    res.render("login", {
        msgs: req.flash("msgs"),
    });
});

router.post("/login", async (req, res) => {
    if (req.session.user) {
        return res.redirect("vuln");
    }
    let user = await User.findOne({
        email: req.body.email,
    }, 'password _id');
    if (!user) {
        return res.render("login", {
            msgs: [
                {
                    noteType: "note-danger",
                    pretext: "Error",
                    value: "The credentials specified were invalid",
                },
            ],
        });
    }
    bcrypt.compare(req.body.password, user.password, (err, result) => {
        if (err) {
            return res.render("login", {
                msgs: [
                    {
                        noteType: "note-danger",
                        pretext: "Error",
                        value: "There was a server error",
                    },
                ],
            });
        }
        if (result == true) {
            req.session.user = user._id;
            return res.redirect("/vuln");
        }
        return res.render("login", {
            msgs: [
                {
                    noteType: "note-danger",
                    pretext: "Error",
                    value: "The credentials specified were invalid",
                },
            ],
        });
    });
});

router.get("/register", (req, res) => {
    if (req.session.user) {
        return res.redirect("vuln");
    }
    res.render("register");
});

router.post(
    "/register", (req, res, next) => {
        if (req.session.user) {
            return res.redirect('/vuln');
        }
        next();
    },
    [
        body("email")
            .exists()
            .withMessage("There was no email specified.")
            .isEmail()
            .withMessage("The email specified was invalid.")
            .isLength({ min: 5, max: 48 })
            .withMessage(
                "The email specified didn't match the desired length (5-48 Characters)"
            )
            .normalizeEmail()
            .custom((value, { req }) => {
                return new Promise((resolve, reject) => {
                    User.findOne({ email: req.body.email }, (err, user) => {
                        if (err) {
                            reject(new Error("Server Error."));
                        }
                        if (Boolean(user)) {
                            reject(new Error("E-mail already in use."));
                        }
                        resolve(true);
                    });
                });
            }),
        body("username")
            .exists()
            .withMessage("There was no username specified.")
            .isAlphanumeric()
            .withMessage("The username specified was not alphanumeric.")
            .isLength({ min: 3, max: 16 })
            .withMessage(
                "The username specified didn't match the desired length (3-16 Characters)"
            )
            .escape()
            .custom((value, { req }) => {
                return new Promise((resolve, reject) => {
                    User.findOne(
                        { username: req.body.username },
                        (err, user) => {
                            if (err) {
                                reject(new Error("Server Error."));
                            }
                            if (Boolean(user)) {
                                reject(new Error("Username already in use."));
                            }
                            resolve(true);
                        }
                    );
                });
            }),
        body("password")
            .exists()
            .withMessage("There was no password specified.")
            .isLength({ min: 5, max: 128 })
            .withMessage(
                "The password specified didn't match the desired length (5-128 Characters)"
            ),
        body("passwordVerify")
            .exists()
            .withMessage("No password was specified in the repetition field.")
            .custom((value, { req }) => value === req.body.password)
            .withMessage("The passwords specified didn't match."),
        body("tosBox")
            .exists()
            .withMessage(
                "You must accept the Terms and Conditions to register."
            ),
    ],
    async (req, res) => {
        if (req.session.user) {
            res.redirect('/vuln');
        }
        const validationErrors = validationResult(req);
        if (!validationErrors.isEmpty()) {
            let errList = [];
            for (err of validationErrors.array()) {
                errList.push({
                    noteType: "note-danger",
                    pretext: "Error",
                    value: err.msg,
                });
            }
            return res.render("register", { msgs: errList });
        }
        try {
            req.body.password = await bcrypt.hash(
                req.body.password,
                saltRounds
            );
        } catch (err) {
            if (err) {
                return res.render("register", {
                    msgs: {
                        noteType: "note-danger",
                        pretext: "Error",
                        value: "Server Error",
                    },
                });
            }
        }
        let user = new User({
            email: req.body.email,
            username: req.body.username,
            password: req.body.password,
        });
        await user.save();
        req.flash("msgs", {
            noteType: "note-success",
            pretext: "Success",
            value:
                "You've registred successfully. Now you can proceed to the login.",
        });
        res.redirect("/login");
    }
);

router.get("/logout", (req, res) => {
    if (req.session.user) {
        // Since we rely on the session when it comes to flash messages
        // We wait a second before invalidating the session
        req.session.user = "";
        req.flash("msgs", [
            {
                noteType: "note-info",
                pretext: "Info",
                value: "Logged out successfully",
            },
        ]);
        setTimeout(() => {
            req.session.destroy();
        }, 1000);
    } else {
        req.flash("msgs", [
            {
                noteType: "note-danger",
                pretext: "Error",
                value: "You need to be logged-in to log-out.",
            },
        ]);
    }
    res.redirect("/login");
});
module.exports = router;
