function isLoggedIn(req, res, next) {
    if (!req.session.user) {
        req.flash("msgs", [
            {
                noteType: "note-warning",
                pretext: "Warning",
                value: "You have to be logged in to access the requested page.",
            },
        ]);
        return res.redirect("/login");
    }
    next();
}

module.exports = { isLoggedIn };
