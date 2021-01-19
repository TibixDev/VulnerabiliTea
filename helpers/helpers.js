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

function sendError(res, errCode) {
    let errDescription;
    switch (errCode) {
        case 400:
            errDescription = "The requested path couldn't be found.";
            break;
        case 404:
            errDescription = "The requested resource couldn't be found.";
            break;
        case 403:
            errDescription = "You are not allowed to view this page";
            break;
    }
    return res.status(errCode).render("err", {
        err: {
            code: errCode,
            description: errDescription,
        },
    });
}

module.exports = { isLoggedIn, sendError };
