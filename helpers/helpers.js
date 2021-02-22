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
            errDescription = "The requested path could not be found.";
            break;
        case 404:
            errDescription = "The requested resource could not be found.";
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

function sendStyledJSONErr(res, errs) {
    let errList = [];
    for (err of errs) {
        console.log(err.msg);
        errList.push({
                noteType: "note-danger",
                pretext: "Error ",
                value: err.msg,
        });
    }
    //console.log(errs);
    return res.json({ status: "failed", msgs: errList });
}

module.exports = { isLoggedIn, sendError, sendStyledJSONErr };
