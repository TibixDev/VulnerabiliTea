 const { body, validationResult } = require("express-validator");

function isLoggedIn(req, res, next) {
    if (!req.session.user) {
        req.flash("msgs", [{
            noteType: "note-warning",
            pretext: "Warning",
            value: "You have to be logged in to access the requested page.",
        }]);
        return res.redirect("/login");
    }
    next();
}

function processValidationErrs(req, res, next) {
    let validationErrors = validationResult(req);
    if (!validationErrors.isEmpty()) {
        return sendStyledJSONErr(res, validationErrors.array(), 400);
    }
    next();
}

function isLoggedInPOST(req, res, next) {
    if (!req.session.user) {
        return sendStyledJSONErr(res, 
            {
                msg: 'You have to be logged in the access this POST endpoint.',
                type: 'notLoggedIn'
            }, 
        400);
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
        }
    });
}

function sendStyledJSONErr(res, errs, code = 200) {
    let errList = [];
    if (errs instanceof Array) {
        for (err of errs) {
            errList.push({
                noteType: "note-danger",
                pretext: "Error ",
                value: err.msg.text || err.msg,
                errType: err.msg.type || err.type
            });
        }
    } else {
        errList.push({
            noteType: "note-danger",
            pretext: "Error ",
            value: errs.msg.text || errs.msg,
            errType: errs.msg.type || errs.type
        })
    }
    return res.status(code).json({
        status: "failed",
        msgs: errList
    });
}

async function tokenValid(vuln, token) {
    let tokenMatches = vuln.tokens.filter(
        (t) => t.code === token
    );
    //console.log('TokenMatches Length: ' + tokenMatches.length);
    if (tokenMatches.length < 1) {
        return false;
    }
    if (tokenMatches[0].expiryDate < Date.now()) {
        //console.log('Token is expired: ' + token);

        // TODO: Make a suitable replacement for this garbage
        //vuln.tokens = vuln.tokens.filter(
        //    (t) => t.code != token
        //);
        //await vuln.save();
        return false;
    }
    return true
}

module.exports = {
    isLoggedIn,
    isLoggedInPOST,
    sendError,
    sendStyledJSONErr,
    tokenValid,
    processValidationErrs
};