/*
* This route exists because of the future possibility
* of implementing cloud saves for settings.
* For now it just serves the purpose of rendering the
* settings template.
*/

// Imports
const express = require('express'),
    router = express.Router();

// Render Settings Pages
router.get("/", (req, res) => { res.render("settings") });

module.exports = router;