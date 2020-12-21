// Imports
const express = require('express'),
    router = express.Router();

// Model Imports
const User = require('../db/models/user.js');

// Handle: Static Home, Register, Login, Logout

router.get('/', (req, res) => {
    res.render('index');
});

router.get('/login', (req, res) => {
    res.render('login');
});

router.post('/login', async (req, res) => {

});

router.get('/register', (req, res) => {
    res.render('register');
});

router.post('/register', async (req, res) => {
    const mailRegexp = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    if (!mailRegexp.test(req.body.email))
        return res.status(400).send('This email is invalid!');
    if (await User.findOne({ email: req.body.email }))
        return res.status(400).send('User with this email already exists!');
    if (await User.findOne({ nickname: req.body.nickname }))
        return res.status(400).send('User with this name already exists!');
    let user = new User({
        email: req.body.email,
        nickname: req.body.nickname,
        password: req.body.password
    });
    await user.save();
    res.status(200).send('User has been created.');
})

module.exports = router;