// Imports
const express = require('express'),
    router = express.Router(),
    { body, validationResult } = require('express-validator');

// Model Imports
const User = require('../db/models/user.js');

// Handle: Static Home, Register, Login, Logout

router.get('/', (req, res) => {
    res.render('index');
});

router.get('/base', (req, res) => {
    res.render('base');
});

router.get('/login', (req, res) => {
    res.render('login');
});

router.post('/login', async (req, res) => {

});

router.get('/register', (req, res) => {
    res.render('register');
});

router.post('/register', [
    body('email').exists().withMessage('There was no email specified.')
                 .isEmail().withMessage('The email specified was invalid.')
                 .isLength({ min: 5, max: 48 }).withMessage('The email specified didn\'t match the desired length (5-48 Characters)')
                 .normalizeEmail()
                 .custom((value, {req}) => {
                    return new Promise((resolve, reject) => {
                      User.findOne({email:req.body.email}, (err, user) => {
                        if(err) {
                          reject(new Error('Server Error.'))
                        }
                        if(Boolean(user)) {
                          reject(new Error('E-mail already in use.'))
                        }
                        resolve(true)
                      });
                    });
                  }),
    body('username').exists().withMessage('There was no username specified.')
                    .isAlphanumeric().withMessage('The username specified was not-alphanumeric.')
                    .isLength({ min: 3, max: 16 }).withMessage('The username specified didn\'t match the desired length (3-16 Characters)')
                    .escape()
                    .custom((value, {req}) => {
                        return new Promise((resolve, reject) => {
                          User.findOne({username:req.body.username}, (err, user) => {
                            if(err) {
                              reject(new Error('Server Error.'))
                            }
                            if(Boolean(user)) {
                              reject(new Error('Username already in use.'))
                            }
                            resolve(true)
                          });
                        });
                      }),
    body('password').exists().withMessage('There was no password specified.')
                    .isLength({ min: 5, max: 128 }).withMessage('The password specified didn\'t match the desired length (5-128 Characters)'),
    body('passwordVerify').exists().withMessage('No password was specified in the repetition field.')
                          .custom((value, { req }) => value === req.body.password).withMessage('The passwords specified didn\'t match.')

], async (req, res) => {
    const validationErrors = validationResult(req);
    if (!validationErrors.isEmpty()) {
        let errList = [];
        for (err of validationErrors.array()) {
            errList.push(err.msg);
        }
        return res.render('register', { infos: errList });
    }
    let user = new User({
        email: req.body.email,
        username: req.body.username,
        password: req.body.password
    });
    await user.save();
    res.status(200).send('User has been created.');
})

module.exports = router;