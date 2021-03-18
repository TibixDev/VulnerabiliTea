// Imports
const express = require('express'),
    app = express(),
    path = require('path'),
    session = require('express-session'),
    MongoStore = require('connect-mongodb-session')(session),
    Config = require('./config/config.json'),
    flash = require('connect-flash'),
    cookieParser = require('cookie-parser'),
    bodyParser = require('body-parser'),
    helpers = require('./helpers/helpers.js'),
    User = require('./db/models/user.js');

/* Middlewares that enable us to:
        - Serve static pages
        - Use Pug to render
        - Receive better formatted POST requests
        - Have Sessions
        - Have Flashes (redirect messages)
        - Have Routes
        - Parse JSON body
        - Serve Errors */

app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'pug');
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

// Configure Mongo & Express Session Store
const store = new MongoStore({
    uri: process.env.MONGODB_URI || Config.session.connection,
    collection: Config.session.collection
});

app.use(session({
    store: store,
    resave: false,
    saveUninitialized: true,
    secret: Config.session.secret
}));

// Pass username to Pug templates when possible
app.use(async (req, res, next) => {
    if (req.session.user) {
        let user = await User.findById(req.session.user).lean();
        res.locals.username = user.username;
    }
    res.locals.versionCode = Config.versionCode;
    res.locals.version = Config.version;
    next();
})

// Configure Flashes and Cookies
app.use(cookieParser());
app.use(flash());

// Routing requests to the correct routers
const routes = require('./routes/routes.js');

app.use('/', routes.index);
app.use('/vuln', routes.vuln);
app.use('/activity', routes.activity);
app.use('/user', routes.user);
app.use('/files', routes.files);
app.all('/*', (req, res, next) => {
   return helpers.sendError(res, 400);
}) 

// Host the app on the port specified so it is accessible with a browser
app.listen(process.env.PORT || Config.port, () => {
    console.log(`VulnerabiliTea started on port ${process.env.PORT || Config.port}`);
});