// Imports
const express = require('express'),
    app = express(),
    path = require('path'),
    session = require('express-session'),
    MongoConnection = require('./db/index.js'),
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
    res.locals.username = req.session.username;
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
app.use('/settings', routes.settings);

// LetsEncrypt
if (process.env.ACME_URI && process.env.ACME_SERVE) {
    app.get(`/.well-known/acme-challenge/${process.env.ACME_URI}`, (req, res) => {
        res.send(process.env.ACME_SERVE);
    });
}

app.all('/*', (req, res, next) => {
   return helpers.sendError(res, 400);
}) 

// Host the app on the port specified so it is accessible with a browser
const server = app.listen(process.env.PORT || Config.port, () => {
    console.log(`VulnerabiliTea started on port ${process.env.PORT || Config.port}`);
});

// Graceful Shutdown
process.on('SIGINT' || 'SIGTERM', async () => {
    console.info('Shutdown signal received.\nVulnerabiliTea is shutting down...');
    console.log('Shutting down HTTP server.');
    await server.close();
    console.log('HTTP server closed.');
    console.log('Disconnecting from MongoDB server...');
    await MongoConnection.close(false);
    console.log('MongoDB connection closed.');
    console.log('Everything finished, killing process with exit code 0.');
    process.exit(0);
});