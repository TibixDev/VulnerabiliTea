// Imports
const express = require('express'),
    app = express(),
    path = require('path'),
    session = require('express-session'),
    MongoStore = require('connect-mongodb-session')(session),
    Config = require('./config/config.json'),
    flash = require('connect-flash'),
    cookieParser = require('cookie-parser');

/* Middlewares that enable use to:
        - Serve static pages
        - Use Pug to render
        - Receive better formatted POST requests
        - Have Sessions
        - Have Flashes (redirect messages)
        - Have Routes */

app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'pug');
app.use(express.urlencoded({ extended: true }));

// Configure Mongo & Express Session Store

const store = new MongoStore({
    uri: Config.session.connection,
    collection: Config.session.collection
});

app.use(session({
    store: store,
    resave: false,
    saveUninitialized: true,
    secret: Config.session.secret
}));

// Configure Flashes and Cookies

app.use(cookieParser());
app.use(flash());

// Routing requests to the correct routers

const routes = require('./routes/routes.js');

app.use('/', routes.index);
app.use('/vuln', routes.vuln);

app.all('*', (req, res) => {
    res.status(404).send("Error 404 -> Not Found");
});

// Host the app on the port specified so it is accessible with a browser

app.listen(Config.port, () => {
    console.log(`VulnerabiliTea started on port ${Config.port}`);
});