const fs = require('fs'),
    path = require('path');

let routes = fs.readdirSync(__dirname).filter(x => x.endsWith('.js') && x != 'routes.js');
for (let route of routes) {
    const router = require(path.join(__dirname, route));
    module.exports[route.split('.')[0]] = router;
}