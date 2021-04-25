const mongoose = require("mongoose"),
    Config = require("../config/config.json");

// Connect to database using Mongoose and the config file
mongoose.connect(process.env.MONGODB_URI || Config.database.connection, { useNewUrlParser: true, useUnifiedTopology: true }).
  catch(err => console.log(`There was an error connecting to MongoDB: ${err}`));

/* Con can act like an event handler, 
   thus we define events which will be logged */

const con = mongoose.connection;

con.on("open", () => {
    console.log(
        `Connected to MongoDB! (${
            process.env.MONGODB_URI || Config.database.connection
        })`
    );
});

con.on("disconnected", () => {
    console.log("The connection to MongoDB has been lost.");
});

con.on("error", (err) => {
    console.log("A database error occured.");
    console.log(err);
});

// Export Connection
module.exports = con;
