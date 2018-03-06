// get all the tools we need
var express  = require('express');
var app      = express();
var fs = require('fs');
var https = require('https');
var port     = process.env.PORT || 3000;
var mongoose = require('mongoose');
var passport = require('passport');
var flash    = require('connect-flash');

var morgan       = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser   = require('body-parser');
var session      = require('express-session');

var configDB = require('./config/database.js');
var secretConfig = require('./config/session');

// configuration ===============================================================
mongoose.connect(configDB.url); // connect to our database

// set up our express application
app.use(morgan('dev')); // log every request to the console
app.use(cookieParser()); // read cookies (needed for auth)
app.use(bodyParser.json()); // get information from html forms
app.use(bodyParser.urlencoded({ extended: true })); 

app.set('view engine', 'ejs'); // set up ejs for templating

app.use(express.static(__dirname + '/public'));

//Setup configurations for HTTPS server
const HTTPSConfig = {  
    //cert: fs.readFileSync('./config/ssl/https.crt'),
   //key: fs.readFileSync('./config/sll/sslcert.key'),
    port: 3443
};

// required for passport
app.use(session({ 
    secret: secretConfig.secret,  // session secret
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } /*Use 'true' without setting up HTTPS will result in
                                redirect errors*/
}));

app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions
app.use(flash()); // use connect-flash for flash messages stored in session

require('./config/passport')(passport); // pass passport for configuration

// routes ======================================================================
require('./app/routes.js')(app, passport); // load our routes and pass in our app and fully configured passport

app.use('/api/user', require('./app/api/routes'));

// launch ======================================================================
app.listen(port);
console.log('The magic happens on port ' + port);