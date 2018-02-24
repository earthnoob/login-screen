// load all the things we need
var LocalStrategy   = require('passport-local').Strategy;
var bcrypt = require('bcrypt-nodejs');
// load up the user model
var User = require('../app/user');

// expose this function to our app using module.exports
module.exports = function(passport) {

    // =========================================================================
    // passport session setup ==================================================
    // =========================================================================
    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        done(null, user);
    });

    // used to deserialize the user
    passport.deserializeUser(function(id, done) {
        User.findById(id, function(err, user) {
            done(err, user);
        });
    });

    

    passport.use('local-signup', new LocalStrategy({
        usernameField: 'username',
        passwordField: 'password',
        passReqToCallback: true,
        session: false
      },
      function(req, username, password, done) {
        User.findOne({ "username": username })
        .then((user, err)=>{
            if(user) {
                //console.log(user, err);
                return done(null, false, req.flash('signupMessage', 'Username already taken.'));
            }
            if(err) {
                return done(null, false, req.flash('signupMessage', 'An error occured.'));
            } else {
                //console.log("error", err, "user", data);
                let passwd = bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
                //console.log(passwd);
                User.create({
                    username: username,
                    password: passwd,
                    first_name: req.body.first_name,
                    last_name: req.body.last_name,
                    gender: req.body.gender,
                    age: req.body.age,
                })
                .then((data, err) => {
                    if(err) {
                        console.log(err);
                        return done(null, false, req.flash('signupMessage', err));
                    }
                    //console.log(data);
                    return done(null, data);
                })
            }
        })
    }
    ));

    passport.use('local-login', new LocalStrategy({
        usernameField: 'username',
        passwordField: 'password',
        passReqToCallback: true,
        session: false
      },
      function(req, username, password, done) {
          
        User.find({ username: username })
        .then((user, err) =>{
            console.log(err, user);
            //if(err) return done(null, false, req.flash('loginMessage', err));
            //if(user) return done(null, false, req.flash('loginMessage', 'User not found.'));

            //console.log("password", password, "hashed password", user.map(val => val.password)[0]);
            let db_passwd = user.map(val => val.password)[0];
            let token = bcrypt.compareSync(password, db_passwd);
            console.log(token);
            
            if(!token) return done(null, false, req.flash('loginMessage', 'Invalid password.'));
            return done(null, user);
        })
      }
    ));
}; 