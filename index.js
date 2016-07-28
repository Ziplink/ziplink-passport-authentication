module.exports = exports = function ziplinkPassportAuthentication(CONFIG){
  
  var express = require('express');
  var router = express.Router();
  
  var passport = require('passport');
  var session = require('express-session');
  const MongoStore = require('connect-mongo')(session);
  
  var User = require('user-basic-mongo-storage');
  
  var googleAuth = require('./providers/google.js');
  
  passport.serializeUser(function(user, done) {
      done(null, 
      {
        _id: user._id,
        displayName: user.displayName
      });
  });
  
  passport.deserializeUser(function(user, done) {
      User.findOne({'_id':user._id}, function(err, user) {
          done(err, user);
      });
  });
  
  if(CONFIG['ziplink-passport-authentication'].session.secret === ''){
    console.error('Session secret not set in ziplink-config, defaulting to "DEFAULT"');
  }
  
  router.use(session({
    secret: CONFIG['ziplink-passport-authentication'].session.secret || 'DEFAULT',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
    store: new MongoStore({ url: CONFIG.mongo.URI })
  }));
  
  router.use(passport.initialize());
  router.use(passport.session());
  
  passport.use(googleAuth.Strategy(CONFIG));
  router.use(googleAuth.Router(passport, CONFIG));
    
  //Make session data available to views
  router.use(function(req, res, next){
    if(typeof req.session.passport !== 'undefined')
      res.locals.user = req.session.passport.user;
    next();
  });
    
  return router;
  
};