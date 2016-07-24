
module.exports = exports = function(authPath, config){
  
  if(!config)
    throw new Error('Configuration not set');
  
  var express = require('express');
  var router = express.Router();
  
  var passport = require('passport');
  var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
  var session = require('express-session');
  const MongoStore = require('connect-mongo')(session);
  
  var User = require('user-basic-mongo-storage');
  
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
  
  passport.use(new GoogleStrategy({  
          clientID: config.GOOGLE_CLIENT_ID,
          clientSecret: config.GOOGLE_CLIENT_SECRET,
          callbackURL: config.GOOGLE_CALLBACK_URL
      },
      function(accessToken, refreshToken, profile, done) {
        User.findByAuthentication(
          {
            'provider': profile.provider,
            'ID': profile.id
          }, function(err, user){
            if(!user)
              User.create({
                displayName: profile.displayName,
                authentication: {
                  provider: profile.provider,
                  ID: profile.id
                }
              }, function (err, user) {
                return done(err, user);
              });
            else return done(err, user);
          });
           
      }
  ));
  
  router.use(session({
    secret: 'supersecretstring',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
    store: new MongoStore({ url: 'mongodb://localhost/ziplink' })
  }));
  
  router.use(passport.initialize());
  router.use(passport.session());



  router.get(authPath + '/google',
    passport.authenticate('google', { session: true, scope: ['https://www.googleapis.com/auth/plus.login', 'https://www.googleapis.com/auth/userinfo.profile'] }));
    
  router.get(authPath + '/google/callback', 
    passport.authenticate('google', { failureRedirect: '/~loginError' }),
    function(req, res) {
      res.redirect('/');
    });
    
  //Make session data available to views
  router.use(function(req, res, next){
    if(typeof req.session.passport !== 'undefined')
      res.locals.user = req.session.passport.user;
    next();
  });
    
  return router;
};