module.exports = exports = function ziplinkPassportAuthentication(CONFIG){
  
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
  
  if(CONFIG['ziplink-passport-authentication'].providers.google.configured){
    passport.use(new GoogleStrategy({  
            clientID: CONFIG['ziplink-passport-authentication'].providers.google.web.client_id,
            clientSecret: CONFIG['ziplink-passport-authentication'].providers.google.web.client_secret,
            callbackURL: CONFIG['ziplink-passport-authentication'].providers.google.web.redirect_uris[0]
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
    
    router.get(CONFIG.routing.authPath + '/google',
      passport.authenticate('google', { session: true, scope: ['https://www.googleapis.com/auth/plus.login', 'https://www.googleapis.com/auth/userinfo.profile'] }));
      
    router.get(CONFIG.routing.authPath + '/google/callback', 
      passport.authenticate('google', { failureRedirect: '/~loginError' }),
      function(req, res) {
        res.redirect('/');
      });
  }
    
  //Make session data available to views
  router.use(function(req, res, next){
    if(typeof req.session.passport !== 'undefined')
      res.locals.user = req.session.passport.user;
    next();
  });
    
  return router;
  
};