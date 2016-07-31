var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var express = require('express');
var router;
var User = require('user-basic-mongo-storage');

var config = require('config');
var passportConfig = config.get('ziplink-passport-authentication.providers.google');

var strategy = new GoogleStrategy({
    clientID: passportConfig.web.client_id,
    clientSecret: passportConfig.web.client_secret,
    callbackURL: passportConfig.web.redirect_uris[0],
  },
  function(accessToken, refreshToken, profile, done) {
    User.findByAuthentication({
      'provider': profile.provider,
      'id': profile.id
    })
    .then(function(user){
      // Return the user found or a promise to create a new user
      return user || 
        User.create({
          displayName: profile.displayName,
          authentication: {
            provider: profile.provider,
            id: profile.id,
          },
        });
    })
    .then(function(user){
      done(undefined, user);
      return user;
    })
    .catch(done);
  });

function setupRouter(passport) {
  if (router) {
    return router;
  } else {
    router = express.Router();
    router.get('/google',
      passport.authenticate('google', {
        session: true,
        scope: ['https://www.googleapis.com/auth/plus.login', 'https://www.googleapis.com/auth/userinfo.profile']
      }));
  
    router.get('/google/callback',
      passport.authenticate('google', {
        failureRedirect: '/~loginError'
      }),
      function(req, res) {
        res.redirect('/');
      });
      
    return router;
  }
}

module.exports = exports = {
  Router: setupRouter,
  Strategy: strategy,
};