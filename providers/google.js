var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var router = require('express').Router();
var User = require('user-basic-mongo-storage');

function createStrategy(CONFIG) {
  return new GoogleStrategy({
      clientID: CONFIG['ziplink-passport-authentication'].providers.google.web.client_id,
      clientSecret: CONFIG['ziplink-passport-authentication'].providers.google.web.client_secret,
      callbackURL: CONFIG['ziplink-passport-authentication'].providers.google.web.redirect_uris[0]
    },
    function(accessToken, refreshToken, profile, done) {
      User.findByAuthentication({
        'provider': profile.provider,
        'id': profile.id
      })
      .then(function(user){
        if(user){
          return done(undefined, user);
        } else {
          return User.create({
            displayName: profile.displayName,
            authentication: {
              provider: profile.provider,
              id: profile.id,
            },
          })
          .then(function(user){
            return done(undefined, user);
          })
          .catch(done);
        }
      });
    });
}

function createRouter(passport, CONFIG) {
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

module.exports = exports = {
  Router: createRouter,
  Strategy: createStrategy
};