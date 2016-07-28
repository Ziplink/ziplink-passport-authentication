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
        'ID': profile.id
      }, function(err, user) {
        if (!user)
          User.create({
            displayName: profile.displayName,
            authentication: {
              provider: profile.provider,
              ID: profile.id
            }
          }, function(err, user) {
            return done(err, user);
          });
        else return done(err, user);
      });

    }
  );
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