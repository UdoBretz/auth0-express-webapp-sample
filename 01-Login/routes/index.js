const express = require('express');
const router = require('express').Router();

const jose = require('jose');

const { requiresAuth } = require('express-openid-connect');
const requiresValidLogoutToken = require('../middlewares/validateLogoutToken');

router.use(express.urlencoded({ extended: true }));

router.post(
  '/backchannel-logout',
  requiresValidLogoutToken,
  function (req, res, next) {
    // at this point the logout token is valid
    // you can access it from the request object: req.logoutToken
    // the payload looks like this:
    // {
    //   iss: 'https://dev-udo.local.dev.auth0.com/',
    //   sub: 'user',
    //   aud: 'X5tAK1WsWD8Lyfexx6Qpo9UkT2ATM0C0',
    //   iat: 1659611563,
    //   jti: 'fac52fdf-466e-4f32-8389-39b90681d310',
    //   events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
    //   trace_id: 'a8e88fcb-6f9a-4035-9ac8-1c378227b4e3',
    //   sid: 'test-session-id'
    // }

    console.log(req.logoutToken);

    deleteUserSessions(res.locals.sessionStore, req.logoutToken.sub);

    res.sendStatus(200);
  }
);

router.get('/', function (req, res, next) {
  res.render('index', {
    title: 'Auth0 Webapp sample Nodejs',
    isAuthenticated: req.oidc.isAuthenticated(),
  });
});

router.get('/profile', requiresAuth(), function (req, res, next) {
  res.render('profile', {
    userProfile: JSON.stringify(req.oidc.user, null, 2),
    title: 'Profile page',
  });
});

function deleteUserSessions(sessionStore, userId) {
  sessionStore.all((error, sessions) => {
    for (const [sessionId, session] of Object.entries(sessions)) {
      const claims = jose.decodeJwt(session.data.id_token);

      if (claims.sub === userId) {
        console.log('Deleting session id: ' + sessionId);
        sessionStore.destroy(sessionId, (error) => {
          if (error) {
            console.log(error);
          }
        });
      }
    }
  });
}

module.exports = router;
