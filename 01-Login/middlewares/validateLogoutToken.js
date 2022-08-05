const jose = require('jose');

async function requiresValidLogoutToken(req, res, next) {
  const JWKS = jose.createRemoteJWKSet(
    new URL(process.env.ISSUER_BASE_URL + '/.well-known/jwks.json')
  );

  const logoutToken = req.body.logout_token;

  if (!logoutToken) {
    res.status(400).send('Need logout token');
  }

  // Validate the logout token as defined here:
  // https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation
  try {
    const { payload, protectedHeader } = await jose.jwtVerify(
      logoutToken,
      JWKS,
      {
        issuer: process.env.ISSUER_BASE_URL + '/',
        audience: process.env.CLIENT_ID,
        typ: 'JWT',
        maxTokenAge: '2 minutes',
      }
    );

    // Verify that the Logout token contains a sub claim, a sid claim, or both
    if (!payload.sub && !payload.sid) {
      res
        .status(400)
        .send(
          'Error: Logout token must contain either sub claim or id claim, or both'
        );
    }

    // Verify that the logout token contains an events claim
    // whose value is JSON object containing the member name http://schemas.openid.net/event/backchannel-logout.
    if (!payload.events['http://schemas.openid.net/event/backchannel-logout']) {
      res
        .status(400)
        .send(
          'Error: Logout token must contain events claim with correct schema'
        );
    }

    // Verify that the Logout token does not contain a nonce claim.
    if (payload.nonce) {
      res
        .status(400)
        .send('Error: Logout token must not contain a nonce claim');
    }

    // TODO: We might want to take a closer look at this step:
    // Validate the iss, aud, and iat Claims in the same way they are validated in ID Tokens.

    // attach valid logout token to request object
    req.logoutToken = payload;

    next();
  } catch (error) {
    res.status(400).send('Error: ' + error.message);
  }
}

module.exports = requiresValidLogoutToken;
