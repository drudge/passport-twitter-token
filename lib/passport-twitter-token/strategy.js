/**
 * Module dependencies.
 */
var util = require('util')
  , OAuthStrategy = require('passport-oauth').OAuthStrategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `TwitterTokenStrategy` constructor.
 *
 * The Twitter authentication strategy authenticates requests by delegating to
 * Twitter using the OAuth protocol.
 *
 * Applications must supply a `verify` callback which accepts a `token`,
 * `tokenSecret` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `consumerKey`     identifies client to Twitter
 *   - `consumerSecret`  secret used to establish ownership of the consumer key
 *
 * Examples:
 *
 *     passport.use(new TwitterTokenStrategy({
 *         consumerKey: '123-456-789',
 *         consumerSecret: 'shhh-its-a-secret'
 *       },
 *       function(token, tokenSecret, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function TwitterTokenStrategy(options, verify) {
  options = options || {};
  options.requestTokenURL = options.requestTokenURL || 'https://api.twitter.com/oauth/request_token';
  options.accessTokenURL = options.accessTokenURL || 'https://api.twitter.com/oauth/access_token';
  options.userAuthorizationURL = options.userAuthorizationURL || 'https://api.twitter.com/oauth/authenticate';
  options.sessionKey = options.sessionKey || 'oauth:twitter';

  OAuthStrategy.call(this, options, verify);
  this.name = 'twitter-token';

  this._skipExtendedUserProfile = (options.skipExtendedUserProfile === undefined) ? false : options.skipExtendedUserProfile;
}

/**
 * Inherit from `OAuthTwitterTokenStrategy`.
 */
util.inherits(TwitterTokenStrategy, OAuthStrategy);


/**
 * Authenticate request by delegating to Twitter using OAuth.
 *
 * @param {Object} req
 * @api protected
 */
TwitterTokenStrategy.prototype.authenticate = function(req, options) {
  // When a user denies authorization on Twitter, they are presented with a link
  // to return to the application in the following format (where xxx is the
  // value of the request token):
  //
  //     http://www.example.com/auth/twitter/callback?denied=xxx
  //
  // Following the link back to the application is interpreted as an
  // authentication failure.
  if (req.query && req.query.denied) {
    return this.fail();
  }
  
  var self = this;
  var token = lookup(req.body, 'oauth_token') || lookup(req.query, 'oauth_token');
  var tokenSecret = lookup(req.body, 'oauth_token_secret') || lookup(req.query, 'oauth_token_secret');
  var userId = lookup(req.body, 'user_id') || lookup(req.query, 'user_id');
  var params = { user_id: userId };
  
  self._loadUserProfile(token, tokenSecret, params, function(err, profile) {
    if (err) { return self.error(err); };
    
    function verified(err, user, info) {
      if (err) { return self.error(err); }
      if (!user) { return self.fail(info); }
      self.success(user, info);
    }
    
    if (self._passReqToCallback) {
      var arity = self._verify.length;
      if (arity == 6) {
        self._verify(req, token, tokenSecret, params, profile, verified);
      } else { // arity == 5
        self._verify(req, token, tokenSecret, profile, verified);
      }
    } else {
      var arity = self._verify.length;
      if (arity == 5) {
        self._verify(token, tokenSecret, params, profile, verified);
      } else { // arity == 4
        self._verify(token, tokenSecret, profile, verified);
      }
    }
  });

  function lookup(obj, field) {
    if (!obj) { return null; }
    var chain = field.split(']').join('').split('[');
    for (var i = 0, len = chain.length; i < len; i++) {
      var prop = obj[chain[i]];
      if (typeof(prop) === 'undefined') { return null; }
      if (typeof(prop) !== 'object') { return prop; }
      obj = prop;
    }
    return null;
  }
}

/**
 * Retrieve user profile from Twitter.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `id`        (equivalent to `user_id`)
 *   - `username`  (equivalent to `screen_name`)
 *
 * Note that because Twitter supplies basic profile information in query
 * parameters when redirecting back to the application, loading of Twitter
 * profiles *does not* result in an additional HTTP request, when the
 * `skipExtendedUserProfile` is enabled.
 *
 * @param {String} token
 * @param {String} tokenSecret
 * @param {Object} params
 * @param {Function} done
 * @api protected
 */
TwitterTokenStrategy.prototype.userProfile = function(token, tokenSecret, params, done) {
  if (!this._skipExtendedUserProfile) {
    this._oauth.get('https://api.twitter.com/1.1/users/show.json?user_id=' + params.user_id, token, tokenSecret, function (err, body, res) {
      if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

      try {
        var json = JSON.parse(body);

        var profile = { provider: 'twitter' };
        profile.id = json.id;
        profile.username = json.screen_name;
        profile.displayName = json.name;
        profile.photos = [{ value: json.profile_image_url_https }];

        profile._raw = body;
        profile._json = json;

        done(null, profile);
      } catch(e) {
        done(e);
      }
    });
  } else {
    var profile = { provider: 'twitter' };
    profile.id = params.user_id;
    profile.username = params.screen_name;

    done(null, profile);
  }
}

/**
 * Return extra Twitter-specific parameters to be included in the user
 * authorization request.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
TwitterTokenStrategy.prototype.userAuthorizationParams = function(options) {
  var params = {};
  if (options.forceLogin) {
    params['force_login'] = options.forceLogin;
  }
  if (options.screenName) {
    params['screen_name'] = options.screenName;
  }
  return params;
}


/**
 * Expose `TwitterTokenStrategy`.
 */
module.exports = TwitterTokenStrategy;
