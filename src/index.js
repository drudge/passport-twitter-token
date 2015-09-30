import { OAuthStrategy, InternalOAuthError } from 'passport-oauth';

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
export default class TwitterTokenStrategy extends OAuthStrategy {
  constructor(_options, _verify) {
    let verify = _verify;
    let options = Object.assign({
      requestTokenURL: 'https://api.twitter.com/oauth/request_token',
      accessTokenURL: 'https://api.twitter.com/oauth/access_token',
      userAuthorizationURL: 'https://api.twitter.com/oauth/authenticate',
      sessionKey: 'oauth:twitter'
    }, _options);

    super(options, verify);

    this.name = 'twitter-token';
  }

  /**
   * Authenticate request by delegating to Twitter using OAuth.
   *
   * @param {Object} req
   * @api protected
   */
  authenticate(req, options) {
    // Following the link back to the application is interpreted as an authentication failure
    if (req.query && req.query.denied) return this.fail();

    let token = (req.body && req.body['oauth_token']) || (req.query && req.query['oauth_token']);
    let tokenSecret = (req.body && req.body['oauth_token_secret']) || (req.query && req.query['oauth_token_secret']);
    let userId = (req.body && req.body['user_id']) || (req.query && req.query['user_id']);
    let params = {user_id: userId};

    if (!token) return this.fail({message: `You should provide oauth_token and oauth_token_secret`});

    this._loadUserProfile(token, tokenSecret, params, (error, profile) => {
      if (error) return this.error(error);

      const verified = (error, user, info) => {
        if (error) return this.error(error);
        if (!user) return this.fail(info);

        return this.success(user, info);
      };

      if (this._passReqToCallback) {
        this._verify(req, token, tokenSecret, profile, verified);
      } else {
        this._verify(token, tokenSecret, profile, verified);
      }
    });
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
  userProfile(token, tokenSecret, params, done) {
    this._oauth.get(`https://api.twitter.com/1.1/users/show.json?user_id=${params.user_id}`, token, tokenSecret, (error, body, res) => {
      if (error) return done(new InternalOAuthError('Failed to fetch user profile', error));

      try {
        let json = JSON.parse(body);
        let profile = {
          provider: 'twitter',
          id: json.id,
          username: json.screen_name,
          displayName: json.name,
          photos: [{value: json.profile_image_url_https}],
          _raw: body,
          _json: json
        };

        done(null, profile);
      } catch (e) {
        done(e);
      }
    });
  }
}
