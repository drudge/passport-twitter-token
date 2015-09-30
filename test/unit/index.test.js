import chai, { assert } from 'chai';
import sinon from 'sinon';
import TwitterTokenStrategy from '../../src/index';
import fakeProfile from '../fixtures/profile';

const STRATEGY_CONFIG = {
  consumerKey: '123',
  consumerSecret: '123'
};

const BLANK_FUNCTION = () => {
};

describe('TwitterTokenStrategy:init', () => {
  it('Should properly export Strategy constructor', () => {
    assert.isFunction(TwitterTokenStrategy);
  });

  it('Should properly initialize', () => {
    let strategy = new TwitterTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);
    assert.equal(strategy.name, 'twitter-token');
  });

  it('Should properly throw exception when options is empty', () => {
    assert.throw(() => new TwitterTokenStrategy(), Error);
  });
});

describe('TwitterTokenStrategy:authenticate', () => {
  describe('Authenticate without passReqToCallback', () => {
    let strategy;

    before(() => {
      strategy = new TwitterTokenStrategy(STRATEGY_CONFIG, (token, tokenSecret, profile, next) => {
        assert.equal(token, 'token');
        assert.equal(tokenSecret, 'token_secret');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {info: 'foo'});
      });

      sinon.stub(strategy._oauth, 'get', (url, token, tokenSecret, next) => next(null, fakeProfile, null));
    });

    after(() => strategy._oauth.get.restore());

    it('Should properly parse token from body', done => {
      chai
        .passport
        .use(strategy)
        .success((user, info) => {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(req => {
          req.body = {
            oauth_token: 'token',
            oauth_token_secret: 'token_secret'
          }
        })
        .authenticate({});
    });

    it('Should properly parse token from query', done => {
      chai
        .passport
        .use(strategy)
        .success((user, info) => {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(req => {
          req.query = {
            oauth_token: 'token',
            oauth_token_secret: 'token_secret'
          }
        })
        .authenticate({});
    });

    it('Should properly call fail if token is not provided', done => {
      chai.passport.use(strategy).fail(error => {
        assert.typeOf(error, 'object');
        assert.typeOf(error.message, 'string');
        assert.equal(error.message, 'You should provide oauth_token and oauth_token_secret');
        done();
      }).authenticate({});
    });
  });

  describe('Authenticate with passReqToCallback', () => {
    let strategy;

    before(() => {
      strategy = new TwitterTokenStrategy(Object.assign(STRATEGY_CONFIG, {passReqToCallback: true}), (req, token, tokenSecret, profile, next) => {
        assert.typeOf(req, 'object');
        assert.equal(token, 'token');
        assert.equal(tokenSecret, 'token_secret');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {info: 'foo'});
      });

      sinon.stub(strategy._oauth, 'get', (url, token, tokenSecret, next) => next(null, fakeProfile, null));
    });

    after(() => strategy._oauth.get.restore());

    it('Should properly call _verify with req', done => {
      chai
        .passport
        .use(strategy)
        .success((user, info) => {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(req => {
          req.body = {
            oauth_token: 'token',
            oauth_token_secret: 'token_secret'
          }
        })
        .authenticate({});
    });
  });

  describe('Failed authentications', () => {
    it('Should properly return error on loadUserProfile', done => {
      let strategy = new TwitterTokenStrategy(STRATEGY_CONFIG, (token, tokenSecret, profile, next) => {
        assert.equal(token, 'token');
        assert.equal(tokenSecret, 'token_secret');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {info: 'foo'});
      });

      sinon.stub(strategy, '_loadUserProfile', (token, tokenSecret, params, next) => next(new Error('Some error occurred')));

      chai
        .passport
        .use(strategy)
        .error(error => {
          assert.instanceOf(error, Error);
          strategy._loadUserProfile.restore();
          done();
        })
        .req(req => {
          req.body = {
            oauth_token: 'token',
            oauth_token_secret: 'token_secret'
          }
        })
        .authenticate({});
    });

    it('Should properly return error on verified', done => {
      let strategy = new TwitterTokenStrategy(STRATEGY_CONFIG, (token, tokenSecret, profile, next) => {
        assert.equal(token, 'token');
        assert.equal(tokenSecret, 'token_secret');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(new Error('Some error occurred'));
      });

      sinon.stub(strategy._oauth, 'get', (url, token, tokenSecret, next) => next(null, fakeProfile, null));

      chai
        .passport
        .use(strategy)
        .error(error => {
          assert.instanceOf(error, Error);
          strategy._oauth.get.restore();
          done();
        })
        .req(req => {
          req.body = {
            oauth_token: 'token',
            oauth_token_secret: 'token_secret'
          }
        })
        .authenticate({});
    });
  });
});

describe('TwitterTokenStrategy:userProfile', () => {
  it('Should properly fetch profile', done => {
    let strategy = new TwitterTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);
    sinon.stub(strategy._oauth, 'get', (url, token, tokenSecret, next) => next(null, fakeProfile, null));

    strategy.userProfile('token', 'tokenSecret', {userId: 'user_id'}, (error, profile) => {
      if (error) return done(error);

      assert.equal(profile.provider, 'twitter');
      assert.equal(profile.id, '1234');
      assert.equal(profile.username, 'ghaiklor');
      assert.equal(profile.displayName, 'Eugene Obrezkov');
      assert.deepEqual(profile.photos, [{value: 'IMAGE_URL'}]);
      assert.equal(typeof profile._raw, 'string');
      assert.equal(typeof profile._json, 'object');

      strategy._oauth.get.restore();

      done();
    });
  });

  it('Should properly handle exception on fetching profile', done => {
    let strategy = new TwitterTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);

    sinon.stub(strategy._oauth, 'get', (url, token, tokenSecret, next) => next(null, 'not a JSON'));

    strategy.userProfile('token', 'tokenSecret', {userId: 'user_id'}, (error, profile) => {
      assert(error instanceof SyntaxError);
      assert.equal(typeof profile, 'undefined');
      strategy._oauth.get.restore();
      done();
    });
  });

  it('Should properly throw error on _oauth.get error', done => {
    let strategy = new TwitterTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);

    sinon.stub(strategy._oauth, 'get', (url, token, tokenSecret, next) => next('Some error occurred'));

    strategy.userProfile('token', 'tokenSecret', {userId: 'user_id'}, (error, profile) => {
      assert.instanceOf(error, Error);
      strategy._oauth.get.restore();
      done();
    });
  });
});
