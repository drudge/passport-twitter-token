# Passport-Twitter-Token

[Passport](http://passportjs.org/) strategy for authenticating with [Twitter](http://twitter.com/) tokens
using the OAuth 1.0a API.

This module lets you authenticate using Twitter in your Node.js applications.
By plugging into Passport, Twitter authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Installation

    $ npm install passport-twitter-token

## Usage

#### Configure Strategy

The Twitter authentication strategy authenticates users using a Twitter account
and OAuth tokens.  The strategy requires a `verify` callback, which receives the
access token and corresponding secret as arguments, as well as `profile` which
contains the authenticated user's Twitter profile.   The `verify` callback must
call `done` providing a user to complete authentication.

In order to identify your application to Twitter, specify the consumer key,
consumer secret, and callback URL within `options`.  The consumer key and secret
are obtained by [creating an application](https://dev.twitter.com/apps) at
Twitter's [developer](https://dev.twitter.com/) site.

    passport.use(new TwitterTokenStrategy({
        consumerKey: TWITTER_CONSUMER_KEY,
        consumerSecret: TWITTER_CONSUMER_SECRET
      },
      function(token, tokenSecret, profile, done) {
        User.findOrCreate({ twitterId: profile.id }, function (err, user) {
          return done(err, user);
        });
      }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'twitter-token'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.post('/auth/twitter/token',
      passport.authenticate('twitter-token'));

## Credits

  - [Nicholas Penree](http://github.com/drudge)
  - [Jared Hanson](http://github.com/jaredhanson)

## License

(The MIT License)

Copyright (c) 2012 Nicholas Penree

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.