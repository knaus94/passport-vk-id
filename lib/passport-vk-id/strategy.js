"use strict";

var util = require("util");
var passportOauth = require("passport-oauth");

var OAuth2Strategy = passportOauth.OAuth2Strategy;
var InternalOAuthError = passportOauth.InternalOAuthError;

function Strategy(options, verify) {
  options = options || {};

  options.clientID = options.clientID || options.clientId || options.client_id;
  options.clientSecret = options.clientSecret || options.client_secret;

  options.authorizationURL =
    options.authorizationURL || "https://id.vk.ru/authorize";
  options.tokenURL = options.tokenURL || "https://id.vk.ru/oauth2/auth";

  if (Array.isArray(options.scope)) {
    options.scope = options.scope.filter(Boolean).join(" ");
  }
  options.scope = options.scope || "vkid.personal_info";

  if (typeof options.state === "undefined") {
    options.state = true;
  }
  if (typeof options.pkce === "undefined") {
    options.pkce = true;
  }

  this._provider = options.provider || "vkid";
  this._langId = options.lang_id;
  this._scheme = options.scheme;
  this._userProfileURL =
    options.userProfileURL ||
    options.profileURL ||
    "https://id.vk.ru/oauth2/user_info";
  this._clientID = options.clientID;

  if (typeof verify !== "function") {
    if (options.passReqToCallback) {
      verify = function (req, accessToken, refreshToken, profile, done) {
        var self = this;

        Promise.resolve()
          .then(function () {
            return self.validate(req, accessToken, refreshToken, profile);
          })
          .then(function (user) {
            done(null, user);
          }, done);
      };
    } else {
      verify = function (accessToken, refreshToken, profile, done) {
        var self = this;

        Promise.resolve()
          .then(function () {
            return self.validate(accessToken, refreshToken, profile);
          })
          .then(function (user) {
            done(null, user);
          }, done);
      };
    }
  }

  OAuth2Strategy.call(this, options, verify);

  this.name = options.name || "vkid";
}

util.inherits(Strategy, OAuth2Strategy);

Strategy.prototype.authorizationParams = function (options) {
  options = options || {};
  var params = {};

  var provider = options.provider || this._provider;
  if (provider) {
    params.provider = String(provider);
  }

  var langId =
    typeof options.lang_id !== "undefined" ? options.lang_id : this._langId;
  if (langId !== undefined && langId !== null && langId !== "") {
    params.lang_id = String(langId);
  }

  var scheme = options.scheme || this._scheme;
  if (scheme) {
    params.scheme = String(scheme);
  }

  if (options.prompt) {
    params.prompt = options.prompt;
  }
  if (options.login_hint) {
    params.login_hint = options.login_hint;
  }

  return params;
};

Strategy.prototype.authenticate = function (req, options) {
  options = Object.assign({}, options || {});

  var query = (req && req.query) || {};
  var body = (req && req.body) || {};

  if (query.code || body.code) {
    var deviceId =
      query.device_id || query.deviceId || body.device_id || body.deviceId;
    var state = query.state || body.state;

    if (deviceId) {
      options._vkid_device_id = String(deviceId);
    }
    if (state) {
      options._vkid_token_state = String(state);
    }
  }

  return OAuth2Strategy.prototype.authenticate.call(this, req, options);
};

Strategy.prototype.tokenParams = function (options) {
  var params = {};

  if (typeof OAuth2Strategy.prototype.tokenParams === "function") {
    params = OAuth2Strategy.prototype.tokenParams.call(this, options) || {};
  }

  if (options && options._vkid_device_id) {
    params.device_id = options._vkid_device_id;
  }
  if (options && options._vkid_token_state) {
    params.state = options._vkid_token_state;
  }

  return params;
};

Strategy.prototype.userProfile = function (accessToken, done) {
  var url = this._userProfileURL;

  var postBody =
    "access_token=" +
    encodeURIComponent(accessToken) +
    "&client_id=" +
    encodeURIComponent(this._clientID);

  var headers = {
    "Content-Type": "application/x-www-form-urlencoded",
  };

  this._oauth2._request(
    "POST",
    url,
    headers,
    postBody,
    null,
    function (err, body) {
      if (err) {
        return done(
          new InternalOAuthError("Failed to fetch user profile", err)
        );
      }

      try {
        var data = typeof body === "string" ? JSON.parse(body) : body;
        var user = data.user;

        var profile = { provider: this._provider };
        profile.id = String(user.user_id);
        profile.displayName = user.first_name;
        profile.name = {
          givenName: user.first_name,
          familyName: user.last_name,
        };
        profile.photos = [{ value: user.avatar }];
        if (user.phone) {
          profile.phone = user.phone;
        }
        if (user.email) {
          profile.email = user.email;
        }
        profile.gender = user.sex;
        profile._json = user;

        return done(null, profile);
      } catch (e) {
        return done(new InternalOAuthError("Failed to parse user profile", e));
      }
    }.bind(this)
  );
};

module.exports = Strategy;
module.exports.Strategy = Strategy;
