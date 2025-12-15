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

  if (options.state === undefined) {
    options.state = true;
  }

  if (options.pkce === undefined) {
    options.pkce = true;
  }

  var scope = options.scope;
  if (scope == null) {
    scope = "vkid.personal_info";
  } else if (Array.isArray(scope)) {
    scope = scope.filter(Boolean).join(" ").trim();
  } else if (typeof scope === "string") {
    scope = scope.trim();
  } else {
    throw new TypeError('VK ID Strategy: "scope" must be a string or an array');
  }
  options.scope = scope || "vkid.personal_info";

  this._provider = options.provider || "vkid";
  this._langId =
    options.lang_id !== undefined ? options.lang_id : options.langId;
  this._scheme = options.scheme;
  this._userProfileURL =
    options.userProfileURL ||
    options.profileURL ||
    "https://id.vk.ru/oauth2/user_info";

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

  var langId = options.lang_id !== undefined ? options.lang_id : options.langId;
  if (langId === undefined) {
    langId = this._langId;
  }
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

  var query = req.query || {};
  var body = req.body || {};

  if (query.code || body.code) {
    var deviceId =
      query.device_id || query.deviceId || body.device_id || body.deviceId;
    var state = query.state || body.state;

    if (deviceId) {
      options._vkid_device_id = deviceId;
    }
    if (state) {
      options._vkid_state = state;
    }
  }

  return OAuth2Strategy.prototype.authenticate.call(this, req, options);
};

Strategy.prototype.tokenParams = function (options) {
  options = options || {};

  var params = OAuth2Strategy.prototype.tokenParams.call(this, options) || {};

  if (options._vkid_device_id) {
    params.device_id = options._vkid_device_id;
  }
  if (options._vkid_state) {
    params.state = options._vkid_state;
  }

  return params;
};

Strategy.prototype.userProfile = function (accessToken, done) {
  var self = this;

  this._oauth2.get(
    this._userProfileURL,
    accessToken,
    function (err, body, res) {
      if (err) {
        return done(
          new InternalOAuthError("Failed to fetch user profile", err)
        );
      }

      if (res && res.statusCode !== 200) {
        return done(
          new InternalOAuthError("Failed to fetch user profile", {
            statusCode: res.statusCode,
            body: body,
          })
        );
      }

      var json;
      try {
        json = typeof body === "string" ? JSON.parse(body) : body;
      } catch (e) {
        return done(new InternalOAuthError("Failed to parse user profile", e));
      }

      var profile;
      try {
        profile = self.parseUserProfile(json);
      } catch (e) {
        return done(new InternalOAuthError("Failed to parse user profile", e));
      }

      if (!profile || !profile.id) {
        return done(
          new InternalOAuthError(
            "Failed to parse user profile",
            new Error("Missing user id")
          )
        );
      }

      profile._raw = typeof body === "string" ? body : JSON.stringify(body);
      profile._json = json;

      return done(null, profile);
    }
  );
};

Strategy.prototype.parseUserProfile = function (response) {
  var user = response && response.user;
  if (!user) {
    return null;
  }

  var userId = user.user_id != null ? user.user_id : user.id;
  if (userId == null || userId === "") {
    return null;
  }

  var firstName = user.first_name || user.firstName || "";
  var lastName = user.last_name || user.lastName || "";
  var displayName = (firstName + " " + lastName).trim() || undefined;

  return {
    provider: this._provider,
    id: String(userId),
    user_id: String(userId),
    displayName: displayName,
    name: {
      givenName: firstName || undefined,
      familyName: lastName || undefined,
    },
    first_name: firstName || undefined,
    last_name: lastName || undefined,
    email: user.email,
    email_verified: user.email_verified,
    phone: user.phone,
    phone_verified: user.phone_verified,
    avatar: user.avatar,
  };
};

module.exports = Strategy;
module.exports.Strategy = Strategy;
