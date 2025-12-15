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

  if (typeof options.state === "undefined") {
    options.state = true;
  }

  if (typeof options.pkce === "undefined") {
    options.pkce = true;
  }

  if (typeof options.scope === "undefined" || options.scope === null) {
    options.scope = "vkid.personal_info";
  } else if (Array.isArray(options.scope)) {
    options.scope =
      options.scope.filter(Boolean).join(" ").trim() || "vkid.personal_info";
  } else if (typeof options.scope === "string") {
    options.scope = options.scope.trim() || "vkid.personal_info";
  } else {
    throw new TypeError('VK ID Strategy: "scope" must be a string or an array');
  }

  this._provider = options.provider || "vkid";
  this._langId =
    typeof options.lang_id !== "undefined" ? options.lang_id : options.langId;
  this._scheme = options.scheme;
  this._userProfileURL =
    options.userProfileURL ||
    options.profileURL ||
    "https://id.vk.ru/oauth2/user_info";

  OAuth2Strategy.call(this, options, verify);

  this.name = options.name || "vk-id";
}

util.inherits(Strategy, OAuth2Strategy);

Strategy.prototype.authorizationParams = function (options) {
  var params = {};

  var provider = (options && options.provider) || this._provider;
  if (provider) {
    params.provider = String(provider);
  }

  var langId;
  if (
    options &&
    (typeof options.lang_id !== "undefined" ||
      typeof options.langId !== "undefined")
  ) {
    langId =
      typeof options.lang_id !== "undefined" ? options.lang_id : options.langId;
  } else {
    langId = this._langId;
  }
  if (langId !== undefined && langId !== null && langId !== "") {
    params.lang_id = String(langId);
  }

  var scheme = (options && options.scheme) || this._scheme;
  if (scheme) {
    params.scheme = String(scheme);
  }

  if (options && options.prompt) {
    params.prompt = options.prompt;
  }
  if (options && options.login_hint) {
    params.login_hint = options.login_hint;
  }

  return params;
};

Strategy.prototype.authenticate = function (req, options) {
  options = Object.assign({}, options || {});

  var query = (req && req.query) || {};
  var body = (req && req.body) || {};

  var code = query.code || body.code;
  if (code) {
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
  var params = {};

  if (typeof OAuth2Strategy.prototype.tokenParams === "function") {
    params = OAuth2Strategy.prototype.tokenParams.call(this, options) || {};
  }

  if (options && options._vkid_device_id) {
    params.device_id = options._vkid_device_id;
  }

  if (options && options._vkid_state) {
    params.state = options._vkid_state;
  }

  return params;
};

Strategy.prototype.userProfile = function (accessToken, done) {
  var url = this._userProfileURL;

  this._oauth2.get(
    url,
    accessToken,
    function (err, body, res) {
      if (err) {
        return done(
          new InternalOAuthError("Failed to fetch user profile", err)
        );
      }

      if (res && res.statusCode && res.statusCode !== 200) {
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
        profile = this.parseUserProfile(json);
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

      profile.provider = this._provider;
      profile._raw = typeof body === "string" ? body : JSON.stringify(body);
      profile._json = json;

      return done(null, profile);
    }.bind(this)
  );
};

Strategy.prototype.parseUserProfile = function (response) {
  var user = response && response.user;
  if (!user) {
    return null;
  }

  var userId =
    typeof user.user_id !== "undefined" && user.user_id !== null
      ? user.user_id
      : user.id;
  if (userId === undefined || userId === null || userId === "") {
    return null;
  }

  var firstName = user.first_name || user.firstName || "";
  var lastName = user.last_name || user.lastName || "";

  var displayName = (firstName + " " + lastName).trim();
  if (!displayName) {
    displayName = firstName || lastName || undefined;
  }

  var profile = {
    provider: this._provider,
    id: String(userId),
    user_id: String(userId),
    displayName: displayName,
    name: {
      givenName: firstName || undefined,
      familyName: lastName || undefined,
    },
  };

  if (firstName) {
    profile.first_name = firstName;
  }
  if (lastName) {
    profile.last_name = lastName;
  }
  if (user.email) {
    profile.email = user.email;
  }
  if (typeof user.email_verified !== "undefined") {
    profile.email_verified = user.email_verified;
  }
  if (user.phone) {
    profile.phone = user.phone;
  }
  if (typeof user.phone_verified !== "undefined") {
    profile.phone_verified = user.phone_verified;
  }
  if (user.avatar) {
    profile.avatar = user.avatar;
  }

  return profile;
};

module.exports = Strategy;
module.exports.Strategy = Strategy;
