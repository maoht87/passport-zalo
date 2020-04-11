// Load modules.
var OAuth2Strategy = require('passport-oauth2'),
	util = require('util'),
	uri = require('url'),
	crypto = require('crypto'),
	Profile = require('./profile'),
	InternalOAuthError = require('passport-oauth2').InternalOAuthError,
	ZaloAPIError = require('./errors/apierror');

/**
 * `Strategy` constructor.
 *
 * The Zalo authentication strategy authenticates requests by delegating to
 * Zalo using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `cb`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Zalo application's App ID
 *   - `clientSecret`  your Zalo application's App Secret
 *   - `callbackURL`   URL to which Zalo will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new ZaloStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/zalo/callback'
 *       },
 *       function(accessToken, refreshToken, profile, cb) {
 *         User.findOrCreate(..., function (err, user) {
 *           cb(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {object} options
 * @param {function} verify
 * @access public
 */
function Strategy(options, verify) {
	options = options || {};
	var version = options.graphAPIVersion || 'v3';

	options.authorizationURL =
		options.authorizationURL ||
		'https://oauth.zaloapp.com/' + version + '/auth';
	options.tokenURL =
		options.tokenURL ||
		'https://graph.facebook.com/' + version + '/access_token';
	options.scopeSeparator = options.scopeSeparator || ',';

	OAuth2Strategy.call(this, options, verify);
	this.name = 'zalo';
	this._profileURL = options.profileURL || 'https://graph.zalo.me/v2.0/me';
	this._profileFields = options.profileFields || null;
	this._enableProof = options.enableProof;
	this._clientSecret = options.clientSecret;
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy);

/**
 * Authenticate request by delegating to Facebook using OAuth 2.0.
 *
 * @param {http.IncomingMessage} req
 * @param {object} options
 * @access protected
 */
Strategy.prototype.authenticate = function (req, options) {
	// Facebook doesn't conform to the OAuth 2.0 specification, with respect to
	// redirecting with error codes.
	//
	//   FIX: https://github.com/jaredhanson/passport-oauth/issues/16
	if (req.query && req.query.error_code && !req.query.error) {
		return this.error(
			new ZaloAPIError(
				req.query.error_message,
				parseInt(req.query.error_code, 10)
			)
		);
	}

	OAuth2Strategy.prototype.authenticate.call(this, req, options);
};

/**
 * Return extra Zalo-specific parameters to be included in the authorization
 * request.
 *
 * Options:
 *  - `display`  Display mode to render dialog, { `page`, `popup`, `touch` }.
 *
 * @param {object} options
 * @return {object}
 * @access protected
 */
Strategy.prototype.authorizationParams = function (options) {
	var params = {};

	// https://developers.Zalo.com/docs/reference/dialogs/oauth/
	if (options.display) {
		params.display = options.display;
	}

	// https://developers.Zalo.com/docs/facebook-login/reauthentication/
	if (options.authType) {
		params.auth_type = options.authType;
	}
	if (options.authNonce) {
		params.auth_nonce = options.authNonce;
	}

	return params;
};

/**
 * Retrieve user profile from Zalo.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `zalo`
 *   - `id`               the user's Zalo ID
 *   - `username`         the user's Zalo username
 *   - `displayName`      the user's full name
 *   - `name.familyName`  the user's last name
 *   - `name.givenName`   the user's first name
 *   - `name.middleName`  the user's middle name
 *   - `gender`           the user's gender: `male` or `female`
 *   - `profileUrl`       the URL of the profile for the user on Zalo
 *   - `emails`           the proxied or contact email address granted by the user
 *
 * @param {string} accessToken
 * @param {function} done
 * @access protected
 */
Strategy.prototype.userProfile = function (accessToken, done) {
	var url = uri.parse(this._profileURL);
	if (this._enableProof) {
		// Secure API call by adding proof of the app secret.  This is required when
		// the "Require AppSecret Proof for Server API calls" setting has been
		// enabled.  The proof is a SHA256 hash of the access token, using the app
		// secret as the key.
		//
		// For further details, refer to:
		// https://developers.facebook.com/docs/reference/api/securing-graph-api/
		var proof = crypto
			.createHmac('sha256', this._clientSecret)
			.update(accessToken)
			.digest('hex');
		url.search = url.search ? url.search + '&' : '';
	}
	if (this._profileFields) {
		var fields = this._convertProfileFields(this._profileFields);
		if (fields !== '') {
			url.search =
				(url.search ? url.search + '&' : '') + 'fields=' + fields;
		}
	}
	url = uri.format(url);

	this._oauth2.get(url, accessToken, function (err, body, res) {
		var json;

		if (err) {
			if (err.data) {
				try {
					json = JSON.parse(err.data);
				} catch (_) {}
			}

			if (json && json.error && typeof json.error == 'object') {
				return done(
					new ZaloAPIError(json.error.message, json.error.code)
				);
			}
			return done(
				new InternalOAuthError('Failed to fetch user profile', err)
			);
		}

		try {
			json = JSON.parse(body);
		} catch (ex) {
			return done(new Error('Failed to parse user profile'));
		}

		var profile = Profile.parse(json);
		profile.provider = 'facebook';
		profile._raw = body;
		profile._json = json;

		done(null, profile);
	});
};

/**
 * Parse error response from Zalo OAuth 2.0 token endpoint.
 *
 * @param {string} body
 * @param {number} status
 * @return {Error}
 * @access protected
 */
Strategy.prototype.parseErrorResponse = function (body, status) {
	var json = JSON.parse(body);
	if (json.error && typeof json.error == 'object') {
		return new ZaloAPIError(json.error.message, json.error.code);
	}
	return OAuth2Strategy.prototype.parseErrorResponse.call(this, body, status);
};

/**
 * Convert Zalo profile to a normalized profile.
 *
 * @param {object} profileFields
 * @return {string}
 * @access protected
 */
Strategy.prototype._convertProfileFields = function (profileFields) {
	var map = {
		id: 'id',
		displayName: 'name',
		gender: 'gender',
		birthday: 'birthday',
		photos: 'picture',
	};

	var fields = [];

	profileFields.forEach(function (f) {
		// return raw Zalo profile field to support the many fields that don't
		// map cleanly to Portable Contacts
		if (typeof map[f] === 'undefined') {
			return fields.push(f);
		}

		if (Array.isArray(map[f])) {
			Array.prototype.push.apply(fields, map[f]);
		} else {
			fields.push(map[f]);
		}
	});

	return fields.join(',');
};

// Expose constructor.
module.exports = Strategy;
