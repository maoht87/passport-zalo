/**
 * `ZaloAPIError` error.
 * https://developers.zalo.me/docs/api/open-api/tai-lieu/ma-loi-post-1067
 *
 * @constructor
 * @param {string} [message]
 * @param {number} [code]
 * @access public
 */
function ZaloAPIError(message, code) {
	Error.call(this);
	Error.captureStackTrace(this, arguments.callee);
	this.name = 'ZaloAPIError';
	this.message = message;
	this.code = code;
	this.status = 500;
}

// Inherit from `Error`.
ZaloAPIError.prototype.__proto__ = Error.prototype;

// Expose constructor.
module.exports = ZaloAPIError;
