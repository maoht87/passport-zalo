/**
 * Parse profile.
 *
 * @param {object|string} json
 * @return {object}
 * @access public
 */
exports.parse = function (json) {
	if ('string' == typeof json) {
		json = JSON.parse(json);
	}

	var profile = {};
	profile.id = json.id;
	profile.displayName = json.name;
	profile.birthday = json.birthday;
	profile.gender = json.gender;
	if (json.picture) {
		if (typeof json.picture == 'object' && json.picture.data) {
			// October 2012 Breaking Changes
			profile.photos = [{ value: json.picture.data.url }];
		} else {
			profile.photos = [{ value: json.picture }];
		}
	}
	return profile;
};
