/*
Copyright © 2015-2016 ADP, LLC.

Licensed under the Apache License, Version 2.0 (the “License”);
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an “AS IS” BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
express or implied.  See the License for the specific language
governing permissions and limitations under the License.
*/

'use strict';

var fs = require('fs');
var debug = require('./debug');
var config = require('../config/default');
var ConfigurationException = require('adp-core').configurationException;

/**
@module ReadCerts
@description This module validates that the cert files exist. It also validates the file types against the config>connect>validCertTypes array.
@param opts {object} contains cert property which is array of cert file locations.
@param cb {function} Function to be executed once cert files are validated or upon exception during validation.
@returns {void}
*/
module.exports = function readCerts(opts, cb) {
	var certFiles = opts.certs;
	var certFileTypes = config.connect.validCertTypes;
	var certPaths = [];
	var err;
	certFiles.forEach(function certFilesForEachCb(f) {
		try{
			fs.readFileSync(f);
			var fileType;
			var tmpFile = f || '';
			fileType = tmpFile.substring(tmpFile.lastIndexOf('.') + 1, tmpFile.length);
			if(~certFileTypes.indexOf(fileType)){
				certPaths.push({
					type: fileType,
					path: f
				});
			}
		} catch(e) {
			err = new ConfigurationException({description: 'Invalid cert path', message: 'Cert files provided cannot be found. `' + f + '` was not present.'});
		}

	});
	if(certPaths.length === 0 && certStrings === 0){
		debug('Unable to find valid cert files or strings.');
	} else {
		debug('Cert files located. Files: ' + JSON.stringify(certPaths));
	}
	return cb(err, certPaths);
};
