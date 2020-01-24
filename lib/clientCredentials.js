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

var debug = require('./debug');
var events = require('events');
var readCerts = require('./readCerts');
var fs = require('fs');
var config = require('../config/default');
var Post = require('adp-core').post;
var ConnectionException = require('adp-core').connectionException;

/**
@class ClientCredentialsConnection
@param conn {ADPAPIConnection} Connected instance of {@link ADPAPIConnection}
*/
function ClientCredentialsConnection(conn) {

	/**
	@private
	@memberof ClientCredentialsConnection
	@type {string}
	@description Value for the grant type associated with the {@link ClientCredentialsConnection} instance.
	*/
	this.granttype = conn.granttype;

	/**
	@memberof ClientCredentialsConnection
	@description Initiates the connection flow for `authorization_code` grant type.
	@returns {void}
	*/
	this.connect = function connect(cb) {
		debug('Initializing ' + this.granttype + ' connection.');
		this.cb = cb;
		this.getCerts();
	};

	/**
	@private
	@memberof ClientCredentialsConnection
	@description Calls the {@link readCerts} module to validate the cert files and return the cert map.
	@returns {void}
	*/
	this.getCerts = function getCerts() {
		var certPaths = [conn.sslCertPath, conn.sslKeyPath].filter(Boolean);
		if (certPaths.length > 0){
			readCerts({ certs: certPaths }, function readCertsCb(err, certs) {
				if (err) {
					return this.cb(err, certs);
				}
				this.certs = certs;
				this.getAccessToken();
			}.bind(this));
		} else {
			this.getAccessToken();
		}
	};

	/**
	@memberof ClientCredentialsConnection
	@description Sets the token expiration based on the epiration sent from the token end point.
	@param token {object} Token response object.
	@returns {void}
	*/
	this.setTokenExpiration = function setTokenExpiration(token) {
		this.tokenExpirationMs = (token.expires_in || config.connect.defaultexpiration) * 1000;
		var date = new Date();
		date.setSeconds(date.getSeconds() + this.tokenExpirationMs / 1000);
		this.tokenExpiration = date;
	};

	/**
	@private
	@memberof ClientCredentialsConnection
	@description Make call to get access token.
	@returns {void}
	*/
	this.getAccessToken = function getAccessToken() {
		var options = {
			requestDesc: 'Access Token Request',
			url: conn.tokenUrl,
			payload: this.buildTokenRequestBody()
		};
		new Post(options, this.parseTokenResponse.bind(this));
	};

	/**
	@private
	@memberof ClientCredentialsConnection
	@description Parse token response.
	@param err {object} Error object if errors occurred during token request call.
	@param token {object} token response payload.
	@returns {void}
	*/
	this.parseTokenResponse = function parseTokenResponse(err, token) {
		var ex;
		if(err) {
			debug('Get access token retuned error.' + JSON.stringify(err));
			var response = err.response || {};
			var errObject = {
				statusCode: err.statusCode,
				oauthResponse: response.body
			};
			ex = new ConnectionException(errObject);
		}
		if(!token || !token.access_token) {
			debug('Unable to retrieve access token.');
		} else {
			this.setTokenExpiration(token);
		}
		if(typeof this.cb === 'function') {
			this.cb(ex, token);
			delete this.cb;
		}
	};

	/**
	@private
	@memberof ClientCredentialsConnection
	@description Helper function to produce token request payload.
	@returns payload {object} object representation of JSON payload.
	*/
	this.buildTokenRequestBody = function buildTokenRequestBody() {
		return {
			agentOptions: {
				ca: [(conn.sslCertString || fs.readFileSync(conn.sslCertPath))],
				key: (conn.sslKeyString || fs.readFileSync(conn.sslKeyPath)),
				cert: (conn.sslCertString || fs.readFileSync(conn.sslCertPath))
			},
			strictSSL: false,
			auth: {
				user: conn.clientId,
				pass: conn.clientSecret,
				sendImmediately: true
			},
			form: {
				grant_type: this.granttype
			}
		};
	};

}

ClientCredentialsConnection.prototype.__proto__ = events.EventEmitter.prototype;

module.exports = ClientCredentialsConnection;
