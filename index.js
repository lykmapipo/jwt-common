'use strict';


/* dependencies */
const _ = require('lodash');


/**
 * @function encode
 * @name encode
 * @description encode given payload as jwt.
 * @param {Object} payload data to encode.
 * @return {String|Error} jwt token if success or error.
 * @author lally elias <lallyelias87@mail.com>
 * @license MIT
 * @since 0.1.0
 * @version 0.1.0
 * @static
 * @public
 * @example
 * const { encode } = require('@lykmapipo/jwt-common');
 *
 * const secret = process.env.JWT_SECRET || 'xo67Rw';
 * const payload = { _id: 'xo5', permissions: ['user:read'] };
 * encode(payload, (error, jwt) => { ...});
 * encode(payload, { secret }, (error, jwt) => { ...});
 */
exports.encode = function encode(payload, options, done) {
  done();
};


/**
 * @function decode
 * @name decode
 * @description decode and verify given jwt.
 * @param {String} jwy token to decode.
 * @return {Payload|Error} payload if success or error.
 * @author lally elias <lallyelias87@mail.com>
 * @license MIT
 * @since 0.1.0
 * @version 0.1.0
 * @static
 * @public
 * @example
 * const { decode } = require('@lykmapipo/jwt-common');
 *
 * const secret = process.env.JWT_SECRET || 'xo67Rw';
 * const payload = { _id: 'xo5', permissions: ['user:read'] };
 * decode(token, (error, payload) => { ...});
 * decode(token, { secret }, (error, payload) => { ...});
 */
exports.decode = function decode(payload, options, done) {
  done();
};
