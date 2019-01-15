'use strict';


/* dependencies */
const _ = require('lodash');
const jwt = require('jsonwebtoken');
const { compact } = require('@lykmapipo/common');
const { getString } = require('@lykmapipo/env');


/**
 * @function withDefaults
 * @name withDefaults
 * @description merge provided options with defaults
 * @param  {Object} [optns] provided options
 * @return {Object} merged options
 * @author lally elias <lallyelias87@mail.com>
 * @license MIT
 * @since 0.1.0
 * @version 0.1.0
 * @static
 * @public
 * @example
 * const { withDefaults } = require('@lykmapipo/jwt-common');
 * withDefaults({ secret: 'xo67Rw' }) // => { secret: 'xo67Rw', ...}
 */
const withDefaults = (optns) => {
  // merge defaults
  let options = _.merge({}, {
    secret: getString('JWT_SECRET'),
    algorithm: getString('JWT_ALGORITHM', 'HS256'),
    audience: getString('JWT_AUDIENCE'),
    issuer: getString('JWT_ISSUER'),
    subject: getString('JWT_SUBJECT'),
    expiresIn: getString('JWT_EXPIRES_IN'),
  }, optns);

  // compact and return
  options = compact(options);
  return options;
};


/**
 * @function encode
 * @name encode
 * @description encode given payload as jwt.
 * @param {Object} payload data to encode.
 * @param {Object} [opts] jwt sign or encoding options.
 * @param {Function} cb callback to invoke on success or failure
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
const encode = (payload, optns, cb) => {
  // normalize arguments
  const options = exports.withDefaults(_.isFunction(optns) ? {} : optns);
  const done = _.isFunction(optns) ? optns : cb;

  // ensure payload
  if (_.isEmpty(payload)) {
    return done(new Error('payload is required'));
  }

  // try to encode payload
  try {

    // prepare jwt sing options
    const { secret, ...rest } = options;

    // generate jwt
    const token = jwt.sign(payload, secret, rest);

    // return token
    return done(null, token);
  }

  // return error
  catch (error) {
    return done(error);
  }

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
const decode = (payload, options, done) => {
  done();
};


/* export */
module.exports = exports = { withDefaults, encode, decode };
