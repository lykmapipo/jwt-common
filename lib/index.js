'use strict';

const lodash = require('lodash');
const jsonwebtoken = require('jsonwebtoken');
const async = require('async');
const common = require('@lykmapipo/common');
const env = require('@lykmapipo/env');

/**
 * @function withDefaults
 * @name withDefaults
 * @description merge provided options with defaults
 * @param  {object} [optns] provided options
 * @returns {object} merged options with environment variables
 * @author lally elias <lallyelias87@mail.com>
 * @license MIT
 * @since 0.1.0
 * @version 0.1.0
 * @static
 * @public
 * @example
 *
 * const { withDefaults } = require('@lykmapipo/jwt-common');
 * withDefaults({ secret: 'xo67Rw' }) // => { secret: 'xo67Rw', ...}
 */
const withDefaults = (optns) => {
  // obtain defaults
  const defaults = {
    secret: env.getString('JWT_SECRET'),
    algorithm: env.getString('JWT_ALGORITHM', 'HS256'),
    audience: env.getString('JWT_AUDIENCE'),
    issuer: env.getString('JWT_ISSUER'),
    subject: env.getString('JWT_SUBJECT'),
    expiresIn: env.getString('JWT_EXPIRES_IN'),
  };

  // merge provided with defaults
  const options = common.compact(common.mergeObjects(defaults, optns));

  // return merged options
  return options;
};

/**
 * @function encode
 * @name encode
 * @description encode given payload as jwt.
 * @param {object} payload data to encode.
 * @param {object} [optns] jwt sign or encoding options.
 * @param {Function} cb callback to invoke on success or failure.
 * @returns {string | Error} jwt token if success or error.
 * @author lally elias <lallyelias87@mail.com>
 * @license MIT
 * @since 0.1.0
 * @version 0.1.0
 * @static
 * @public
 * @example
 *
 * const { encode } = require('@lykmapipo/jwt-common');
 *
 * const payload = { _id: 'xo5', permissions: ['user:read'] };
 *
 * // encode with default options
 * encode(payload, (error, jwt) => { ... });
 *
 * // encode with merged options
 * encode(payload, { secret: 'xo67Rw' }, (error, jwt) => { ... });
 */
const encode = (payload, optns, cb) => {
  // normalize arguments
  const options = withDefaults(lodash.isFunction(optns) ? {} : optns);
  const done = lodash.isFunction(optns) ? optns : cb;

  // throw if empty payload
  if (lodash.isEmpty(payload)) {
    const error = new Error('Payload Required');
    error.status = 400;
    return done(error);
  }

  // continue with encoding

  // prepare jwt sign options
  const { secret, ...jwtSignOptns } = options;

  // generate jwt
  return jsonwebtoken.sign(payload, secret, jwtSignOptns, done);
};

/**
 * @function decode
 * @name decode
 * @description decode and verify given jwt.
 * @param {string} token jwt token to decode.
 * @param {object} [optns] jwt verify or decoding options.
 * @param {Function} cb callback to invoke on success or failure.
 * @returns {object|Error} payload if success or error.
 * @author lally elias <lallyelias87@mail.com>
 * @license MIT
 * @since 0.1.0
 * @version 0.1.0
 * @static
 * @public
 * @example
 *
 * const { decode } = require('@lykmapipo/jwt-common');
 *
 * const token = 'eyJhbGciOiJIUz...';
 *
 * // decode with default options
 * decode(token, (error, payload) => { ... });
 *
 * // decode with provided options
 * decode(token, { secret: 'xo67Rw' }, (error, payload) => { ... });
 */
const decode = (token, optns, cb) => {
  // normalize arguments
  const options = withDefaults(lodash.isFunction(optns) ? {} : optns);
  const done = lodash.isFunction(optns) ? optns : cb;

  // prepare jwt decoding options
  const { secret, ...jwtVerifyOptns } = options;

  // decode and verify
  return jsonwebtoken.verify(token, secret, jwtVerifyOptns, done);
};

/**
 * @function refresh
 * @name refresh
 * @description decode a given jwt, if expired return new jwt.
 * @param {string} token jwt token to refresh.
 * @param {object} payload data to encode.
 * @param {object} [optns] jwt verify or decoding options.
 * @param {Function} cb callback to invoke on success or failure.
 * @returns {string | Error} jwt token if success or error.
 * @author lally elias <lallyelias87@mail.com>
 * @license MIT
 * @since 0.4.0
 * @version 0.1.0
 * @static
 * @public
 * @example
 *
 * const { refresh } = require('@lykmapipo/jwt-common');
 *
 * const token = 'eyJhbGciOiJIUz...';
 * const payload = { _id: 'xo5', permissions: ['user:read'] };
 *
 * // refresh with default options
 * refresh(token, payload, (error, jwt) => { ... });
 *
 * // refresh with provided options
 * refresh(token, payload, { secret: 'xo67Rw' }, (error, jwt) => { ... });
 */
const refresh = (token, payload, optns, cb) => {
  // normalize arguments
  const options = withDefaults(lodash.isFunction(optns) ? {} : optns);
  const done = lodash.isFunction(optns) ? optns : cb;

  // try decode token
  const doDecode = (next) => {
    // decode jwt
    return decode(token, options, (error, decoded) => {
      // ignore if expired(or jwt errors)
      return next(null, decoded || {});
    });
  };

  // try return fresh token
  const doEncode = (decoded, next) => {
    // return token if still valid
    if (!lodash.isEmpty(decoded)) {
      return next(null, token);
    }

    // create fresh jwt
    return encode(payload, options, next);
  };

  // prepare refresh tasks
  const tasks = [doDecode, doEncode];

  // do refresh
  return async.waterfall(tasks, done);
};

/**
 * @function isExpired
 * @name isExpired
 * @description check if jwt expired without verifying if
 * the signature is valid.
 * @param {string} token jwt token to check for expiry.
 * @param {object} [optns] jwt verify or decoding options.
 * @returns {boolean} whether jwt expired.
 * @author lally elias <lallyelias87@mail.com>
 * @license MIT
 * @since 0.4.0
 * @version 0.1.0
 * @static
 * @public
 * @example
 *
 * const { isExpired } = require('@lykmapipo/jwt-common');
 *
 * const token = 'eyJhbGciOiJIUz...';
 *
 * // isExpired with default options
 * isExpired(token); //=> false
 *
 * // isExpired with provided options
 * const optns = { clockTimestamp : Math.floor(Date.now() / 1000) }
 * isExpired(token, optns); //=> true
 */
const isExpired = (token, optns) => {
  // normalize arguments
  const options = withDefaults(optns);

  // obtain clock timestamp
  const clockTimestamp =
    options.clockTimestamp || Math.floor(Date.now() / 1000);

  // decode jwt
  const { payload } = jsonwebtoken.decode(token, { complete: true }) || {};

  // check for expiry
  if (payload && payload.exp) {
    return clockTimestamp >= payload.exp;
  }

  // always true if error
  return true;
};

/**
 * @function decodeJwtToUser
 * @name decodeJwtToUser
 * @description return a function used to decode jwt to user.
 * @param {object} [optns] decoding options.
 * @param {Function} [optns.user] custom user fetch function
 * @returns {Function} jwt to user decoder
 * @author lally elias <lallyelias87@mail.com>
 * @license MIT
 * @since 0.2.0
 * @version 0.1.0
 * @private
 */
const decodeJwtToUser = (optns = {}) => {
  // obtain jwt to user decoder
  const { user = (token, next) => next(null, null) } = optns;

  // wrap decoder
  const decodeToUser = (token, next) => {
    user(token, (error, foundUser) => next(error, token, foundUser));
  };

  // return jwt to user decoder
  return decodeToUser;
};

/**
 * @function parseJwtFromHttpHeaders
 * @name parseJwtFromHttpHeaders
 * @description parse request headers to get jwt.
 * @param {object} request valid http request object.
 * @param {Function} done callback to invoke on success or failure.
 * @returns {object|Error} jwt if success or error.
 * @author lally elias <lallyelias87@mail.com>
 * @license MIT
 * @since 0.1.0
 * @version 0.1.0
 * @static
 * @public
 * @example
 *
 * const { parseJwtFromHttpHeaders } = require('@lykmapipo/jwt-common');
 * parseJwtFromHttpHeaders(request, (error, jwt) => { ... });
 */
const parseJwtFromHttpHeaders = (request, done) => {
  let token;

  // get authorization header
  const authorization =
    lodash.get(request, 'headers.authorization') ||
    lodash.get(request, 'headers.Authorization');

  // parse jwt from header
  if (!lodash.isEmpty(authorization)) {
    // split authorization headers
    const parts = authorization.split(' ');
    const [scheme, parsedToken] = parts;

    // is token in the form of Bearer token
    if (/^Bearer$/i.test(scheme)) {
      token = parsedToken;
    }

    // no its just a token
    else {
      token = scheme;
    }
  }

  // return found token
  return done(null, token);
};

/**
 * @function parseJwtFromHttpQueryParams
 * @name parseJwtFromHttpQueryParams
 * @description parse request headers to get jwt.
 * @param {object} request valid http request object.
 * @param {Function} done callback to invoke on success or failure.
 * @returns {object|Error} jwt if success or error.
 * @author lally elias <lallyelias87@mail.com>
 * @license MIT
 * @since 0.1.0
 * @version 0.1.0
 * @static
 * @public
 * @example
 *
 * const { parseJwtFromHttpQueryParams } = require('@lykmapipo/jwt-common');
 * parseJwtFromHttpQueryParams(request, (error, jwt) => { ... });
 */
const parseJwtFromHttpQueryParams = (request, done) => {
  // get jwt from request query params
  const token = lodash.get(request, 'query.token');
  if (!lodash.isEmpty(token)) {
    // delete the token from query params
    delete request.query.token;
  }

  // return found token
  return done(null, token);
};

/**
 * @function parseJwtFromHttpRequest
 * @name parseJwtFromHttpRequest
 * @description parse request headers to get jwt.
 * @param {object} request valid http request object.
 * @param {Function} done callback to invoke on success or failure.
 * @returns {object|Error} jwt if success or error.
 * @author lally elias <lallyelias87@mail.com>
 * @license MIT
 * @since 0.1.0
 * @version 0.1.0
 * @static
 * @public
 * @example
 *
 * const { parseJwtFromHttpRequest } = require('@lykmapipo/jwt-common');
 * parseJwtFromHttpRequest(request, (error, jwt) => { ... });
 */
const parseJwtFromHttpRequest = (request, done) => {
  // parse for jwt from request headers and query params
  return async.parallel(
    {
      headerToken: (next) => parseJwtFromHttpHeaders(request, next),
      urlToken: (next) => parseJwtFromHttpQueryParams(request, next),
    },
    (error, results = {}) => {
      // collect parsed header
      const { headerToken, urlToken } = results;
      const token = headerToken || urlToken;
      if (error || lodash.isEmpty(token)) {
        error = error || new Error('Unauthorized'); //eslint-disable-line
        error.status = error.status || 401; //eslint-disable-line
        error.message = error.message || 'Unauthorized'; //eslint-disable-line
        return done(error);
      }
      return done(null, token);
    }
  );
};

/**
 * @function jwtAuth
 * @name jwtAuth
 * @description create middlware to authorize request using jwt
 * @param {object} [optns] jwt verify or decoding options.
 * @returns {Function} express compactoble middleware.
 * @author lally elias <lallyelias87@mail.com>
 * @license MIT
 * @since 0.1.0
 * @version 0.1.0
 * @static
 * @public
 * @example
 *
 * const { jwtAuth } = require('@lykmapipo/jwt-common');
 *
 * app.get('/users', jwtAuth({ secret: 'xo67Rw' }), (req, res, next) => { ... });
 */
const jwtAuth = (optns) => {
  // implement jwt authorize middleware
  const jwtAuthorize = (request, response, next) => {
    // parse jwt from request
    const parseJwt = (cb) => parseJwtFromHttpRequest(request, cb);

    // decode jwt from request
    const decodeJwt = (token, cb) => decode(token, optns, cb);

    // run
    async.waterfall(
      [parseJwt, decodeJwt, decodeJwtToUser(optns)],
      (error, token, user) => {
        // handle error
        if (error) {
          error.status = error.status || 401; //eslint-disable-line
          error.message = error.message || 'Unauthorized'; //eslint-disable-line
          return next(error);
        }
        // set jwt and continue

        request.jwt = token;
        request.user = user;
        return next();
      }
    );
  };

  // return
  return jwtAuthorize;
};

/**
 * @function jwtPermit
 * @name jwtPermit
 * @description create middlware to check request for jwt permissions(or scopes).
 * @param {string[] | ...string} requiredScopes required scopes or permissions.
 * @returns {Function} express compactoble middleware.
 * @author lally elias <lallyelias87@mail.com>
 * @license MIT
 * @since 0.1.0
 * @version 0.1.0
 * @static
 * @public
 * @example
 *
 * const { jwtPermit } = require('@lykmapipo/jwt-common');
 *
 * app.get('/users', jwtPermit('user:read'), (req, res, next) => { ... });
 */
const jwtPermit = (...requiredScopes) => {
  // implement jwt permit
  const checkJwtPermit = (request, response, next) => {
    // obtain user and jwt from request
    const { user = {}, jwt = {} } = request;

    // obtain scopes
    const jwtScopes = jwt.scope || jwt.scopes || jwt.permissions;
    const userScopes = user.scope || user.scopes || user.permissions;
    let givenScopes = [].concat(userScopes || jwtScopes);
    givenScopes = common.uniq(
      lodash.flattenDeep(givenScopes.map((scope) => scope.split(' ')))
    );

    // check for required scopes
    const permits = common.uniq([].concat(...requiredScopes));
    const allowed = permits.some((scope) => givenScopes.includes(scope));

    // has scopes
    if (allowed) {
      return next();
    }
    // has no scopes

    const error = new Error('Forbidden');
    error.status = 403;
    return next(error);
  };

  // return
  return checkJwtPermit;
};

exports.decode = decode;
exports.decodeJwtToUser = decodeJwtToUser;
exports.encode = encode;
exports.isExpired = isExpired;
exports.jwtAuth = jwtAuth;
exports.jwtPermit = jwtPermit;
exports.parseJwtFromHttpHeaders = parseJwtFromHttpHeaders;
exports.parseJwtFromHttpQueryParams = parseJwtFromHttpQueryParams;
exports.parseJwtFromHttpRequest = parseJwtFromHttpRequest;
exports.refresh = refresh;
exports.withDefaults = withDefaults;
