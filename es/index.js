import { isFunction, isEmpty, get, flattenDeep } from 'lodash';
import { sign, verify, decode as decode$1 } from 'jsonwebtoken';
import { waterfall, parallel } from 'async';
import { compact, mergeObjects, uniq } from '@lykmapipo/common';
import { getString } from '@lykmapipo/env';

/**
 * @function withDefaults
 * @name withDefaults
 * @description merge provided options with defaults
 * @param  {Object} [optns] provided options
 * @return {Object} merged options with environment variables
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
    secret: getString('JWT_SECRET'),
    algorithm: getString('JWT_ALGORITHM', 'HS256'),
    audience: getString('JWT_AUDIENCE'),
    issuer: getString('JWT_ISSUER'),
    subject: getString('JWT_SUBJECT'),
    expiresIn: getString('JWT_EXPIRES_IN'),
  };

  // merge provided with defaults
  const options = compact(mergeObjects(defaults, optns));

  // return merged options
  return options;
};

/**
 * @function encode
 * @name encode
 * @description encode given payload as jwt.
 * @param {Object} payload data to encode.
 * @param {Object} [opts] jwt sign or encoding options.
 * @param {Function} cb callback to invoke on success or failure.
 * @return {String|Error} jwt token if success or error.
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
  const options = withDefaults(isFunction(optns) ? {} : optns);
  const done = isFunction(optns) ? optns : cb;

  // throw if empty payload
  if (isEmpty(payload)) {
    const error = new Error('Payload Required');
    error.status = 400;
    return done(error);
  }

  // continue with encoding

  // prepare jwt sign options
  const { secret, ...jwtSignOptns } = options;

  // generate jwt
  return sign(payload, secret, jwtSignOptns, done);
};

/**
 * @function decode
 * @name decode
 * @description decode and verify given jwt.
 * @param {String} token jwt token to decode.
 * @param {Object} [opts] jwt verify or decoding options.
 * @param {Function} cb callback to invoke on success or failure.
 * @return {Payload|Error} payload if success or error.
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
  const options = withDefaults(isFunction(optns) ? {} : optns);
  const done = isFunction(optns) ? optns : cb;

  // prepare jwt decoding options
  const { secret, ...jwtVerifyOptns } = options;

  // decode and verify
  return verify(token, secret, jwtVerifyOptns, done);
};

/**
 * @function refresh
 * @name refresh
 * @description decode a given jwt, if expired return new jwt.
 * @param {String} token jwt token to refresh.
 * @param {Object} payload data to encode.
 * @param {Object} [opts] jwt verify or decoding options.
 * @param {Function} cb callback to invoke on success or failure.
 * @return {String|Error} jwt token if success or error.
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
  const options = withDefaults(isFunction(optns) ? {} : optns);
  const done = isFunction(optns) ? optns : cb;

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
    if (!isEmpty(decoded)) {
      return next(null, token);
    }

    // create fresh jwt
    return encode(payload, options, next);
  };

  // prepare refresh tasks
  const tasks = [doDecode, doEncode];

  // do refresh
  return waterfall(tasks, done);
};

/**
 * @function isExpired
 * @name isExpired
 * @description check if jwt expired without verifying if
 * the signature is valid.
 * @param {String} token jwt token to check for expiry.
 * @param {Object} [opts] jwt verify or decoding options.
 * @param {Function} [cb] callback to invoke on success or failure.
 * @return {Boolean} whether jwt expired.
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
  const { payload } = decode$1(token, { complete: true }) || {};

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
 * @param {Object} [opts] decoding options.
 * @param {Functon} [opts.user]
 * @return {Function} jwt to user decoder
 * @author lally elias <lallyelias87@mail.com>
 * @license MIT
 * @since 0.2.0
 * @version 0.1.0
 * @private
 */
const decodeJwtToUser = (optns) => {
  // normalize arguments
  const options = withDefaults(optns);

  // obtain jwt to user decoder
  const { user = (token, next) => next(null, null) } = options;

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
 * @params {Object} request valid http request object.
 * @param {Function} done callback to invoke on success or failure.
 * @return {Payload|Error} jwt if success or error.
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
    get(request, 'headers.authorization') ||
    get(request, 'headers.Authorization');

  // parse jwt from header
  if (!isEmpty(authorization)) {
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
 * @params {Object} request valid http request object.
 * @param {Function} done callback to invoke on success or failure.
 * @return {Payload|Error} jwt if success or error.
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
  const token = get(request, 'query.token');
  if (!isEmpty(token)) {
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
 * @params {Object} request valid http request object.
 * @param {Function} done callback to invoke on success or failure.
 * @return {Payload|Error} jwt if success or error.
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
  parallel(
    {
      headerToken: (next) => parseJwtFromHttpHeaders(request, next),
      urlToken: (next) => parseJwtFromHttpQueryParams(request, next),
    },
    (error, results = {}) => {
      // collect parsed header
      const { headerToken, urlToken } = results;
      const token = headerToken || urlToken;
      if (error || isEmpty(token)) {
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
 * @param {Object} [opts] jwt verify or decoding options.
 * @return {Function} express compactoble middleware.
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
    waterfall(
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
 * @param {String[]|...String} requiredScopes required scopes or permissions.
 * @return {Function} express compactoble middleware.
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
    givenScopes = uniq(
      flattenDeep(givenScopes.map((scope) => scope.split(' ')))
    );

    // check for required scopes
    const permits = uniq([].concat(...requiredScopes));
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

export { decode, decodeJwtToUser, encode, isExpired, jwtAuth, jwtPermit, parseJwtFromHttpHeaders, parseJwtFromHttpQueryParams, parseJwtFromHttpRequest, refresh, withDefaults };
