import _ from 'lodash';
import { sign, verify } from 'jsonwebtoken';
import { parallel, waterfall } from 'async';
import { compact, uniq } from '@lykmapipo/common';
import { getString } from '@lykmapipo/env';

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
export const withDefaults = optns => {
  // merge defaults
  let options = _.merge(
    {},
    {
      secret: getString('JWT_SECRET'),
      algorithm: getString('JWT_ALGORITHM', 'HS256'),
      audience: getString('JWT_AUDIENCE'),
      issuer: getString('JWT_ISSUER'),
      subject: getString('JWT_SUBJECT'),
      expiresIn: getString('JWT_EXPIRES_IN'),
    },
    optns
  );

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
 * @param {Function} cb callback to invoke on success or failure.
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
export const encode = (payload, optns, cb) => {
  // normalize arguments
  const options = withDefaults(_.isFunction(optns) ? {} : optns);
  const done = _.isFunction(optns) ? optns : cb;

  // throw if empty payload
  if (_.isEmpty(payload)) {
    return done(new Error('payload is required'));
  }

  // prepare jwt sign options
  const { secret, ...rest } = options;

  // generate jwt
  return sign(payload, secret, rest, done);
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
 * const { decode } = require('@lykmapipo/jwt-common');
 *
 * const secret = process.env.JWT_SECRET || 'xo67Rw';
 * const payload = { _id: 'xo5', permissions: ['user:read'] };
 * decode(token, (error, payload) => { ...});
 * decode(token, { secret }, (error, payload) => { ...});
 */
export const decode = (token, optns, cb) => {
  // normalize arguments
  const options = withDefaults(_.isFunction(optns) ? {} : optns);
  const done = _.isFunction(optns) ? optns : cb;

  // prepare jwt decoding options
  const { secret, ...rest } = options;

  // decode and verify
  verify(token, secret, rest, done);
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
export const decodeJwtToUser = optns => {
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
 * const { parseJwtFromHttpHeaders } = require('@lykmapipo/jwt-common');
 * parseJwtFromHttpHeaders(request, (error, jwt) => { ... });
 */
export const parseJwtFromHttpHeaders = (request, done) => {
  let token;

  // get authorization header
  const authorization =
    _.get(request, 'headers.authorization') ||
    _.get(request, 'headers.Authorization');

  // parse jwt from header
  if (!_.isEmpty(authorization)) {
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
  done(null, token);
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
 * const { parseJwtFromHttpQueryParams } = require('@lykmapipo/jwt-common');
 * parseJwtFromHttpQueryParams(request, (error, jwt) => { ... });
 */
export const parseJwtFromHttpQueryParams = (request, done) => {
  // get jwt from request query params
  const token = _.get(request, 'query.token');
  if (!_.isEmpty(token)) {
    // delete the token from query params
    delete request.query.token;
  }

  // return found token
  done(null, token);
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
 * const { parseJwtFromHttpRequest } = require('@lykmapipo/jwt-common');
 * parseJwtFromHttpRequest(request, (error, jwt) => { ... });
 */
export const parseJwtFromHttpRequest = (request, done) => {
  // parse for jwt from request headers and query params
  parallel(
    {
      headerToken: next => parseJwtFromHttpHeaders(request, next),
      urlToken: next => parseJwtFromHttpQueryParams(request, next),
    },
    (error, results = {}) => {
      // collect parsed header
      const { headerToken, urlToken } = results;
      const token = headerToken || urlToken;
      if (error || _.isEmpty(token)) {
        error = error || new Error('Unauthorized'); //eslint-disable-line
        error.status = error.status || 401; //eslint-disable-line
        error.message = error.message || 'Unauthorized'; //eslint-disable-line
        done(error);
      } else {
        done(null, token);
      }
    }
  );
};

/**
 * @function jwtAuth
 * @name jwtAuth
 * @description create middlware to authorize request using jwt
 * @param {Object} [opts] jwt verify or decoding options.
 * @author lally elias <lallyelias87@mail.com>
 * @license MIT
 * @since 0.1.0
 * @version 0.1.0
 * @static
 * @public
 * @example
 * const { jwtAuth } = require('@lykmapipo/jwt-common');
 * const secret = process.env.JWT_SECRET || 'xo67Rw';
 * app.get('/users', jwtAuth({ secret }), (req, res, next) => { ... });
 */
export const jwtAuth = optns => {
  // implement jwt authorize middleware
  const jwtAuthorize = (request, response, next) => {
    // parse jwt from request
    const parseJwt = cb => parseJwtFromHttpRequest(request, cb);

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
          next(error);
        }
        // set jwt and continue
        else {
          request.jwt = token;
          request.user = user;
          next();
        }
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
 * @author lally elias <lallyelias87@mail.com>
 * @license MIT
 * @since 0.1.0
 * @version 0.1.0
 * @static
 * @public
 * @example
 * const { jwtPermit } = require('@lykmapipo/jwt-common');
 *
 * app.get('/users', jwtPermit('user:read'), (req, res, next) => { ... });
 */
export const jwtPermit = (...requiredScopes) => {
  // implement jwt permit
  const checkJwtPermit = (request, response, next) => {
    // obtain user and jwt from request
    const { user = {}, jwt = {} } = request;

    // obtain scopes
    const jwtScopes = jwt.scope || jwt.scopes || jwt.permissions;
    const userScopes = user.scope || user.scopes || user.permissions;
    let givenScopes = [].concat(userScopes || jwtScopes);
    givenScopes = uniq(
      _.flattenDeep(givenScopes.map(scope => scope.split(' ')))
    );

    // check for required scopes
    const permits = uniq([].concat(...requiredScopes));
    const allowed = permits.some(scope => givenScopes.includes(scope));

    // has scopes
    if (allowed) {
      next();
    }
    // has no scopes
    else {
      const error = new Error('Forbidden');
      error.status = 403;
      next(error);
    }
  };

  // return
  return checkJwtPermit;
};
