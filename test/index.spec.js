import { waterfall } from 'async';
import { expect } from 'chai';
import {
  withDefaults,
  encode,
  decode,
  parseJwtFromHttpHeaders,
  parseJwtFromHttpQueryParams,
  parseJwtFromHttpRequest,
  jwtAuth,
  jwtPermit,
} from '../src/index';

describe('jwt common', () => {
  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = 'secret';
  process.env.JWT_AUDIENCE = 'audience';
  process.env.JWT_ISSUER = 'issuer';
  process.env.JWT_SUBJECT = 'subject';
  process.env.JWT_EXPIRES_IN = '7y';

  it('should merge options with defaults', () => {
    expect(withDefaults).to.exist;
    expect(withDefaults).to.be.a('function');
    expect(withDefaults.name).to.be.equal('withDefaults');
    expect(withDefaults.length).to.be.equal(1);

    const options = withDefaults();
    expect(options.secret).to.be.equal('secret');
    expect(options.algorithm).to.be.equal('HS256');
    expect(options.audience).to.be.equal('audience');
    expect(options.issuer).to.be.equal('issuer');
    expect(options.subject).to.be.equal('subject');
    expect(options.expiresIn).to.be.equal('7y');
  });

  it('should encode given payload', done => {
    expect(encode).to.exist;
    expect(encode).to.be.a('function');
    expect(encode.name).to.be.equal('encode');
    expect(encode.length).to.be.equal(3);

    const payload = { _id: 'xo5', permissions: ['user:read'] };
    encode(payload, (error, jwt) => {
      expect(error).to.not.exist;
      expect(jwt).to.exist;
      done(error, jwt);
    });
  });

  it('should encode given payload with provide options', done => {
    expect(encode).to.exist;
    expect(encode).to.be.a('function');
    expect(encode.name).to.be.equal('encode');
    expect(encode.length).to.be.equal(3);

    const payload = { _id: 'xo5', permissions: ['user:read'] };
    const options = { secret: 'xo67' };
    encode(payload, options, (error, jwt) => {
      expect(error).to.not.exist;
      expect(jwt).to.exist;
      done(error, jwt);
    });
  });

  it('should throw if encode empty payload', done => {
    expect(encode).to.exist;
    expect(encode).to.be.a('function');
    expect(encode.name).to.be.equal('encode');
    expect(encode.length).to.be.equal(3);

    encode({}, (error, jwt) => {
      expect(error).to.exist;
      expect(jwt).to.not.exist;
      expect(error.message).to.be.equal('payload is required');
      done();
    });
  });

  it('should decode given payload', done => {
    expect(decode).to.exist;
    expect(decode).to.be.a('function');
    expect(decode.name).to.be.equal('decode');
    expect(decode.length).to.be.equal(3);

    const payload = { _id: 'xo5', permissions: ['user:read'] };
    waterfall(
      [next => encode(payload, next), (jwt, next) => decode(jwt, next)],
      (error, decoded) => {
        expect(error).to.not.exist;
        expect(decoded).to.exist;
        expect(decoded._id).to.be.equal(payload._id);
        expect(decoded.permissions).to.be.eql(payload.permissions);
        expect(decoded.iat).to.exist;
        expect(decoded.exp).to.exist;
        expect(decoded.aud).to.be.equal('audience');
        expect(decoded.iss).to.be.equal('issuer');
        expect(decoded.sub).to.be.equal('subject');
        done(error, decoded);
      }
    );
  });

  it('should decode given payload with provided options', done => {
    expect(decode).to.exist;
    expect(decode).to.be.a('function');
    expect(decode.name).to.be.equal('decode');
    expect(decode.length).to.be.equal(3);

    const payload = { _id: 'xo5', permissions: ['user:read'] };
    const options = { secret: 'xo67', subject: 'sub', audience: 'aud' };
    waterfall(
      [
        next => encode(payload, options, next),
        (jwt, next) => decode(jwt, options, next),
      ],
      (error, decoded) => {
        expect(error).to.not.exist;
        expect(decoded).to.exist;
        expect(decoded._id).to.be.equal(payload._id);
        expect(decoded.permissions).to.be.eql(payload.permissions);
        expect(decoded.iat).to.exist;
        expect(decoded.exp).to.exist;
        expect(decoded.aud).to.be.equal('aud');
        expect(decoded.iss).to.be.equal('issuer');
        expect(decoded.sub).to.be.equal('sub');
        done(error, decoded);
      }
    );
  });

  it('should parse jwt from http headers', done => {
    expect(parseJwtFromHttpHeaders).to.exist;
    expect(parseJwtFromHttpHeaders).to.be.a('function');
    expect(parseJwtFromHttpHeaders.name).to.be.equal('parseJwtFromHttpHeaders');
    expect(parseJwtFromHttpHeaders.length).to.be.equal(2);

    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiJ4bzUiLCJwZXJtaXNzaW9ucyI6WyJ1c2VyOnJlYWQiXSwiaWF0IjoxNTQ3NTM0MzY0LCJleHAiOjE3Njg0Mzc1NjQsImF1ZCI6ImF1ZGllbmNlIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCJ9.k5efjPoUWuZMHtonYzNsbfPxWjZTBKUxjh5QzREtiYw';

    const request = { headers: { authorization: `Bearer ${jwt}` } };

    parseJwtFromHttpHeaders(request, (error, token) => {
      expect(error).to.not.exist;
      expect(token).to.exist;
      expect(token).to.be.equal(jwt);
      done(error, token);
    });
  });

  it('should parse jwt from http headers', done => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiJ4bzUiLCJwZXJtaXNzaW9ucyI6WyJ1c2VyOnJlYWQiXSwiaWF0IjoxNTQ3NTM0MzY0LCJleHAiOjE3Njg0Mzc1NjQsImF1ZCI6ImF1ZGllbmNlIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCJ9.k5efjPoUWuZMHtonYzNsbfPxWjZTBKUxjh5QzREtiYw';

    const request = { headers: { authorization: jwt } };

    parseJwtFromHttpHeaders(request, (error, token) => {
      expect(error).to.not.exist;
      expect(token).to.exist;
      expect(token).to.be.equal(jwt);
      done(error, token);
    });
  });

  it('should parse jwt from http query params', done => {
    expect(parseJwtFromHttpQueryParams).to.exist;
    expect(parseJwtFromHttpQueryParams).to.be.a('function');
    expect(parseJwtFromHttpQueryParams.name).to.be.equal(
      'parseJwtFromHttpQueryParams'
    );
    expect(parseJwtFromHttpQueryParams.length).to.be.equal(2);

    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiJ4bzUiLCJwZXJtaXNzaW9ucyI6WyJ1c2VyOnJlYWQiXSwiaWF0IjoxNTQ3NTM0MzY0LCJleHAiOjE3Njg0Mzc1NjQsImF1ZCI6ImF1ZGllbmNlIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCJ9.k5efjPoUWuZMHtonYzNsbfPxWjZTBKUxjh5QzREtiYw';

    const request = { query: { token: jwt } };

    parseJwtFromHttpQueryParams(request, (error, token) => {
      expect(error).to.not.exist;
      expect(token).to.exist;
      expect(token).to.be.equal(jwt);
      done(error, token);
    });
  });

  it('should parse jwt from http request', done => {
    expect(parseJwtFromHttpRequest).to.exist;
    expect(parseJwtFromHttpRequest).to.be.a('function');
    expect(parseJwtFromHttpRequest.name).to.be.equal('parseJwtFromHttpRequest');
    expect(parseJwtFromHttpRequest.length).to.be.equal(2);

    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiJ4bzUiLCJwZXJtaXNzaW9ucyI6WyJ1c2VyOnJlYWQiXSwiaWF0IjoxNTQ3NTM0MzY0LCJleHAiOjE3Njg0Mzc1NjQsImF1ZCI6ImF1ZGllbmNlIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCJ9.k5efjPoUWuZMHtonYzNsbfPxWjZTBKUxjh5QzREtiYw';

    const request = { headers: { authorization: `Bearer ${jwt}` } };

    parseJwtFromHttpRequest(request, (error, token) => {
      expect(error).to.not.exist;
      expect(token).to.exist;
      expect(token).to.be.equal(jwt);
      done(error, token);
    });
  });

  it('should parse jwt from http request', done => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiJ4bzUiLCJwZXJtaXNzaW9ucyI6WyJ1c2VyOnJlYWQiXSwiaWF0IjoxNTQ3NTM0MzY0LCJleHAiOjE3Njg0Mzc1NjQsImF1ZCI6ImF1ZGllbmNlIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCJ9.k5efjPoUWuZMHtonYzNsbfPxWjZTBKUxjh5QzREtiYw';

    const request = { headers: { authorization: jwt } };

    parseJwtFromHttpRequest(request, (error, token) => {
      expect(error).to.not.exist;
      expect(token).to.exist;
      expect(token).to.be.equal(jwt);
      done(error, token);
    });
  });

  it('should parse jwt from http request', done => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiJ4bzUiLCJwZXJtaXNzaW9ucyI6WyJ1c2VyOnJlYWQiXSwiaWF0IjoxNTQ3NTM0MzY0LCJleHAiOjE3Njg0Mzc1NjQsImF1ZCI6ImF1ZGllbmNlIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCJ9.k5efjPoUWuZMHtonYzNsbfPxWjZTBKUxjh5QzREtiYw';

    const request = { query: { token: jwt } };

    parseJwtFromHttpRequest(request, (error, token) => {
      expect(error).to.not.exist;
      expect(token).to.exist;
      expect(token).to.be.equal(jwt);
      done(error, token);
    });
  });

  it('should authorize http request', done => {
    expect(jwtAuth).to.exist;
    expect(jwtAuth).to.be.a('function');
    expect(jwtAuth.name).to.be.equal('jwtAuth');
    expect(jwtAuth.length).to.be.equal(1);

    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiJ4bzUiLCJwZXJtaXNzaW9ucyI6WyJ1c2VyOnJlYWQiXSwiaWF0IjoxNTQ3NTM3MjgwLCJleHAiOjE3Njg0NDA0ODAsImF1ZCI6ImF1ZGllbmNlIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCJ9.ZMe4zfu9l8UPM08nMQmRMLZx3rj0AeUNNsGjczMv2A4';
    const payload = { _id: 'xo5', permissions: ['user:read'] };
    const request = { headers: { authorization: `Bearer ${jwt}` } };
    const response = {};

    jwtAuth()(request, response, error => {
      expect(error).to.not.exist;
      expect(request.jwt).to.exist;
      expect(request.jwt._id).to.be.equal(payload._id);
      expect(request.jwt.permissions).to.be.eql(payload.permissions);
      done(error);
    });
  });

  it('should authorize http request with options', done => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiJ4bzUiLCJwZXJtaXNzaW9ucyI6WyJ1c2VyOnJlYWQiXSwiaWF0IjoxNTQ3NTM3NTkyLCJleHAiOjE3Njg0NDA3OTIsImF1ZCI6ImF1ZGllbmNlIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCJ9.0dHIXyBV1385t72eZ4GZ_wXaGV2SPh2lfUkw81bCQb4';

    const options = { secret: 'xo67' };
    const payload = { _id: 'xo5', permissions: ['user:read'] };
    const request = { headers: { authorization: `Bearer ${jwt}` } };
    const response = {};

    jwtAuth(options)(request, response, error => {
      expect(error).to.not.exist;
      expect(request.jwt).to.exist;
      expect(request.jwt._id).to.be.equal(payload._id);
      expect(request.jwt.permissions).to.be.eql(payload.permissions);
      done(error);
    });
  });

  it('should authorize http request and decode jwt to user', done => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiJ4bzUiLCJwZXJtaXNzaW9ucyI6WyJ1c2VyOnJlYWQiXSwiaWF0IjoxNTQ3NTM3NTkyLCJleHAiOjE3Njg0NDA3OTIsImF1ZCI6ImF1ZGllbmNlIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCJ9.0dHIXyBV1385t72eZ4GZ_wXaGV2SPh2lfUkw81bCQb4';

    const user = (token, next) => next(null, { name: 'user' });
    const options = { secret: 'xo67', user };
    const payload = { _id: 'xo5', permissions: ['user:read'] };
    const request = { headers: { authorization: `Bearer ${jwt}` } };
    const response = {};

    jwtAuth(options)(request, response, error => {
      expect(error).to.not.exist;
      expect(request.jwt).to.exist;
      expect(request.jwt._id).to.be.equal(payload._id);
      expect(request.user).to.exist;
      expect(request.user).to.be.eql({ name: 'user' });
      expect(request.jwt.permissions).to.be.eql(payload.permissions);
      done(error);
    });
  });

  it('should throw unauthorized if token missing', done => {
    const request = {};
    const response = {};

    jwtAuth()(request, response, error => {
      expect(error).to.exist;
      expect(error.message).to.be.equal('Unauthorized');
      expect(error.status).to.be.equal(401);
      done();
    });
  });

  it('should permit http request with required scopes', done => {
    expect(jwtPermit).to.exist;
    expect(jwtPermit).to.be.a('function');
    expect(jwtPermit.name).to.be.equal('jwtPermit');

    const payload = { _id: 'xo5', permissions: ['user:read'] };
    const request = { jwt: payload };
    const response = {};

    jwtPermit('user:read')(request, response, error => {
      expect(error).to.not.exist;
      expect(request.jwt).to.exist;
      done();
    });
  });

  it('should throw insufficient scopes if miss required scopes', done => {
    const payload = { _id: 'xo5', permissions: ['user:read'] };
    const request = { jwt: payload };
    const response = {};

    jwtPermit('user:create')(request, response, error => {
      expect(error).to.exist;
      expect(error.message).to.be.equal('Forbidden');
      expect(error.status).to.be.equal(403);
      done();
    });
  });
});
