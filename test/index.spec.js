'use strict';


process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'secret';
process.env.JWT_AUDIENCE = 'audience';
process.env.JWT_ISSUER = 'issuer';
process.env.JWT_SUBJECT = 'subject';
process.env.JWT_EXPIRES_IN = '7y';


/* dependencies */
const { waterfall } = require('async');
const { expect } = require('chai');
const { withDefaults, encode, decode } = require('../');


describe('jwt common', () => {

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

  it('should encode given payload', (done) => {
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

  it('should encode given payload with provide options', (done) => {
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

  it('should throw if encode empty payload', (done) => {
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

  it('should decode given payload', (done) => {
    expect(decode).to.exist;
    expect(decode).to.be.a('function');
    expect(decode.name).to.be.equal('decode');
    expect(decode.length).to.be.equal(3);

    const payload = { _id: 'xo5', permissions: ['user:read'] };
    waterfall([
      (next) => encode(payload, next),
      (jwt, next) => decode(jwt, next)
    ], (error, decoded) => {
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
    });
  });

  it('should decode given payload with provided options', (done) => {
    expect(decode).to.exist;
    expect(decode).to.be.a('function');
    expect(decode.name).to.be.equal('decode');
    expect(decode.length).to.be.equal(3);

    const payload = { _id: 'xo5', permissions: ['user:read'] };
    const options = { secret: 'xo67', subject: 'sub', audience: 'aud' };
    waterfall([
      (next) => encode(payload, options, next),
      (jwt, next) => decode(jwt, options, next)
    ], (error, decoded) => {
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
    });
  });
});
