'use strict';


process.env.NODE_ENV = 'test';


/* dependencies */
const { expect } = require('chai');
const { withDefaults, encode, decode } = require('../');


describe('jwt common', () => {

  it('should merge options with defaults', () => {
    expect(withDefaults).to.exist;
    expect(withDefaults).to.be.a('function');
    expect(withDefaults.name).to.be.equal('withDefaults');
    expect(withDefaults.length).to.be.equal(1);

    // set process.env
    process.env.JWT_SECRET = 'secret';
    process.env.JWT_AUDIENCE = 'audience';
    process.env.JWT_ISSUER = 'issuer';
    process.env.JWT_SUBJECT = 'subject';
    process.env.JWT_EXPIRES_IN = '7y';

    const options = withDefaults();
    expect(options.secret).to.be.equal('secret');
    expect(options.algorithm).to.be.equal('HS256');
    expect(options.audience).to.be.equal('audience');
    expect(options.issuer).to.be.equal('issuer');
    expect(options.subject).to.be.equal('subject');
    expect(options.expiresIn).to.be.equal('7y');

    // clear process.env
    delete process.env.JWT_SECRET;
    delete process.env.JWT_AUDIENCE;
    delete process.env.JWT_ISSUER;
    delete process.env.JWT_SUBJECT;
    delete process.env.JWT_EXPIRES_IN;
  });

  it('should encode given payload', (done) => {
    expect(encode).to.exist;
    done();
  });

  it('should decode given payload', (done) => {
    expect(decode).to.exist;
    done();
  });
});
