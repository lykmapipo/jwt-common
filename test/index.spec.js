'use strict';


process.env.NODE_ENV = 'test';


/* dependencies */
const { expect } = require('chai');
const { encode, decode } = require('../');


describe('jwt common', () => {
  it('should encode given payload', (done) => {
    expect(encode).to.exist;
    done();
  });

  it('should decode given payload', (done) => {
    expect(decode).to.exist;
    done();
  });
});
