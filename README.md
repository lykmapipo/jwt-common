# jwt-common

[![Build Status](https://travis-ci.org/lykmapipo/jwt-common.svg?branch=master)](https://travis-ci.org/lykmapipo/jwt-common)
[![Dependencies Status](https://david-dm.org/lykmapipo/jwt-common.svg?style=flat-square)](https://david-dm.org/lykmapipo/jwt-common)
[![Coverage Status](https://coveralls.io/repos/github/lykmapipo/jwt-common/badge.svg?branch=master)](https://coveralls.io/github/lykmapipo/jwt-common?branch=master)

Helper utilities for day to day [jwt](https://jwt.io/) usage.


## Requirements

- [NodeJS v8.11.1+](https://nodejs.org)
- [npm v5.6.0+](https://www.npmjs.com/)

## Installation

```sh
npm install --save @lykmapipo/jwt-common
```

## Usage

```js
const { encode, decode, refresh, isExpired } = require('@lykmapipo/jwt-common');

// plain
encode(payload, (error, jwt) => { ... });
decode(token, (error, jwt) => { ... });
refresh(token, payload, (error, jwt) => { ... });
isExpired(token); //=> false

// express
const { jwtAuth, jwtPermit } = require('@lykmapipo/jwt-common');
const secret = process.env.JWT_SECRET || 'secret';

const user = (token, next) => fetchUser(token._id, next);
app.get('/users', jwtAuth({ secret, user }), (req, res, next) => { ... });
app.get('/users', jwtAuth({ secret, user }), jwtPermit('user:read'), (req, res, next) => { ... });

```

### Environment
If below options are available in `process.env` will be used as default.
```js
process.env.JWT_SECRET
process.env.JWT_ALGORITHM
process.env.JWT_AUDIENCE
process.env.JWT_ISSUER
process.env.JWT_SUBJECT
process.env.JWT_EXPIRES_IN
```

## Test

- Clone this repository

- Install all dependencies

```sh
npm install
```

- Then run test

```sh
npm test
```

## Contribute

It will be nice, if you open an issue first so that we can know what is going on, then, fork this repo and push in your ideas. Do not forget to add a bit of test(s) of what value you adding.

## Licence

The MIT License (MIT)

Copyright (c) 2018 lykmapipo & Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
