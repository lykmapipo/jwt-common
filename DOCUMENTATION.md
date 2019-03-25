#### withDefaults([optns]) 

merge provided options with defaults




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| optns | `Object`  | provided options | *Optional* |




##### Examples

```javascript

const { withDefaults } = require('@lykmapipo/jwt-common');
withDefaults({ secret: 'xo67Rw' }) // => { secret: 'xo67Rw', ...}
```


##### Returns


- `Object`  merged options with environment variables



#### encode(payload[, opts], cb) 

encode given payload as jwt.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| payload | `Object`  | data to encode. | &nbsp; |
| opts | `Object`  | jwt sign or encoding options. | *Optional* |
| cb | `Function`  | callback to invoke on success or failure. | &nbsp; |




##### Examples

```javascript

const { encode } = require('@lykmapipo/jwt-common');

const payload = { _id: 'xo5', permissions: ['user:read'] };

// encode with default options
encode(payload, (error, jwt) => { ... });

// encode with merged options
encode(payload, { secret: 'xo67Rw' }, (error, jwt) => { ... });
```


##### Returns


- `String` `Error`  jwt token if success or error.



#### decode(token[, opts], cb) 

decode and verify given jwt.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| token | `String`  | jwt token to decode. | &nbsp; |
| opts | `Object`  | jwt verify or decoding options. | *Optional* |
| cb | `Function`  | callback to invoke on success or failure. | &nbsp; |




##### Examples

```javascript

const { decode } = require('@lykmapipo/jwt-common');

const payload = { _id: 'xo5', permissions: ['user:read'] };

// decode with default options
decode(token, (error, payload) => { ... });

// decode with provided options
decode(token, { secret: 'xo67Rw' }, (error, payload) => { ... });
```


##### Returns


- `Payload` `Error`  payload if success or error.



#### decodeJwtToUser([opts])  *private method*

return a function used to decode jwt to user.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| opts | `Object`  | decoding options. | *Optional* |
| opts.user | `Functon`  |  | *Optional* |




##### Returns


- `Function`  jwt to user decoder



#### parseJwtFromHttpHeaders(done) 

parse request headers to get jwt.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| done | `Function`  | callback to invoke on success or failure. | &nbsp; |




##### Examples

```javascript

const { parseJwtFromHttpHeaders } = require('@lykmapipo/jwt-common');
parseJwtFromHttpHeaders(request, (error, jwt) => { ... });
```


##### Returns


- `Payload` `Error`  jwt if success or error.



#### parseJwtFromHttpQueryParams(done) 

parse request headers to get jwt.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| done | `Function`  | callback to invoke on success or failure. | &nbsp; |




##### Examples

```javascript

const { parseJwtFromHttpQueryParams } = require('@lykmapipo/jwt-common');
parseJwtFromHttpQueryParams(request, (error, jwt) => { ... });
```


##### Returns


- `Payload` `Error`  jwt if success or error.



#### parseJwtFromHttpRequest(done) 

parse request headers to get jwt.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| done | `Function`  | callback to invoke on success or failure. | &nbsp; |




##### Examples

```javascript

const { parseJwtFromHttpRequest } = require('@lykmapipo/jwt-common');
parseJwtFromHttpRequest(request, (error, jwt) => { ... });
```


##### Returns


- `Payload` `Error`  jwt if success or error.



#### jwtAuth([opts]) 

create middlware to authorize request using jwt




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| opts | `Object`  | jwt verify or decoding options. | *Optional* |




##### Examples

```javascript

const { jwtAuth } = require('@lykmapipo/jwt-common');

app.get('/users', jwtAuth({ secret: 'xo67Rw' }), (req, res, next) => { ... });
```


##### Returns


- `Function`  express compactoble middleware.



#### jwtPermit(requiredScopes) 

create middlware to check request for jwt permissions(or scopes).




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| requiredScopes | `Array.<String>` `String`  | required scopes or permissions. | &nbsp; |




##### Examples

```javascript

const { jwtPermit } = require('@lykmapipo/jwt-common');

app.get('/users', jwtPermit('user:read'), (req, res, next) => { ... });
```


##### Returns


- `Function`  express compactoble middleware.




*Documentation generated with [doxdox](https://github.com/neogeek/doxdox).*
