#falcon-jwt-checker

falcon-jwt-checker is a middleware for the [Falcon](https://falconframework.org/) Python web framework. It checks all requests except those to specified exempt routes for a valid jwt, rejecting those that do not have one present. It uses [PyJwt](https://github.com/jpadilla/pyjwt) to perform jwt validation.

falcon-jwt-checker merely checks for valid jwts on requests, it does not deal with issuing tokens at all. This is because I view that as a separate concern entirely, for which there are a number of possible strategies.
 
## Installation

```
pip install falcon-jwt-checker
```

## Usage

```
import falcon
from falcon_jwt_checker import JwtChecker

jwt_checker = JwtChecker(
    secret='secret_here', # May be a public key
    algorithm='HS256',
    exempt_routes=['/auth'], # Routes listed here will not require a jwt
    audience='api.example.com',
    leeway=30
)

app = falcon.API(middleware=[jwt_checker])

...
```
 
## Tests

```
pytest falcon_jwt_checker
```
 
## License

MIT