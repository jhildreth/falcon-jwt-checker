from falcon import HTTPUnauthorized
import jwt


class JwtChecker:
    """A middleware for the Falcon web framework.

    It will verify that a valid, signed jwt is present on requests to any
    resource, except for the specified exempt routes.

    """

    def __init__(self, secret='', algorithm='', exempt_routes=None,
                 audience='', leeway=0):
        """Set up the JwtChecker, including the expected secret,
        algorithm, audience, and any exempted routes for which a jwt
        shall not be required.

        """

        self.secret = secret
        self.algorithm = algorithm
        self.exempt_routes = exempt_routes or []
        self.audience = audience
        self.leeway = leeway

        algorithms = [
            'HS256', 'HS384', 'HS512',
            'ES256', 'ES384', 'ES512',
            'RS256', 'RS384', 'RS512',
            'PS256', 'PS384', 'PS512'
        ]
        if self.algorithm not in algorithms:
            raise RuntimeError('Unsupported algorithm')

    def process_resource(self, req, resp, resource, params):
        """If this is not an exempt route, verify that a valid, signed
        jwt is present.

        """

        if req.path in self.exempt_routes:
            return

        token = req.headers.get('AUTHORIZATION', '').partition('Bearer ')[2]

        try:
            claims = jwt.decode(token,
                                key=self.secret,
                                audience=self.audience,
                                leeway=self.leeway)
            params['jwt_claims'] = {}
            for claim in claims:
                params['jwt_claims'][claim] = claims[claim]
        except jwt.InvalidTokenError as err:
            raise HTTPUnauthorized('Authentication Required',
                                   'Please provide a valid auth token.',
                                   None)
