from unittest.mock import MagicMock

import falcon
import pytest

from falcon_jwt_checker.falcon_jwt_checker import JwtChecker


class TestJwtChecker:

    def test_rejects_unsupported_algorithm(self):
        with pytest.raises(RuntimeError):
            JwtChecker(algorithm='super_algo')

    def test_raises_401_when_no_auth_header(self):
        with pytest.raises(falcon.HTTPUnauthorized):
            checker = JwtChecker(algorithm='HS256', secret='secret')

            req = MagicMock(spec=falcon.request)
            resp = MagicMock(spec=falcon.response)
            resource = {}
            params = {}

            req.headers = {}
            req.path = '/test'

            checker.process_resource(req, resp, resource, params)

    def test_raises_401_when_no_token_present(self):
        with pytest.raises(falcon.HTTPUnauthorized):
            checker = JwtChecker(algorithm='HS256', secret='secret')

            req = MagicMock(spec=falcon.request)
            resp = MagicMock(spec=falcon.response)
            resource = {}
            params = {}

            req.headers = {'AUTHORIZATION': 'Something else'}
            req.path = '/test'

            checker.process_resource(req, resp, resource, params)

    def test_raises_401_when_bad_token_present(self):
        with pytest.raises(falcon.HTTPUnauthorized):
            checker = JwtChecker(algorithm='HS256', secret='secret')

            req = MagicMock(spec=falcon.request)
            resp = MagicMock(spec=falcon.response)
            resource = {}
            params = {}

            req.headers = {'AUTHORIZATION': 'Bearer xxBadTokenHerexx'}
            req.path = '/test'

            checker.process_resource(req, resp, resource, params)

    def test_adds_claims_to_params_for_valid_token(self):
        valid_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJUZXN0IEF1dGggU3lzdGVtIiwiaWF0IjoxNDc2NTU1NzIyLCJleHAiOjcyNTE0NDUzNjYsImF1ZCI6ImZhbGNvbi1qd3QtY2hlY2tlciIsInN1YiI6InRlc3RfdXNlciIsInJvbGUiOiJhZG1pbiJ9.v3wtjNKnz0-lRCJWm4UdYSkuMZ075PgwBsDL4kET62I'

        checker = JwtChecker(algorithm='HS256', secret='secret',
                             audience='falcon-jwt-checker')

        req = MagicMock(spec=falcon.request)
        resp = MagicMock(spec=falcon.response)
        resource = {}
        params = {}

        req.headers = {'AUTHORIZATION': 'Bearer ' + valid_token}
        req.path = '/test'

        checker.process_resource(req, resp, resource, params)

        assert params['jwt_claims']['sub'] == 'test_user'
        assert params['jwt_claims']['role'] == 'admin'

    def test_jwt_checking_is_skipped_on_exempt_routes(self):
        checker = JwtChecker(algorithm='HS256', secret='secret',
                             audience='falcon-jwt-checker',
                             exempt_routes=['/', '/login'])

        req = MagicMock(spec=falcon.request)
        resp = MagicMock(spec=falcon.response)
        resource = {}
        params = {}

        req.headers = {}
        req.path = '/login'

        checker.process_resource(req, resp, resource, params)
