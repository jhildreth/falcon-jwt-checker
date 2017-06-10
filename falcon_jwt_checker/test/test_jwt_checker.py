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

            req = MagicMock(spec=falcon.Request)
            resp = MagicMock(spec=falcon.Response)
            resource = {}
            params = {}

            req.headers = {}
            req.path = '/test'

            checker.process_resource(req, resp, resource, params)

    def test_raises_401_when_no_token_present(self):
        with pytest.raises(falcon.HTTPUnauthorized):
            checker = JwtChecker(algorithm='HS256', secret='secret')

            req = MagicMock(spec=falcon.Request)
            resp = MagicMock(spec=falcon.Response)
            resource = {}
            params = {}

            req.headers = {'AUTHORIZATION': 'Something else'}
            req.path = '/test'

            checker.process_resource(req, resp, resource, params)

    def test_raises_401_when_bad_token_present(self):
        with pytest.raises(falcon.HTTPUnauthorized):
            checker = JwtChecker(algorithm='HS256', secret='secret')

            req = MagicMock(spec=falcon.Request)
            resp = MagicMock(spec=falcon.Response)
            resource = {}
            params = {}

            req.headers = {'AUTHORIZATION': 'Bearer xxBadTokenHerexx'}
            req.path = '/test'

            checker.process_resource(req, resp, resource, params)

    def test_adds_claims_to_params_for_valid_token(self):
        valid_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJUZXN0IEF1dGggU3lzdGVtIiwiaWF0IjoxNDc2NTU1NzIyLCJleHAiOjcyNTE0NDUzNjYsImF1ZCI6ImZhbGNvbi1qd3QtY2hlY2tlciIsInN1YiI6InRlc3RfdXNlciIsInJvbGUiOiJhZG1pbiJ9.v3wtjNKnz0-lRCJWm4UdYSkuMZ075PgwBsDL4kET62I'

        checker = JwtChecker(algorithm='HS256', secret='secret',
                             audience='falcon-jwt-checker')

        req = MagicMock(spec=falcon.Request)
        resp = MagicMock(spec=falcon.Response)
        resource = {}
        params = {}

        req.headers = {'AUTHORIZATION': 'Bearer ' + valid_token}
        req.path = '/test'

        checker.process_resource(req, resp, resource, params)

        assert params['jwt_claims']['sub'] == 'test_user'
        assert params['jwt_claims']['role'] == 'admin'
        assert params['jwt_claims']['iss'] == 'Test Auth System'
        assert params['jwt_claims']['aud'] == 'falcon-jwt-checker'

    def test_jwt_checking_is_skipped_on_exempt_routes(self):
        checker = JwtChecker(algorithm='HS256', secret='secret',
                             audience='falcon-jwt-checker',
                             exempt_routes=['/', '/login'])

        req = MagicMock(spec=falcon.Request)
        resp = MagicMock(spec=falcon.Response)
        resource = {}
        params = {}

        req.headers = {}
        req.path = '/login'

        checker.process_resource(req, resp, resource, params)

        # Test that only the specified route is exempt
        with pytest.raises(falcon.HTTPUnauthorized):
            req = MagicMock(spec=falcon.Request)
            resp = MagicMock(spec=falcon.Response)

            req.headers = {}
            req.path = '/test'

            checker.process_resource(req, resp, resource, params)

    def test_jwt_checking_is_skipped_for_exempt_methods(self):
        checker = JwtChecker(algorithm='HS256', secret='secret',
                             audience='falcon-jwt-checker',
                             exempt_methods=['OPTIONS'])

        req = MagicMock(spec=falcon.request)
        resp = MagicMock(spec=falcon.response)
        resource = {}
        params = {}

        req.headers = {}
        req.path = '/test'
        req.method = 'OPTIONS'

        checker.process_resource(req, resp, resource, params)

        # Test that only the specified method is exempt
        with pytest.raises(falcon.HTTPUnauthorized):
            req = MagicMock(spec=falcon.Request)
            resp = MagicMock(spec=falcon.Response)

            req.headers = {}
            req.path = '/test'
            req.method = 'GET'

            checker.process_resource(req, resp, resource, params)

    def test_raises_401_when_audience_is_wrong(self):
        with pytest.raises(falcon.HTTPUnauthorized):
            checker = JwtChecker(algorithm='HS256', secret='secret',
                                 audience='urn:foo')

            # Signature is good, but audience is 'wrong'
            bad_aud_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJUZXN0IEF1dGggU3lzdGVtIiwiaWF0IjoxNDc2NTU1NzIyLCJleHAiOjcyNTE0NDUzNjYsImF1ZCI6Indyb25nIiwic3ViIjoidGVzdF91c2VyIiwicm9sZSI6ImFkbWluIn0.3isrOoC_qtCoW13TCe-QhnMYb0z3gOd5VnxswLA_mFo'

            req = MagicMock(spec=falcon.Request)
            resp = MagicMock(spec=falcon.Response)
            resource = {}
            params = {}

            req.headers = {'AUTHORIZATION': 'Bearer ' + bad_aud_token}
            req.path = '/test'

            checker.process_resource(req, resp, resource, params)

    def test_raises_401_when_issuer_is_wrong(self):
        with pytest.raises(falcon.HTTPUnauthorized):
            checker = JwtChecker(algorithm='HS256', secret='secret',
                                 issuer='urn:foo')

            # Signature is good, but issuer is 'wrong'
            bad_iss_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ3cm9uZyIsImlhdCI6MTQ3NjU1NTcyMiwiZXhwIjo3MjUxNDQ1MzY2LCJhdWQiOiJmYWxjb24tand0LWNoZWNrZXIiLCJzdWIiOiJ0ZXN0X3VzZXIiLCJyb2xlIjoiYWRtaW4ifQ.1KRxaQcX9I_ua2DFkZCd3nsnbopiE8-mNMfRt99Jmhk'

            req = MagicMock(spec=falcon.Request)
            resp = MagicMock(spec=falcon.Response)
            resource = {}
            params = {}

            req.headers = {'AUTHORIZATION': 'Bearer ' + bad_iss_token}
            req.path = '/test'

            checker.process_resource(req, resp, resource, params)

    def test_optional_claims_may_be_omitted_from_checker(self):
        # No iss or aud claims present
        minimal_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NzY1NTU3MjIsImV4cCI6NzI1MTQ0NTM2Niwic3ViIjoidGVzdF91c2VyIiwicm9sZSI6ImFkbWluIn0.WuEQjLcBEt60suxcEMNLaYpN5PRxPhRUrmwqRvSDl-Y'

        checker = JwtChecker(algorithm='HS256', secret='secret')

        req = MagicMock(spec=falcon.Request)
        resp = MagicMock(spec=falcon.Response)
        resource = {}
        params = {}

        req.headers = {'AUTHORIZATION': 'Bearer ' + minimal_token}
        req.path = '/test'

        checker.process_resource(req, resp, resource, params)
