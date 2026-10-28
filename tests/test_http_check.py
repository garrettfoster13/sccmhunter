import unittest
from unittest.mock import MagicMock, patch

from requests.exceptions import ConnectionError, Timeout

from lib.attacks.smb import HTTP_TIMEOUT, SMB

class HttpCheckTests(unittest.TestCase):

    def test_returns_true_when_http_probe_fails_but_https_probe_returns_401(self):
        smb = SMB.__new__(SMB)

        def request_side_effect(method, endpoint, verify=False, timeout=None):
            if endpoint.startswith("http://"):
                raise ConnectionError("connection refused")
            response = MagicMock()
            response.status_code = 401
            return response

        with patch('lib.attacks.smb.requests.request', side_effect=request_side_effect):
            result = smb.http_check('somehost')

        self.assertTrue(result)

    def test_returns_false_when_all_probes_raise_connection_errors(self):
        smb = SMB.__new__(SMB)

        with patch('lib.attacks.smb.requests.request', side_effect=ConnectionError("connection refused")):
            result = smb.http_check('somehost')

        self.assertFalse(result)

    def test_returns_true_when_altauth_returns_403(self):
        smb = SMB.__new__(SMB)

        def request_side_effect(method, endpoint, verify=False, timeout=None):
            response = MagicMock()
            response.status_code = 403 if endpoint == f"https://somehost/ccm_system_altauth/" else 500
            return response

        with patch('lib.attacks.smb.requests.request', side_effect=request_side_effect):
            result = smb.http_check('somehost')

        self.assertTrue(result)

    def test_returns_true_when_ccm_post_returns_200(self):
        smb = SMB.__new__(SMB)

        def request_side_effect(method, endpoint, verify=False, timeout=None):
            response = MagicMock()
            response.status_code = 200 if (method == "CCM_POST" and endpoint == f"https://somehost/ccm_system_altauth/request") else 500
            return response

        with patch('lib.attacks.smb.requests.request', side_effect=request_side_effect):
            result = smb.http_check('somehost')

        self.assertTrue(result)

    def test_returns_false_when_probes_succeed_but_do_not_indicate_mp(self):
        smb = SMB.__new__(SMB)

        response = MagicMock()
        response.status_code = 404
        with patch('lib.attacks.smb.requests.request', return_value=response):
            result = smb.http_check('somehost')

        self.assertFalse(result)

    def test_every_probe_is_called_with_timeout(self):
        smb = SMB.__new__(SMB)

        response = MagicMock()
        response.status_code = 404
        with patch('lib.attacks.smb.requests.request', return_value=response) as mock_request:
            smb.http_check('somehost')

        self.assertEqual(mock_request.call_count, 4)
        for call in mock_request.call_args_list:
            self.assertIn('timeout', call.kwargs)
            self.assertEqual(call.kwargs['timeout'], HTTP_TIMEOUT)

    def test_returns_false_when_all_probes_time_out(self):
        smb = SMB.__new__(SMB)

        with patch('lib.attacks.smb.requests.request', side_effect=Timeout("timed out")):
            result = smb.http_check('somehost')

        self.assertFalse(result)

    def test_timeout_on_one_probe_does_not_abort_remaining_probes(self):
        smb = SMB.__new__(SMB)

        def request_side_effect(method, endpoint, verify=False, timeout=None):
            if endpoint == f"https://somehost/ccm_system_windowsauth/":
                raise Timeout("timed out")
            response = MagicMock()
            response.status_code = 403 if endpoint == f"https://somehost/ccm_system_altauth/" else 500
            return response

        with patch('lib.attacks.smb.requests.request', side_effect=request_side_effect) as mock_request:
            result = smb.http_check('somehost')

        self.assertTrue(result)
        called_endpoints = [call.args[1] for call in mock_request.call_args_list]
        self.assertEqual(mock_request.call_count, 3)
        self.assertIn("https://somehost/ccm_system_altauth/", called_endpoints)
