import unittest
from unittest.mock import MagicMock, patch

from requests.exceptions import ConnectionError, Timeout

from lib.attacks.smb import HTTP_TIMEOUT, SMB

class ProviderCheckTests(unittest.TestCase):

    def test_returns_true_when_provider_returns_401(self):
        smb = SMB.__new__(SMB)

        response = MagicMock()
        response.status_code = 401
        with patch('lib.attacks.smb.requests.request', return_value=response) as mock_request:
            result = smb.provider_check('somehost')

        self.assertTrue(result)
        mock_request.assert_called_once_with("GET",
                                             "https://somehost/adminservice/wmi/",
                                             verify=False,
                                             timeout=HTTP_TIMEOUT)

    def test_returns_false_when_provider_returns_other_status(self):
        smb = SMB.__new__(SMB)

        response = MagicMock()
        response.status_code = 200
        with patch('lib.attacks.smb.requests.request', return_value=response):
            result = smb.provider_check('somehost')

        self.assertFalse(result)

    def test_returns_false_when_provider_request_times_out(self):
        smb = SMB.__new__(SMB)

        with patch('lib.attacks.smb.requests.request', side_effect=Timeout("timed out")) as mock_request:
            result = smb.provider_check('somehost')

        self.assertFalse(result)
        self.assertEqual(mock_request.call_args.kwargs['timeout'], HTTP_TIMEOUT)

    def test_returns_false_when_provider_request_raises_connection_error(self):
        smb = SMB.__new__(SMB)

        with patch('lib.attacks.smb.requests.request', side_effect=ConnectionError("connection refused")):
            result = smb.provider_check('somehost')

        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()
