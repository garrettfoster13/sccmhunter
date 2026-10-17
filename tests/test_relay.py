import unittest
from unittest.mock import MagicMock, patch

import lib.attacks.relay as relay
from lib.attacks.relay import SCCMHTTPSRelayClient
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED


class SendAuthTests(unittest.TestCase):

    def setUp(self):
        relay.SUCCESS = False
        relay.ELEVATED.clear()

    def _make_client(self, status, body=b'{}'):
        # Bypasses the real __init__ (needs a full impacket relay-server setup) --
        # same trick the existing tests/test_add_computer_to_db.py already uses
        # (SCCMHUNTER.__new__(SCCMHUNTER)), just manually setting what _sendAuth needs.
        client = SCCMHTTPSRelayClient.__new__(SCCMHTTPSRelayClient)
        res = MagicMock()
        res.status = status
        res.read.return_value = body
        client.session = MagicMock()
        client.session.getresponse.return_value = res
        client.path = '/AdminService/wmi/SMS_Admin'
        client.SCCM_relay = MagicMock()
        client.SCCM_relay.target_user = 'testuser'
        client.SCCM_relay.target_sid = '0xDEADBEEF'
        return client

    @patch('lib.attacks.relay.NTLMAuthChallengeResponse')
    def test_already_elevated_sets_success_and_returns_success_tuple(self, mock_ntlm_response):
        # _sendAuth parses a real NTLM AUTHENTICATE message to pull out domain/username.
        # Mocking the parser itself avoids needing to construct a byte-perfect real one.
        mock_ntlm_response.return_value.__getitem__.side_effect = {
            'domain_name': 'DOMAIN'.encode('utf-16le'),
            'user_name': 'attacker'.encode('utf-16le'),
        }.__getitem__

        relay.ELEVATED.append('DOMAIN\\attacker')
        client = self._make_client(status=201)
        result = client._sendAuth(b'\x00fake-token')

        self.assertEqual(result, (None, STATUS_SUCCESS))
        self.assertFalse(relay.SUCCESS)

    @patch('lib.attacks.relay.NTLMAuthChallengeResponse')
    def test_201_sets_success_and_returns_success_tuple(self, mock_ntlm_response):
        # _sendAuth parses a real NTLM AUTHENTICATE message to pull out domain/username.
        # Mocking the parser itself avoids needing to construct a byte-perfect real one.
        mock_ntlm_response.return_value.__getitem__.side_effect = {
            'domain_name': 'DOMAIN'.encode('utf-16le'),
            'user_name': 'attacker'.encode('utf-16le'),
        }.__getitem__

        client = self._make_client(status=201)
        result = client._sendAuth(b'\x00fake-token')

        self.assertEqual(result, ('{}', STATUS_SUCCESS))
        self.assertTrue(relay.SUCCESS)

    @patch('lib.attacks.relay.NTLMAuthChallengeResponse')
    def test_401_returns_unsuccessful_tuple(self, mock_ntlm_response):
        mock_ntlm_response.return_value.__getitem__.side_effect = {
            'domain_name': 'DOMAIN'.encode('utf-16le'),
            'user_name': 'attacker'.encode('utf-16le'),
        }.__getitem__

        client = self._make_client(status=401)
        result = client._sendAuth(b'\x00fake-token')

        self.assertEqual(result, (None, STATUS_ACCESS_DENIED))
        self.assertFalse(relay.SUCCESS)

    @patch('lib.attacks.relay.NTLMAuthChallengeResponse')
    def test_unexpected_status_code_returns_unsuccessful_tuple(self, mock_ntlm_response):
        mock_ntlm_response.return_value.__getitem__.side_effect = {
            'domain_name': 'DOMAIN'.encode('utf-16le'),
            'user_name': 'attacker'.encode('utf-16le'),
        }.__getitem__

        client = self._make_client(status=500)
        result = client._sendAuth(b'\x00fake-token')

        self.assertEqual(result, (None, STATUS_ACCESS_DENIED))
        self.assertFalse(relay.SUCCESS)
    
    @patch('lib.attacks.relay.NTLMAuthChallengeResponse')
    def test_exception_returns_unsuccessful_tuple(self, mock_ntlm_response):
        mock_ntlm_response.return_value.__getitem__.side_effect = {
            'domain_name': 'DOMAIN'.encode('utf-16le'),
            'user_name': 'attacker'.encode('utf-16le'),
        }.__getitem__

        client = self._make_client(status=200) # status irrelevant here since its never reached
        client.session.request.side_effect = Exception("connection reset")
        result = client._sendAuth(b'\x00fake-token')

        self.assertEqual(result, (None, STATUS_ACCESS_DENIED))
        self.assertFalse(relay.SUCCESS)
    