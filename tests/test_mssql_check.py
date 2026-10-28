import socket
import unittest
from unittest.mock import MagicMock, patch

from lib.attacks.smb import SMB

class MssqlCheckSocketCleanupTests(unittest.TestCase):

    def make_smb(self):
        return SMB.__new__(SMB)

    def test_returns_true_and_closes_socket_on_successful_connect(self):
        smb = self.make_smb()
        with patch('lib.attacks.smb.socket.socket') as mock_socket:
            sock = MagicMock()
            sock.connect.return_value = None
            mock_socket.return_value = sock

            result = smb.mssql_check('DB01.lab.local')

        self.assertTrue(result)
        mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect.assert_called_once_with(('DB01.lab.local', 1433))
        sock.close.assert_called_once()

    def test_returns_false_and_closes_socket_on_connection_refused(self):
        smb = self.make_smb()
        with patch('lib.attacks.smb.socket.socket') as mock_socket, \
             self.assertLogs('lib.logger', level='DEBUG') as logs:
            sock = MagicMock()
            sock.connect.side_effect = ConnectionRefusedError('[Errno 61] Connection refused')
            mock_socket.return_value = sock

            result = smb.mssql_check('10.0.0.5')

        self.assertFalse(result)
        sock.close.assert_called_once()

    def test_returns_false_and_closes_socket_on_timeout(self):
        smb = self.make_smb()
        with patch('lib.attacks.smb.socket.socket') as mock_socket, \
             self.assertLogs('lib.logger', level='DEBUG'):
            sock = MagicMock()
            sock.connect.side_effect = socket.timeout('timed out')
            mock_socket.return_value = sock

            result = smb.mssql_check('10.0.0.6')

        self.assertFalse(result)
        sock.settimeout.assert_called_once_with(2)
        sock.close.assert_called_once()

if __name__ == '__main__':
    unittest.main()
