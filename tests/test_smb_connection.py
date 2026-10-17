import unittest
from unittest.mock import MagicMock, patch

from lib.ldap import get_machine_name

class GetMachineNameSocketCleanupTests(unittest.TestCase):

    def test_close_called_on_successful_login(self):
        with patch('lib.ldap.SMBConnection') as mock_smb:
            conn = MagicMock()
            conn.login.side_effect = None
            conn.getServerName.return_value = 'DC01'
            mock_smb.return_value = conn

            result = get_machine_name('10.0.0.1', 'lab.local')

        self.assertEqual(result, 'DC01')
        conn.close.assert_called_once()

    def test_close_called_on_unsuccessful_login(self):
        with patch('lib.ldap.SMBConnection') as mock_smb:
            conn = MagicMock()
            conn.login.side_effect = Exception('STATUS_ACCESS_DENIED')
            conn.getServerName.return_value = 'DC02'
            mock_smb.return_value = conn

            result = get_machine_name('10.0.0.1', 'lab.local')

        self.assertEqual(result, 'DC02')
        conn.close.assert_called_once()

    def test_close_called_on_successful_dns_fallback(self):
        with patch('lib.ldap.SMBConnection') as mock_smb, patch('socket.gethostbyaddr') as mock_gethostbyaddr:
            conn = MagicMock()
            conn.login.side_effect = Exception('STATUS_ACCESS_DENIED')
            conn.getServerName.return_value = ''
            mock_smb.return_value = conn
            mock_gethostbyaddr.return_value = ('dc03.lab.local', [], ['10.0.0.1'])
            
            result = get_machine_name('10.0.0.1', 'lab.local')

        self.assertEqual(result, 'DC03') 
        conn.close.assert_called_once()

