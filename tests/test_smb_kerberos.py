import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from lib.attacks.smb import SMB

class SmbKerberosTests(unittest.TestCase):

    def setUp(self):
        self.logs_dir = tempfile.mkdtemp()
        self.smb = SMB.__new__(SMB)
        self.smb.username = 'user'
        self.smb.password = ''
        self.smb.domain = 'DOM'
        self.smb.lmhash = ''
        self.smb.nthash = ''
        self.smb.hashes = None
        self.smb.dc_ip = '10.0.0.1'
        self.smb.kerberos = True
        self.smb.no_pass = True
        self.smb.logs_dir = self.logs_dir

    def tearDown(self):
        shutil.rmtree(self.logs_dir, ignore_errors=True)

    def test_smb_connection_passes_aes_key_to_kerberos_login(self):
        self.smb.aes = 'c67d8d0ea8ea9d38b0c8f1a3f4f9e6c8a1b2c3d4e5f60718293a4b5c6d7e8f90'
        conn = MagicMock()

        with patch('lib.attacks.smb.SMBConnection', return_value=conn):
            self.smb.smb_connection('10.0.0.5')

        conn.kerberosLogin.assert_called_once_with(
            user='user', password='', domain='DOM', kdcHost='10.0.0.1',
            aesKey='c67d8d0ea8ea9d38b0c8f1a3f4f9e6c8a1b2c3d4e5f60718293a4b5c6d7e8f90',
        )

    def test_smb_connection_passes_no_aes_key_when_aes_is_none(self):
        self.smb.aes = None
        conn = MagicMock()

        with patch('lib.attacks.smb.SMBConnection', return_value=conn):
            self.smb.smb_connection('10.0.0.5')

        conn.kerberosLogin.assert_called_once_with(
            user='user', password='', domain='DOM', kdcHost='10.0.0.1', aesKey=None,
        )

    def test_smb_spider_passes_aes_key_to_kerberos_login(self):
        self.smb.aes = 'c67d8d0ea8ea9d38b0c8f1a3f4f9e6c8a1b2c3d4e5f60718293a4b5c6d7e8f90'
        self.smb.save = False
        conn = MagicMock()
        conn.listPath.return_value = []

        with patch('lib.attacks.smb.SMBConnection', return_value=conn):
            self.smb.smb_spider(MagicMock(), ['10.0.0.5'])

        conn.kerberosLogin.assert_called_once_with(
            user='user', password='', domain='DOM', kdcHost='10.0.0.1',
            aesKey='c67d8d0ea8ea9d38b0c8f1a3f4f9e6c8a1b2c3d4e5f60718293a4b5c6d7e8f90',
        )

    def test_smb_spider_passes_no_aes_key_when_aes_is_none(self):
        self.smb.aes = None
        self.smb.save = False
        conn = MagicMock()
        conn.listPath.return_value = []

        with patch('lib.attacks.smb.SMBConnection', return_value=conn):
            self.smb.smb_spider(MagicMock(), ['10.0.0.5'])

        conn.kerberosLogin.assert_called_once_with(
            user='user', password='', domain='DOM', kdcHost='10.0.0.1', aesKey=None,
        )
