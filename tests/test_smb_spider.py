import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, call, mock_open, patch

from lib.attacks.smb import SMB

class FakeSmbFile:
    def __init__(self, name):
        self.name = name

    def get_longname(self):
        return self.name

class SmbSpiderTests(unittest.TestCase):

    def setUp(self):
        self.logs_dir = tempfile.mkdtemp()
        self.loot_dir = os.path.join(self.logs_dir, 'loot')
        self.smb = SMB.__new__(SMB)
        self.smb.username = 'user'
        self.smb.password = 'pass'
        self.smb.domain = 'DOM'
        self.smb.lmhash = ''
        self.smb.nthash = ''
        self.smb.dc_ip = '10.0.0.1'
        self.smb.kerberos = False
        self.smb.save = True
        self.smb.logs_dir = self.logs_dir

    def tearDown(self):
        shutil.rmtree(self.logs_dir, ignore_errors=True)

    def make_conn(self, file_names, get_file=None):
        conn = MagicMock()
        conn.listPath.return_value = [FakeSmbFile(name) for name in file_names]
        if get_file is not None:
            conn.getFile.side_effect = get_file
        return conn

    def test_downloads_land_directly_in_logs_dir_loot(self):
        conn = self.make_conn(['test1.var'])
        new_conn = MagicMock()
        new_conn.listPath.return_value = conn.listPath.return_value

        with patch('lib.attacks.smb.SMBConnection', return_value=new_conn) as smb_conn_mock, \
             patch('os.makedirs') as makedirs_mock, \
             patch('builtins.open', mock_open()) as open_mock:
            self.smb.smb_spider(MagicMock(), ['10.0.0.5'])

        smb_conn_mock.assert_called_once_with('10.0.0.5', '10.0.0.5', None, timeout=2)
        makedirs_mock.assert_called_once_with(self.loot_dir, exist_ok=True)
        self.assertEqual(
            open_mock.call_args_list[0],
            call(os.path.join(self.loot_dir, 'test1.var'), 'wb'),
        )
        new_conn.getFile.assert_called_once_with(
            shareName='REMINST',
            pathName='SMSTemp//test1.var',
            callback=open_mock.return_value.__enter__.return_value.write,
        )

    def test_failed_download_is_removed_and_does_not_abort_remaining_downloads(self):
        def get_file(shareName, pathName, callback):
            if 'test1.var' in pathName:
                raise Exception('STATUS_ACCESS_DENIED')
            callback(b'variables-data')

        conn = self.make_conn(['test1.var', 'test2.var'], get_file=get_file)

        with patch('lib.attacks.smb.SMBConnection', return_value=conn):
            self.smb.smb_spider(MagicMock(), ['10.0.0.5'])

        self.assertEqual(conn.getFile.call_count, 2)
        # failed download leaves no empty file behind
        self.assertFalse(os.path.exists(os.path.join(self.loot_dir, 'test1.var')))
        # remaining download still succeeded and landed in loot
        with open(os.path.join(self.loot_dir, 'test2.var'), 'rb') as fh:
            self.assertEqual(fh.read(), b'variables-data')

    def test_no_files_written_to_cwd_and_no_os_replace(self):
        def get_file(shareName, pathName, callback):
            callback(b'variables-data')

        conn = self.make_conn(['test1.var', 'test2.var'], get_file=get_file)
        cwd_before = set(os.listdir(os.getcwd()))

        with patch('lib.attacks.smb.SMBConnection', return_value=conn), \
             patch('os.replace') as replace_mock:
            try:
                self.smb.smb_spider(MagicMock(), ['10.0.0.5'])
            finally:
                cwd_after = set(os.listdir(os.getcwd()))
                stray = cwd_after - cwd_before

        replace_mock.assert_not_called()
        self.assertEqual(stray, set())
        self.assertTrue(os.path.exists(os.path.join(self.loot_dir, 'test1.var')))
        self.assertTrue(os.path.exists(os.path.join(self.loot_dir, 'test2.var')))

    def test_no_empty_loot_dir_left_when_save_is_false(self):
        self.smb.save = False
        conn = self.make_conn(['test1.var'])

        with patch('lib.attacks.smb.SMBConnection', return_value=conn), \
             patch('os.makedirs') as makedirs_mock:
            self.smb.smb_spider(MagicMock(), ['10.0.0.5'])

        makedirs_mock.assert_not_called()
        self.assertFalse(os.path.exists(self.loot_dir))

