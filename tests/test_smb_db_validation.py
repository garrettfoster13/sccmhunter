import os
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from lib.attacks.smb import SMB

REQUIRED_TABLES = ['SiteServers', 'ManagementPoints', 'PXEDistributionPoints', 'Computers', 'CAS']

class SmbDbValidationTests(unittest.TestCase):

    def setUp(self):
        self.logs_dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.logs_dir, 'db'))
        self.database = os.path.join(self.logs_dir, 'db', 'find.db')

    def tearDown(self):
        shutil.rmtree(self.logs_dir, ignore_errors=True)

    def make_smb(self):
        smb = SMB.__new__(SMB)
        smb.logs_dir = self.logs_dir
        smb.database = self.database
        if os.path.exists(self.database):
            smb.conn = sqlite3.connect(self.database, check_same_thread=False)
        else:
            smb.conn = None
        return smb

    def create_db(self, tables=REQUIRED_TABLES):
        conn = sqlite3.connect(self.database)
        for table in tables:
            conn.execute(f'CREATE TABLE {table} (Hostname)')
        conn.commit()
        conn.close()

    def test_missing_database_stops_cleanly_and_leaves_no_file(self):
        smb = self.make_smb()
        self.assertIsNone(smb.conn)

        with patch.object(SMB, 'check_siteservers') as mock_ss, \
             patch.object(SMB, 'check_managementpoints') as mock_mp, \
             patch.object(SMB, 'check_distributionpoints') as mock_dp, \
             patch.object(SMB, 'check_computers') as mock_pc, \
             self.assertLogs('lib.logger', level='INFO') as logs:
            smb.run()

        for check in (mock_ss, mock_mp, mock_dp, mock_pc):
            check.assert_not_called()
        output = '\n'.join(logs.output)
        self.assertIn('No find.db found', output)
        self.assertIn('Run the find module first', output)
        self.assertFalse(os.path.exists(self.database))

    def test_init_does_not_create_empty_database(self):
        SMB(username='user', password='pass', domain='DOM', dc_ip='10.0.0.1',
            logs_dir=self.logs_dir)

        self.assertFalse(os.path.exists(self.database))

    def test_init_connects_on_existing_database(self):
        self.create_db()
        smb = SMB(username='user', password='pass', domain='DOM', dc_ip='10.0.0.1',
                  logs_dir=self.logs_dir)

        self.assertIsNotNone(smb.conn)
        smb.conn.close()

    def test_missing_table_stops_cleanly_and_names_it(self):
        self.create_db(tables=['SiteServers', 'ManagementPoints', 'PXEDistributionPoints', 'CAS'])
        smb = self.make_smb()

        with patch.object(SMB, 'check_siteservers') as mock_ss, \
             patch.object(SMB, 'check_managementpoints') as mock_mp, \
             patch.object(SMB, 'check_distributionpoints') as mock_dp, \
             patch.object(SMB, 'check_computers') as mock_pc, \
             self.assertLogs('lib.logger', level='INFO') as logs:
            smb.run()

        for check in (mock_ss, mock_mp, mock_dp, mock_pc):
            check.assert_not_called()
        output = '\n'.join(logs.output)
        self.assertIn('Computers', output)
        self.assertIn('Run the find module first', output)
        #the pre-existing database must not be deleted
        self.assertTrue(os.path.exists(self.database))

    def test_valid_database_proceeds_with_profiling(self):
        self.create_db()
        smb = self.make_smb()

        with patch.object(SMB, 'check_siteservers') as mock_ss, \
             patch.object(SMB, 'check_managementpoints') as mock_mp, \
             patch.object(SMB, 'check_distributionpoints') as mock_dp, \
             patch.object(SMB, 'check_computers') as mock_pc:
            smb.run()

        mock_ss.assert_called_once()
        mock_mp.assert_called_once()
        mock_dp.assert_called_once()
        mock_pc.assert_called_once()

if __name__ == '__main__':
    unittest.main()
