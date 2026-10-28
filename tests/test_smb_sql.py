import os
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from lib.attacks.smb import SMB

class SmbSqlTests(unittest.TestCase):

    def setUp(self):
        self.logs_dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.logs_dir, 'db'))
        self.database = os.path.join(self.logs_dir, 'db', 'find.db')
        self.conn = sqlite3.connect(self.database, check_same_thread=False)
        #schema mirrors lib/attacks/find.py so the real queries run unchanged
        self.conn.execute('''CREATE TABLE ManagementPoints(Hostname, SiteCode, SigningStatus)''')
        self.conn.execute('''CREATE TABLE Computers(Hostname, SiteCode, SigningStatus, SiteServer, ManagementPoint, DistributionPoint, SMSProvider, WSUS, MSSQL)''')
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.logs_dir, ignore_errors=True)

    def make_smb(self):
        smb = SMB.__new__(SMB)
        smb.logs_dir = self.logs_dir
        smb.database = self.database
        smb.conn = self.conn
        return smb

    def add_computer(self, hostname):
        self.conn.execute('INSERT INTO Computers (Hostname) VALUES (?)', (hostname,))
        self.conn.commit()

    def add_management_point(self, hostname, site_code):
        self.conn.execute('INSERT INTO ManagementPoints (Hostname, SiteCode) VALUES (?, ?)', (hostname, site_code))
        self.conn.commit()

    def run_check_computers(self, site_code_from_smb='None'):
        smb = self.make_smb()
        with patch.object(SMB, 'smb_connection', return_value=MagicMock()), \
             patch.object(SMB, 'mssql_check', return_value='False'), \
             patch.object(SMB, 'http_check', return_value='False'), \
             patch.object(SMB, 'provider_check', return_value='False'), \
             patch.object(SMB, 'smb_hunter', return_value=(True, site_code_from_smb, None, None, None, None, None)), \
             self.assertLogs('lib.logger', level='INFO'):
            smb.check_computers()

    def computers_site_code(self, hostname):
        cursor = self.conn.execute('SELECT SiteCode FROM Computers WHERE Hostname = ?', (hostname,))
        row = cursor.fetchone()
        cursor.close()
        return row[0] if row else None

    def test_site_code_fallback_survives_quote_in_hostname(self):
        #a quote-bearing hostname must not break the fallback query
        self.add_computer("host'--")
        self.add_management_point("host'--", 'LAB')

        self.run_check_computers()

        self.assertEqual(self.computers_site_code("host'--"), 'LAB')

    def test_site_code_fallback_survives_apostrophe_in_hostname(self):
        self.add_computer("O'Brien")
        self.add_management_point("O'Brien", 'XYZ')

        self.run_check_computers()

        self.assertEqual(self.computers_site_code("O'Brien"), 'XYZ')

    def test_hostname_not_in_management_points_leaves_site_code_none(self):
        self.add_computer("host'--")
        #no ManagementPoints row for this hostname
        self.add_management_point('otherhost', 'LAB')

        self.run_check_computers()

        self.assertEqual(self.computers_site_code("host'--"), 'None')

    def test_hostname_in_management_points_sets_site_code(self):
        self.add_computer('mp01')
        self.add_management_point('mp01', 'ABC')

        self.run_check_computers()

        self.assertEqual(self.computers_site_code('mp01'), 'ABC')

    def test_site_code_from_smb_hunter_skips_fallback(self):
        #when smb_hunter already resolved a site code, it is written as-is
        self.add_computer('mp01')
        self.add_management_point('mp01', 'ABC')

        self.run_check_computers(site_code_from_smb='ZZZ')

        self.assertEqual(self.computers_site_code('mp01'), 'ZZZ')

    def test_profiling_updates_computer_row(self):
        #the bound-parameter UPDATE still records the other profile fields
        self.add_computer("host'--")
        self.add_management_point("host'--", 'LAB')

        self.run_check_computers()

        cursor = self.conn.execute('SELECT SigningStatus, MSSQL FROM Computers WHERE Hostname = ?', ("host'--",))
        row = cursor.fetchone()
        cursor.close()
        self.assertEqual(row, ('True', 'False'))

if __name__ == '__main__':
    unittest.main()
