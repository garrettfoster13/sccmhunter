import shutil
import tempfile
import unittest

from lib.attacks.smb import SMB


class SmbHashesTests(unittest.TestCase):

    def setUp(self):
        self.logs_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.logs_dir, ignore_errors=True)

    def make_smb(self, hashes):
        return SMB(username='user', password='pass', domain='DOM', dc_ip='10.0.0.1',
                   hashes=hashes, logs_dir=self.logs_dir)

    def test_nt_only_hash_form_still_works(self):
        smb = self.make_smb(':32ed87bdb97fdc3a1dba1c5b0db7080b')

        self.assertEqual(smb.lmhash, '')
        self.assertEqual(smb.nthash, '32ed87bdb97fdc3a1dba1c5b0db7080b')

    def test_full_lm_nt_hash_form_works(self):
        smb = self.make_smb('aad3b435b51404eeaad3b435b51404ee:32ed87bdb97fdc3a1dba1c5b0db7080b')

        self.assertEqual(smb.lmhash, 'aad3b435b51404eeaad3b435b51404ee')
        self.assertEqual(smb.nthash, '32ed87bdb97fdc3a1dba1c5b0db7080b')

    def test_bare_hash_without_colon_exits_cleanly_with_format_error(self):
        with self.assertLogs('lib.logger', level='INFO') as logs:
            with self.assertRaises(SystemExit) as ctx:
                self.make_smb('32ed87bdb97fdc3a1dba1c5b0db7080b')

        self.assertEqual(ctx.exception.code, 1)
        output = '\n'.join(logs.output)
        self.assertIn('Invalid -hashes format', output)
        self.assertIn('LMHASH:NTHASH', output)

    def test_hash_with_two_colons_exits_cleanly_with_format_error(self):
        with self.assertLogs('lib.logger', level='INFO') as logs:
            with self.assertRaises(SystemExit) as ctx:
                self.make_smb('aad3b435b51404eeaad3b435b51404ee:32ed87bdb97fdc3a1dba1c5b0db7080b:extra')

        self.assertEqual(ctx.exception.code, 1)
        output = '\n'.join(logs.output)
        self.assertIn('Invalid -hashes format', output)
        self.assertIn('LMHASH:NTHASH', output)

    def test_init_no_longer_accepts_ldaps_option(self):
        #The smb command does no LDAP, so the dead -ldaps option was removed;
        #passing it must now fail loudly instead of being silently ignored.
        with self.assertRaises(TypeError):
            SMB(username='user', password='pass', domain='DOM', dc_ip='10.0.0.1',
                ldaps=True, logs_dir=self.logs_dir)


if __name__ == '__main__':
    unittest.main()
