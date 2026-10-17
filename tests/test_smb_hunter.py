import unittest
from unittest.mock import MagicMock

from lib.attacks.smb import SMB

class SmbHunterTests(unittest.TestCase):

    def test_returns_safe_defaults_when_isSigningRequired_raises(self):
            smb = SMB.__new__(SMB)
            conn = MagicMock()
            conn.isSigningRequired.side_effect = Exception("connection dropped")

            result = smb.smb_hunter('somehost', conn)
            
            signing, site_code, sitesrv, distp, wsus, wdspxe, sccmpxe = result

            self.assertEqual(signing, None)

    def test_returns_safe_defaults_when_listShares_raises(self):
            smb = SMB.__new__(SMB)
            conn = MagicMock()
            conn.listShares.side_effect = Exception("listing shares failed")

            result = smb.smb_hunter('somehost', conn)
            
            signing, site_code, sitesrv, distp, wsus, wdspxe, sccmpxe = result

            self.assertEqual(result, (None, 'None', None, None, None, None, None))


    def test_returns_real_values_when_nothing_raises(self):
        smb = SMB.__new__(SMB)
        conn = MagicMock()
        conn.isSigningRequired.return_value = True
        conn.listShares.return_value = []

        result = smb.smb_hunter('somehost', conn)

        signing, site_code, siteserv, distp, wsus, wdspxe, sccmpxe = result
        self.assertEqual(result, (True, 'None', False, False, False, False, False))