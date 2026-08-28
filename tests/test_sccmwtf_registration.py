import unittest
from unittest.mock import Mock, patch

from lib.scripts.sccmwtf import SCCMTools


SMSID = "4E84FAEF-B5D5-474F-8C0C-0026DAB8C514"


def registration_response(status, include_smsid=False):
    smsid = f' SMSID="GUID:{SMSID}"' if include_smsid else ""
    token = ' PreAuthToken="token"' if status == 0 else ""
    return (
        f'<ClientRegistrationResponse ResponseType="Confirmation"{smsid} '
        f'Status="{status}"{token} />'
    )


class RegistrationConfirmationTests(unittest.TestCase):
    def setUp(self):
        self.tools = SCCMTools(
            target_name="relay",
            target_fqdn="relay",
            target_sccm="mp.example.test",
            target_username="",
            target_password="",
            sleep=5,
            logs_dir="/tmp",
        )
        self.tools.cert = Mock()
        self.tools.cert.public_bytes.return_value = b"certificate"
        self.tools.key = object()

    @patch("lib.scripts.sccmwtf.time.sleep")
    @patch("lib.scripts.sccmwtf.CryptoTools.sign", return_value=b"signature")
    def test_pending_registration_polls_until_status_zero(self, _sign, sleep):
        self.tools.sendCCMPostRequest = Mock(
            return_value=registration_response(1, include_smsid=True)
        )
        self.tools.sendConfirmationRequest = Mock(
            side_effect=[registration_response(1), registration_response(0)]
        )

        result = self.tools.sendRegistration("relay", "relay", "", "")

        self.assertEqual(SMSID, result)
        self.assertEqual(2, self.tools.sendConfirmationRequest.call_count)
        self.assertEqual(2, sleep.call_count)
        message_ids = {
            call.args[2] for call in self.tools.sendConfirmationRequest.call_args_list
        }
        self.assertEqual(1, len(message_ids))

    @patch("lib.scripts.sccmwtf.time.sleep")
    @patch("lib.scripts.sccmwtf.CryptoTools.sign", return_value=b"signature")
    def test_reset_status_is_not_treated_as_success(self, _sign, sleep):
        self.tools.sendCCMPostRequest = Mock(
            return_value=registration_response(2, include_smsid=True)
        )
        self.tools.sendConfirmationRequest = Mock()

        with self.assertRaisesRegex(RuntimeError, "Reset"):
            self.tools.sendRegistration("relay", "relay", "", "")

        sleep.assert_not_called()
        self.tools.sendConfirmationRequest.assert_not_called()

    @patch("lib.scripts.sccmwtf.time.sleep")
    @patch("lib.scripts.sccmwtf.CryptoTools.sign", return_value=b"signature")
    def test_pending_registration_times_out_instead_of_sending_ddr(self, _sign, sleep):
        pending = registration_response(1)
        self.tools.sendCCMPostRequest = Mock(
            return_value=registration_response(1, include_smsid=True)
        )
        self.tools.sendConfirmationRequest = Mock(return_value=pending)

        with self.assertRaisesRegex(TimeoutError, "still pending"):
            self.tools.sendRegistration("relay", "relay", "", "")

        self.assertEqual(5, self.tools.sendConfirmationRequest.call_count)
        self.assertEqual(5, sleep.call_count)


if __name__ == "__main__":
    unittest.main()
