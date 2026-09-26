import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
from pyasn1.codec.der.encoder import encode
from pyasn1.type import univ
from pyasn1_modules import rfc5652, rfc5280

from lib.scripts.sccmwtf import (
    SCCMTools,
    RSA_OAEP_OID,
    RSA_PKCS1V15_OID,
    AES_256_CBC_OID,
    AES_128_CBC_OID,
    DES_EDE3_CBC_OID,
)


def _oaep():
    return rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)


def build_encrypted_policy(recipient_public_key, kt_algorithm_oid, kt_padding,
                           content_encryption_oid, symmetric_key, iv, plaintext_utf16,
                           block_bits=None):
    """Build a DER-encoded CMS ContentInfo/EnvelopedData blob shaped like a real
    SCCM MP policy response, so parseEncryptedPolicy is exercised against
    realistic ASN.1 structures rather than mocks. Content is PKCS7-padded
    before encryption, matching the real CMS wire format."""
    if block_bits is None:
        block_bits = 64 if content_encryption_oid == DES_EDE3_CBC_OID else 128

    padder = sym_padding.PKCS7(block_bits).padder()
    padded = padder.update(plaintext_utf16) + padder.finalize()

    if content_encryption_oid == DES_EDE3_CBC_OID:
        cipher = Cipher(TripleDES(symmetric_key), modes.CBC(iv))
    else:
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    encrypted_key = recipient_public_key.encrypt(symmetric_key, kt_padding)

    issuer_serial = rfc5652.IssuerAndSerialNumber()
    issuer_serial.setComponentByName('issuer', rfc5280.Name().setComponentByPosition(0, rfc5280.RDNSequence()))
    issuer_serial.setComponentByName('serialNumber', 1)

    rid = rfc5652.RecipientIdentifier()
    rid.setComponentByName('issuerAndSerialNumber', issuer_serial)

    kt_alg = rfc5652.KeyEncryptionAlgorithmIdentifier()
    kt_alg.setComponentByName('algorithm', univ.ObjectIdentifier(kt_algorithm_oid))

    ktri = rfc5652.KeyTransRecipientInfo()
    ktri.setComponentByName('version', 0)
    ktri.setComponentByName('rid', rid)
    ktri.setComponentByName('keyEncryptionAlgorithm', kt_alg)
    ktri.setComponentByName('encryptedKey', encrypted_key)

    recipient_info = rfc5652.RecipientInfo()
    recipient_info.setComponentByName('ktri', ktri)

    recipient_infos = rfc5652.RecipientInfos()
    recipient_infos.setComponentByPosition(0, recipient_info)

    # parseEncryptedPolicy strips the 2-byte DER tag+length header off the
    # parameters field to get the raw IV, so wrap it the same way here.
    content_enc_alg = rfc5652.ContentEncryptionAlgorithmIdentifier()
    content_enc_alg.setComponentByName('algorithm', univ.ObjectIdentifier(content_encryption_oid))
    content_enc_alg.setComponentByName('parameters', univ.Any(encode(univ.OctetString(iv))))

    enc_content_info = rfc5652.EncryptedContentInfo()
    enc_content_info.setComponentByName('contentType', rfc5652.id_data)
    enc_content_info.setComponentByName('contentEncryptionAlgorithm', content_enc_alg)
    enc_content_info.setComponentByName('encryptedContent', ciphertext)

    enveloped_data = rfc5652.EnvelopedData()
    enveloped_data.setComponentByName('version', 0)
    enveloped_data.setComponentByName('recipientInfos', recipient_infos)
    enveloped_data.setComponentByName('encryptedContentInfo', enc_content_info)

    content_info = rfc5652.ContentInfo()
    content_info.setComponentByName('contentType', rfc5652.id_envelopedData)
    content_info.setComponentByName('content', univ.Any(encode(enveloped_data)))

    return encode(content_info)


class ParseEncryptedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.tools = SCCMTools.__new__(SCCMTools)
        self.tools.key = self.key
        # Deliberately NOT block-aligned, so a real round-trip must actually
        # add and then strip PKCS7 padding to come back byte-for-byte.
        self.plaintext = "<Policy>secret naa creds</Policy>".encode('utf-16')

    def _assert_roundtrip(self, kt_oid, kt_padding, content_oid, key_size):
        symmetric_key = b"\x11" * key_size
        iv = b"\x22" * 16 if content_oid != DES_EDE3_CBC_OID else b"\x22" * 8
        blob = build_encrypted_policy(
            self.key.public_key(), kt_oid, kt_padding, content_oid,
            symmetric_key, iv, self.plaintext,
        )
        result = self.tools.parseEncryptedPolicy(blob)
        self.assertEqual(result, self.plaintext.decode('utf-16'))

    def test_legacy_pkcs1v15_and_3des(self):
        self._assert_roundtrip(RSA_PKCS1V15_OID, rsa_padding.PKCS1v15(), DES_EDE3_CBC_OID, 24)

    def test_modern_oaep_and_aes256(self):
        self._assert_roundtrip(RSA_OAEP_OID, _oaep(), AES_256_CBC_OID, 32)

    def test_modern_oaep_and_aes128(self):
        self._assert_roundtrip(RSA_OAEP_OID, _oaep(), AES_128_CBC_OID, 16)

    def test_rejects_unknown_key_transport_algorithm(self):
        blob = build_encrypted_policy(
            self.key.public_key(), "1.2.3.4.5.6", rsa_padding.PKCS1v15(),
            AES_256_CBC_OID, b"\x11" * 32, b"\x22" * 16, self.plaintext,
        )
        with self.assertRaises(ValueError):
            self.tools.parseEncryptedPolicy(blob)

    def test_rejects_unknown_content_encryption_algorithm(self):
        blob = build_encrypted_policy(
            self.key.public_key(), RSA_OAEP_OID, _oaep(),
            "1.2.3.4.5.6", b"\x11" * 32, b"\x22" * 16, self.plaintext,
            block_bits=128,
        )
        with self.assertRaises(ValueError):
            self.tools.parseEncryptedPolicy(blob)


if __name__ == "__main__":
    unittest.main()
