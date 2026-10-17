import unittest
import argparse
from lib.parsers.parsers import PARSERS

class DoDecryptParsersTests(unittest.TestCase):

    def test_do_decrypt_parsers(self):
        parsers = PARSERS.do_decrypt_parsers()
        result = parsers.parse_args(['some_test_blob'])

        self.assertEqual(result.blob, 'some_test_blob')
        self.assertIsInstance(parsers, argparse.ArgumentParser)
