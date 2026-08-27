import unittest
from unittest.mock import patch
from app import analyze

class Response:
    status = 200
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, _limit): return b'Contact: not-a-uri\n'

class TestSecurityTxtEdgeCases(unittest.TestCase):
    @patch('app.open_no_redirect', return_value=Response())
    @patch('security_utils.assert_public_resolution')
    def test_rejects_missing_expiry_and_bad_contact(self, _resolve, _open):
        result = analyze({'url':'example.com'})
        self.assertFalse(result['valid'])
        self.assertTrue(result['errors'])

if __name__ == '__main__': unittest.main()
