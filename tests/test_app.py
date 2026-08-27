import unittest
from unittest.mock import patch
from app import analyze

class FakeResponse:
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, _limit): return b'Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z\n'

class TestSecurityTxt(unittest.TestCase):
    @patch('app.urlopen', return_value=FakeResponse())
    def test_valid_file(self, _urlopen):
        self.assertTrue(analyze({'url':'example.com'})['valid'])

if __name__ == '__main__': unittest.main()
