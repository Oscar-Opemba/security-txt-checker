import unittest

import app


class TestSecurityTxtDomainHardening(unittest.TestCase):
    def test_invalid_hostname_fallback_is_structured(self):
        result = app.analyze({'url': 'not a valid hostname'})
        self.assertIsInstance(result, dict)
        self.assertIn('error', result)


if __name__ == '__main__': unittest.main()
