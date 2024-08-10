import re
import unittest
from django.core.exceptions import ValidationError
from test_cases.validators import validate_input

class ValidateInputTestCase(unittest.TestCase):

    def test_sql_injection(self):
        sql_injection_strings = [
            "1; DROP TABLE users",
            "' OR '1'='1",
            "' UNION SELECT NULL, NULL, NULL--",
            "admin'--",
            "exec sp_executesql N'SELECT * FROM users WHERE name ='' OR ''='' "
        ]
        for test_str in sql_injection_strings:
            with self.assertRaises(ValidationError):
                validate_input(test_str)

    def test_xss(self):
        xss_strings = [
            "<script>alert('XSS')</script>",
            "<img src='x' onerror='alert(1)'>",
            "<body onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        for test_str in xss_strings:
            with self.assertRaises(ValidationError):
                validate_input(test_str)

if __name__ == '__main__':
    unittest.main()
