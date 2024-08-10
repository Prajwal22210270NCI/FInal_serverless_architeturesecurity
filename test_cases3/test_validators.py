# test_cases3/test_validators.py

import re
import unittest
from django.core.exceptions import ValidationError
from test_cases.test_validators import validate_custom_field

class ValidateCustomFieldTestCase(unittest.TestCase):

    def test_custom_field_valid(self):
        valid_custom_fields = [
            "valid_field",
            "ValidField123",
            "another_valid_field_456"
        ]
        for test_str in valid_custom_fields:
            try:
                validate_custom_field(test_str)
            except ValidationError:
                self.fail(f"ValidationError raised for valid input: {test_str}")

    def test_custom_field_invalid(self):
        invalid_custom_fields = [
            "invalid field with spaces",
            "invalid-field-with-hyphens",
            "invalid*field*with*asterisks",
            "invalid#field#with#hashes",
            "invalid&field&with&amps"
        ]
        for test_str in invalid_custom_fields:
            with self.assertRaises(ValidationError):
                validate_custom_field(test_str)

if __name__ == '__main__':
    unittest.main()
