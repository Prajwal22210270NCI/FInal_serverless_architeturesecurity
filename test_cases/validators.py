import re
from django.core.exceptions import ValidationError

def validate_input(data):
    if not isinstance(data, str):
        raise ValidationError("Invalid input: input must be a string")

    # Check for SQL Injection patterns
    sql_injection_patterns = [
        re.compile(r'(--|\b(select|union|insert|update|delete|drop|alter)\b)', re.IGNORECASE),
        re.compile(r'(\bexec\b|\bexecute\b)', re.IGNORECASE)
    ]
    for pattern in sql_injection_patterns:
        if pattern.search(data):
            raise ValidationError("Invalid input: possible SQL injection detected")

    # Check for XSS patterns
    xss_patterns = [
        re.compile(r'<script.*?>.*?</script>', re.IGNORECASE),
        re.compile(r'javascript:', re.IGNORECASE)
    ]
    for pattern in xss_patterns:
        if pattern.search(data):
            raise ValidationError("Invalid input: possible XSS detected")

    # Check for command injection patterns
    command_injection_patterns = [
        re.compile(r'(\||;|&|`|\$|\(|\)|<|>|\[|\]|\{|\}|\*|\?|!|~)', re.IGNORECASE),
        re.compile(r'(\bsh\b|\bbash\b|\bperl\b|\bpython\b|\bphp\b|\bnode\b|\bjava\b)', re.IGNORECASE),
        re.compile(r'(rm\b|ls\b|cd\b|cat\b|echo\b|wget\b|curl\b)', re.IGNORECASE)
    ]
    for pattern in command_injection_patterns:
        if pattern.search(data):
            raise ValidationError("Invalid input: possible command injection detected")

    # Check for LDAP injection patterns
    ldap_injection_patterns = [
        re.compile(r'(\(|\)|&|\||=)', re.IGNORECASE)
    ]
    for pattern in ldap_injection_patterns:
        if pattern.search(data):
            raise ValidationError("Invalid input: possible LDAP injection detected")

    # Check for XML injection patterns
    xml_injection_patterns = [
        re.compile(r'(<\?xml|<!DOCTYPE|<!ENTITY)', re.IGNORECASE)
    ]
    for pattern in xml_injection_patterns:
        if pattern.search(data):
            raise ValidationError("Invalid input: possible XML injection detected")

    return data
