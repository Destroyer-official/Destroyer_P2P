# Destroyer_P2P Security Test Suite

This directory contains comprehensive security tests for the Destroyer_P2P secure chat system. These tests are designed to verify the security properties of the system and ensure that fixed vulnerabilities remain mitigated.

## Test Suite Components

The test suite covers the following security-critical components:

1. **Certificate Authentication** (`test_cert_auth_security.py`): Tests for secure certificate exchange, proper key derivation, and protection against the previously identified ChaCha20-Poly1305 key size vulnerability.

2. **Hybrid Key Exchange** (`test_hybrid_kex_security.py`): Tests for the security of the post-quantum hybrid key exchange implementation, including X25519 + ML-KEM-1024.

3. **Double Ratchet Messaging** (`test_double_ratchet_security.py`): Tests for forward secrecy, break-in recovery, and protection against replay attacks in the double ratchet messaging protocol.

4. **TLS Channel Security** (`test_tls_channel_security.py`): Tests for proper TLS 1.3 configuration, cipher suite enforcement, and secure channel establishment.

5. **Cryptographic Suite** (`test_crypto_suite.py`): General tests for the cryptographic primitives used throughout the system.

6. **Padding Security** (`test_padding.py`): Tests for proper padding implementation to prevent padding oracle attacks.

## Key Security Tests

### ChaCha20Poly1305 Key Size Vulnerability Test

A critical vulnerability was discovered and fixed in the certificate exchange process where a 33-byte key was incorrectly used with ChaCha20Poly1305 (which requires exactly 32 bytes). This test specifically verifies:

1. The vulnerability is properly fixed using HKDF-SHA256 for key derivation
2. Error handling is improved to fail securely rather than returning plaintext
3. The system correctly rejects invalid key sizes

To run this specific test:

```bash
python tests/test_chacha20poly1305_key_vulnerability.py
```

All 7 tests in this file should pass, confirming the vulnerability has been properly mitigated.

## Running the Tests

### Running All Security Tests

To run the entire security test suite and generate a comprehensive security report:

```bash
python tests/run_security_tests.py
```

By default, this will run all tests with normal verbosity and save the security report to `security_report.json`.

### Command Line Options

The test runner supports several command-line options:

- `-v, --verbosity`: Control test output verbosity (0=minimal, 1=normal, 2=verbose)
- `-o, --output`: Specify the output file for the security report (JSON format)

Example with options:

```bash
python tests/run_security_tests.py --verbosity 2 --output custom_security_report.json
```

### Running Individual Test Files

You can also run individual test files if you want to focus on a specific security aspect:

```bash
python -m unittest tests.test_cert_auth_security
python -m unittest tests.test_hybrid_kex_security
python -m unittest tests.test_double_ratchet_security
python -m unittest tests.test_tls_channel_security
```

## Interpreting Test Results

The test runner generates a comprehensive security report that includes:

1. **Summary statistics**: Total tests run, passed tests, failed tests, and potential vulnerabilities.
2. **Component-specific results**: Detailed results for each security component.
3. **Potential vulnerability details**: Information about tests that specifically check for vulnerabilities and whether they passed or failed.

### Security Report Format

The security report is generated in JSON format with the following structure:

```json
{
  "timestamp": "ISO timestamp",
  "summary": {
    "total_tests": 42,
    "passed": 40,
    "failures": 1,
    "errors": 1,
    "potential_vulnerabilities": 1,
    "pass_rate": 95.2
  },
  "components": {
    "Component Name": {
      "total_tests": 10,
      "passed": 9,
      "failed": 1,
      "pass_rate": 90.0,
      "issues": [
        {
          "id": "test_id",
          "class": "TestClassName",
          "method": "test_method_name",
          "description": "Test description",
          "error_type": "AssertionError",
          "error_message": "Error message",
          "status": "FAIL",
          "timestamp": "ISO timestamp",
          "potential_vulnerability": true
        }
      ]
    }
  },
  "failed_tests": [
    // Same structure as issues above
  ],
  "execution_time": 1622547632.123456,
  "execution_date": "2025-06-01 12:34:56"
}
```

## Adding New Security Tests

When adding new security tests, follow these guidelines:

1. **Test naming**: Use descriptive names that clearly indicate what security property is being tested.
2. **Docstrings**: Include detailed docstrings that explain the security property being tested and how the test verifies it.
3. **Vulnerability keywords**: Include keywords like "vulnerability", "replay", "secure", "tampering", etc. in test methods that specifically check for known vulnerabilities. This ensures they're properly flagged in the security report.
4. **Comprehensive testing**: Test both the "happy path" (when things work correctly) and failure modes (when attacks are attempted).

## Continuous Security Testing

It's recommended to run these tests:

1. **Before each release**: To ensure no security regressions.
2. **After security fixes**: To verify vulnerabilities are properly mitigated.
3. **When updating cryptographic libraries**: To ensure the security properties are maintained.
4. **During security audits**: To provide evidence of security properties.

## Known Limitations

1. **Hardware security**: Some tests may be skipped on platforms without hardware security features.
2. **Performance considerations**: The full test suite may take several minutes to run due to the computational intensity of some cryptographic operations.
3. **External dependencies**: Tests assume the presence of required cryptographic libraries. Missing libraries might cause some tests to be skipped. 