"""
#!/usr/bin/env python3
Verify that all test modules can be imported without errors.
This is a simple check to ensure the basic structure of the test suite is intact.
"""

import sys
import importlib
import traceback

# List of test modules to verify
TEST_MODULES = [
    'test_cert_auth_security',
    'test_chacha20poly1305_key_vulnerability',
    'test_crypto_suite',
    'test_double_ratchet_security',
    'test_hybrid_kex_security',
    'test_tls_channel_security',
    'test_padding'
]

def main():
    """Attempt to import each test module and report results"""
    print("Verifying test modules...")
    success_count = 0
    failed_modules = []
    
    for module_name in TEST_MODULES:
        try:
            print(f"Importing {module_name}...", end='')
            importlib.import_module(module_name)
            print(" OK")
            success_count += 1
        except Exception as e:
            print(" FAILED")
            print(f"  Error: {e}")
            failed_modules.append((module_name, str(e)))
    
    # Report results
    print("\nResults:")
    print(f"- {success_count}/{len(TEST_MODULES)} modules imported successfully")
    
    if failed_modules:
        print(f"- {len(failed_modules)} modules failed to import:")
        for module, error in failed_modules:
            print(f"  - {module}: {error}")
        return 1
    else:
        print("All test modules verified successfully!")
        return 0


if __name__ == '__main__':
    sys.exit(main()) 