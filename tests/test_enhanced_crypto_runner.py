#!/usr/bin/env python3
"""
Runner script for Enhanced Post-Quantum Cryptography Test Suite

This script executes the test_enhanced_crypto.py tests and provides a clear summary of the results.
"""

import os
import sys
import time
import logging
import unittest
import subprocess
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('logs/enhanced_crypto_test_results.log', mode='w')
    ]
)
log = logging.getLogger(__name__)

def print_separator(char='=', length=80):
    """Print a separator line"""
    print(char * length)

def run_tests():
    """Run the enhanced crypto tests"""
    print_separator()
    print(f"ENHANCED POST-QUANTUM CRYPTOGRAPHY TEST SUITE")
    print(f"Starting tests at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_separator()
    
    # Check if the test files exist
    test_files = [
        'tests/test_enhanced_crypto.py',
        'tests/test_sphincs_plus.py'
    ]
    
    missing_files = [f for f in test_files if not os.path.exists(f)]
    if missing_files:
        print(f"Error: The following test files are missing: {', '.join(missing_files)}")
        return False
    
    print("\nRunning tests for EnhancedFALCON_1024, EnhancedMLKEM_1024, and SPHINCS+...\n")
    
    # Run the tests
    start_time = time.time()
    
    # Create a test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test modules
    for test_file in test_files:
        module_name = os.path.splitext(test_file)[0].replace('/', '.')
        try:
            tests = loader.loadTestsFromName(module_name)
            suite.addTest(tests)
            print(f"Added tests from {module_name}")
        except Exception as e:
            print(f"Error loading tests from {module_name}: {e}")
    
    # Run the tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    end_time = time.time()
    
    # Print summary
    print_separator()
    print(f"TEST SUMMARY")
    print_separator()
    print(f"Total execution time: {end_time - start_time:.2f} seconds")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    
    if not result.failures and not result.errors:
        print("\n✅ All tests PASSED!")
        print("\nThe enhanced implementations of FALCON-1024, ML-KEM-1024, and SPHINCS+ are working correctly")
        print("and provide the expected security enhancements.")
    else:
        print("\n❌ Some tests FAILED!")
        print("\nPlease review the output above for details on the failures.")
    
    print_separator()
    return len(result.failures) == 0 and len(result.errors) == 0

def main():
    """Main entry point"""
    try:
        # Make sure logs directory exists
        os.makedirs('logs', exist_ok=True)
        
        success = run_tests()
        sys.exit(0 if success else 1)
    except Exception as e:
        log.error(f"Error running tests: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 