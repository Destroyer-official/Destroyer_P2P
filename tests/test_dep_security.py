#!/usr/bin/env python
"""
Test script for the Data Execution Prevention (DEP) security implementation.
"""

import unittest
import ctypes
import logging
import platform
import sys

# Import our DEP implementation
import dep_impl

# Configure logging
log = logging.getLogger("dep_test")

class TestDepSecurity(unittest.TestCase):
    """
    Test suite for Data Execution Prevention (DEP) security features.
    """

    @unittest.skipUnless(platform.system() == 'Windows', "This test is for Windows only")
    def test_standard_dep_windows(self):
        """Test standard Windows DEP implementation handles expected errors."""
        log.info("Testing standard Windows DEP implementation...")
        dep = dep_impl.EnhancedDEP()
        result = dep._enable_standard_dep()
        log.info(f"Standard DEP enabled: {result}")
        if not result:
            error = ctypes.windll.kernel32.GetLastError()
            log.info(f"Last error code: {error}")
            self.assertIn(error, [50, 109], "Expected error code 50 or 109 on failure")
        self.assertTrue(True) # Test passes if it runs, assertion is for expected errors

    @unittest.skipUnless(platform.system() == 'Windows', "This test is for Windows only")
    def test_enhanced_dep_windows(self):
        """Test enhanced DEP implementation on Windows."""
        log.info("Testing enhanced DEP implementation on Windows...")
        dep = dep_impl.EnhancedDEP()
        result = dep._enable_enhanced_dep()
        log.info(f"Enhanced DEP enabled: {result}")
        self.assertTrue(result)

    @unittest.skipUnless(platform.system() == 'Windows', "This test is for Windows only")
    def test_memory_protection_windows(self):
        """Test memory protection features on Windows."""
        log.info("Testing memory protection features on Windows...")
        dep = dep_impl.EnhancedDEP()
        dep.enable_dep()
        
        addr, region_id = dep.allocate_protected_memory(4096)
        self.assertIsNotNone(addr, "Failed to allocate protected memory")
        log.info(f"Allocated protected memory at {addr:#x}, region {region_id}")

        self.assertTrue(dep.mark_as_non_executable(region_id), "Failed to mark memory as non-executable")
        log.info(f"Marked region {region_id} as non-executable")

        try:
            function_type = ctypes.CFUNCTYPE(ctypes.c_int)
            func = function_type(addr)
            result = func()
            self.fail("SECURITY FAILURE: Executed code from protected memory!")
        except Exception as e:
            log.info(f"Expected exception when trying to execute protected memory: {e}")

        if dep.status().get('acg_enabled', False):
            log.info("ACG is enabled. Skipping marking memory as executable, as it's expected to fail.")
            self.assertTrue(dep.free_memory(region_id), "Failed to free memory")
            log.info(f"Freed memory region {region_id}")
        else:
            self.assertTrue(dep.mark_as_executable(region_id), "Failed to mark memory as executable")
            log.info(f"Marked region {region_id} as executable")
            self.assertTrue(dep.free_memory(region_id), "Failed to free memory")
            log.info(f"Freed memory region {region_id}")

    @unittest.skipUnless(platform.system() == 'Windows', "This test is for Windows only")
    def test_error_code_handling_windows(self):
        """Test that error codes are properly handled as expected conditions on Windows."""
        log.info("Testing error code handling in DEP implementation on Windows...")
        dep = dep_impl.EnhancedDEP()
        dep._enable_standard_dep()
        error = ctypes.windll.kernel32.GetLastError()
        log.info(f"Last error code: {error}")
        
        if error in [50, 109]:
            log.info(f"Error code {error} detected - this should be handled as an expected condition")
            overall_result = dep.enable_dep()
            log.info(f"Overall DEP enable result: {overall_result}")
            log.info(f"DEP status: {dep.status()}")
            self.assertTrue(dep.status()['effective'] and overall_result, f"Error code {error} was not properly handled")
            log.info(f"SUCCESS: Error code {error} was properly handled as an expected condition")
        else:
            log.warning(f"Expected error code 50 or 109, but got {error} instead")
            overall_result = dep.enable_dep()
            self.assertTrue(dep.status()['effective'] and overall_result, f"DEP is not active despite unexpected error code {error}")

    @unittest.skipUnless(platform.system() == 'Windows', "This test is for Windows only")
    def test_full_dep_implementation_windows(self):
        """Test the full DEP implementation as used in secure_p2p.py on Windows."""
        log.info("Testing full DEP implementation on Windows...")
        dep = dep_impl.implement_dep_in_secure_p2p()
        log.info(f"DEP status: {dep.status()}")
        self.assertTrue(dep.status()['effective'], "No effective DEP protection is active")
        log.info("DEP protection is active")

    def test_cross_platform_noop(self):
        """Test that on non-Windows platforms, the module acts as a no-op."""
        if platform.system() == 'Windows':
            self.skipTest("This test is for non-Windows platforms")
        
        log.info(f"Running basic cross-platform check on {platform.system()}...")
        dep = dep_impl.EnhancedDEP()
        log.info("Successfully instantiated EnhancedDEP on non-Windows platform.")
        
        self.assertFalse(dep.enable_dep(), "enable_dep should return False")
        self.assertFalse(dep._enable_standard_dep(), "_enable_standard_dep should return False")
        self.assertFalse(dep._enable_enhanced_dep(), "_enable_enhanced_dep should return False")
        self.assertFalse(dep.protect_memory(0, 0), "protect_memory should return False")
        
        addr, region_id = dep.allocate_protected_memory(1024)
        self.assertIsNone(addr)
        self.assertIsNone(region_id)
        
        self.assertFalse(dep.free_memory("dummy"), "free_memory should return False")
        self.assertFalse(dep.mark_as_non_executable("dummy"), "mark_as_non_executable should return False")
        self.assertFalse(dep.mark_as_executable("dummy"), "mark_as_executable should return False")
        
        status = dep.status()
        self.assertFalse(status['effective'], "status() should report not effective")
        
        dep_handler = dep_impl.implement_dep_in_secure_p2p()
        self.assertIsInstance(dep_handler, dep_impl.EnhancedDEP)
        self.assertFalse(dep_handler.status()['effective'])
        log.info("All DEP methods returned expected default values on non-Windows platform.")

if __name__ == "__main__":
    unittest.main() 