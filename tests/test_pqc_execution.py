#!/usr/bin/env python3
"""
Tests for pqc_test.py execution

This test verifies that the pqc_test.py script executes correctly and produces the expected output.
"""

import os
import sys
import unittest
import subprocess
import tempfile
from typing import Tuple, Optional

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class TestPQCExecution(unittest.TestCase):
    """Test the execution of pqc_test.py"""
    
    def test_pqc_execution_output(self):
        """Test that pqc_test.py executes and produces the expected output"""
        # Get the absolute path to pqc_test.py
        pqc_test_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'pqc_test.py'))
        
        # Ensure the file exists
        self.assertTrue(os.path.isfile(pqc_test_path), f"pqc_test.py not found at {pqc_test_path}")
        
        # Execute the script and capture output
        result = self._run_script(pqc_test_path)
        
        # Check return code
        self.assertEqual(result[0], 0, f"pqc_test.py exited with code {result[0]}, output: {result[1]}")
        
        # Check for expected output strings
        output = result[1]
        expected_strings = [
            "Testing Enhanced PQC Algorithms",
            "FALCON version:",
            "Generated keys",
            "Verification result: True",
            "ML-KEM keys",
            "Shared secrets match: True",
            "Test completed successfully!",
            "SECURITY SUMMARY"
        ]
        
        for expected in expected_strings:
            self.assertIn(expected, output, f"Expected string '{expected}' not found in output")
            
        # Check for expected security statements
        security_statements = [
            "FALCON-1024 with tau=1.28",
            "ML-KEM-1024 provides",
            "Implementation includes constant-time operations",
            "Domain separation prevents multi-target attacks"
        ]
        
        for statement in security_statements:
            self.assertIn(statement, output, f"Security statement '{statement}' not found in output")
    
    def _run_script(self, script_path: str) -> Tuple[int, str]:
        """Run a Python script and return its exit code and output"""
        try:
            result = subprocess.run(
                [sys.executable, script_path], 
                capture_output=True,
                text=True,
                timeout=30  # Timeout after 30 seconds
            )
            return result.returncode, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return -1, "Script execution timed out"
        except Exception as e:
            return -1, f"Error executing script: {str(e)}"

if __name__ == "__main__":
    unittest.main() 