"""
Tests for constant-time operations in the Double Ratchet implementation.

These tests verify that security-critical operations are performed in constant time
to prevent timing side-channel attacks.
"""

import unittest
import os
import sys
import time
import statistics
from typing import List, Callable

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the modules under test
from double_ratchet import ConstantTime, ReplayCache
import secure_key_manager as skm

class TestConstantTimeOperations(unittest.TestCase):
    """Test case for constant-time operations."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Number of iterations for timing tests
        self.iterations = 1000
    
    def measure_execution_time(self, func: Callable, *args) -> List[float]:
        """
        Measure the execution time of a function over multiple iterations.
        
        Args:
            func: The function to measure
            *args: Arguments to pass to the function
            
        Returns:
            List of execution times in seconds
        """
        times = []
        for _ in range(self.iterations):
            start = time.perf_counter()
            func(*args)
            end = time.perf_counter()
            times.append(end - start)
        return times
    
    def test_constant_time_compare(self):
        """Test that ConstantTime.compare operates in constant time."""
        # Create test data
        a = b"A" * 32
        b_equal = b"A" * 32
        b_diff_start = b"B" + b"A" * 31
        b_diff_middle = b"A" * 16 + b"B" + b"A" * 15
        b_diff_end = b"A" * 31 + b"B"
        
        # Measure execution times for different comparisons
        times_equal = self.measure_execution_time(ConstantTime.compare, a, b_equal)
        times_diff_start = self.measure_execution_time(ConstantTime.compare, a, b_diff_start)
        times_diff_middle = self.measure_execution_time(ConstantTime.compare, a, b_diff_middle)
        times_diff_end = self.measure_execution_time(ConstantTime.compare, a, b_diff_end)
        
        # Calculate statistics
        mean_equal = statistics.mean(times_equal)
        mean_diff_start = statistics.mean(times_diff_start)
        mean_diff_middle = statistics.mean(times_diff_middle)
        mean_diff_end = statistics.mean(times_diff_end)
        
        # Calculate the standard deviation of the means
        means = [mean_equal, mean_diff_start, mean_diff_middle, mean_diff_end]
        stdev = statistics.stdev(means)
        mean_of_means = statistics.mean(means)
        
        # The standard deviation should be small relative to the mean
        # This indicates that the execution times are similar regardless of input
        self.assertLess(stdev / mean_of_means, 0.1, 
                      "Execution times vary too much for constant-time operation")
    
    def test_replay_cache_contains(self):
        """Test that ReplayCache.contains operates in constant time."""
        # Create a replay cache and add some message IDs
        cache = ReplayCache()
        message_id_in_cache = os.urandom(8)
        message_id_not_in_cache = os.urandom(8)
        cache.add(message_id_in_cache)
        
        # Measure execution times for both cases
        times_in_cache = self.measure_execution_time(cache.contains, message_id_in_cache)
        times_not_in_cache = self.measure_execution_time(cache.contains, message_id_not_in_cache)
        
        # Calculate statistics
        mean_in_cache = statistics.mean(times_in_cache)
        mean_not_in_cache = statistics.mean(times_not_in_cache)
        
        # Calculate the ratio of the means
        ratio = max(mean_in_cache, mean_not_in_cache) / min(mean_in_cache, mean_not_in_cache)
        
        # The ratio should be close to 1 for constant-time operation
        self.assertLess(ratio, 2.0, 
                      "Execution times vary too much between cache hit and miss")
    
    def test_constant_time_select(self):
        """Test that ConstantTime.select operates in constant time."""
        # Create test data
        a = b"A" * 32
        b = b"B" * 32
        
        # Measure execution times for different conditions
        times_true = self.measure_execution_time(ConstantTime.select, True, a, b)
        times_false = self.measure_execution_time(ConstantTime.select, False, a, b)
        
        # Calculate statistics
        mean_true = statistics.mean(times_true)
        mean_false = statistics.mean(times_false)
        
        # Calculate the ratio of the means
        ratio = max(mean_true, mean_false) / min(mean_true, mean_false)
        
        # The ratio should be close to 1 for constant-time operation
        self.assertLess(ratio, 1.5, 
                      "Execution times vary too much between True and False conditions")
    
    def test_functional_correctness(self):
        """Test that constant-time functions produce correct results."""
        # Test ConstantTime.compare
        self.assertTrue(ConstantTime.compare(b"same", b"same"))
        self.assertFalse(ConstantTime.compare(b"same", b"diff"))
        self.assertFalse(ConstantTime.compare(b"same", b"same_longer"))
        
        # Test ConstantTime.select
        self.assertEqual(ConstantTime.select(True, b"a", b"b"), b"a")
        self.assertEqual(ConstantTime.select(False, b"a", b"b"), b"b")
        
        # Test ReplayCache.contains
        cache = ReplayCache()
        message_id = os.urandom(8)
        self.assertFalse(message_id in cache)
        cache.add(message_id)
        self.assertTrue(message_id in cache)
        
if __name__ == '__main__':
    unittest.main() 