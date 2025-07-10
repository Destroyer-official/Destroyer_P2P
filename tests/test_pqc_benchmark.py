#!/usr/bin/env python3
"""
Performance Benchmarks for Post-Quantum Cryptography Algorithms

This test measures and compares the performance of EnhancedFALCON_1024 and 
EnhancedMLKEM_1024 against their base implementations.
"""

import os
import sys
import time
import statistics
import unittest
import logging
from typing import List, Dict, Callable, Any, Tuple
# Optional visualization support
try:
    import matplotlib.pyplot as plt
    HAVE_MATPLOTLIB = True
except ImportError:
    HAVE_MATPLOTLIB = False

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger(__name__)

# Import implementations
try:
    from pqc_algorithms import EnhancedFALCON_1024, EnhancedMLKEM_1024
    from quantcrypt.dss import FALCON_1024
    from quantcrypt.kem import MLKEM_1024
    log.info("Successfully imported crypto implementations")
except ImportError as e:
    log.error(f"Failed to import crypto modules: {e}")
    log.error("This test requires both pqc_algorithms and quantcrypt modules.")
    sys.exit(1)

class BenchmarkUtils:
    """Utilities for benchmarking cryptographic operations"""
    
    @staticmethod
    def measure_time(func: Callable, *args, iterations: int = 5) -> Dict[str, float]:
        """
        Measure execution time statistics for a function.
        
        Args:
            func: Function to measure
            *args: Arguments to pass to the function
            iterations: Number of iterations to run
            
        Returns:
            Dict with timing statistics (min, max, avg, median)
        """
        times = []
        
        # Warm-up run
        try:
            func(*args)
        except Exception as e:
            log.error(f"Error during warm-up: {e}")
            return {
                'min': float('inf'),
                'max': float('inf'),
                'avg': float('inf'),
                'median': float('inf'),
                'stdev': float('inf')
            }
            
        # Timed runs
        for i in range(iterations):
            start_time = time.time()
            try:
                func(*args)
            except Exception as e:
                log.error(f"Error during iteration {i}: {e}")
                continue
            end_time = time.time()
            times.append(end_time - start_time)
            
        # If all iterations failed, return inf
        if not times:
            return {
                'min': float('inf'),
                'max': float('inf'),
                'avg': float('inf'),
                'median': float('inf'),
                'stdev': float('inf')
            }
            
        # Calculate statistics
        return {
            'min': min(times),
            'max': max(times),
            'avg': statistics.mean(times),
            'median': statistics.median(times),
            'stdev': statistics.stdev(times) if len(times) > 1 else 0
        }
        
    @staticmethod
    def compare_implementations(name: str, base_results: Dict, enhanced_results: Dict) -> None:
        """Print a comparison of timing results"""
        print(f"\n=== {name} Performance Comparison ===")
        print(f"{'Operation':<15} {'Base (ms)':<12} {'Enhanced (ms)':<12} {'Difference %':<12}")
        print("-" * 50)
        
        for op in base_results:
            if op in enhanced_results:
                base_avg = base_results[op]['avg'] * 1000  # Convert to ms
                enhanced_avg = enhanced_results[op]['avg'] * 1000  # Convert to ms
                
                if base_avg > 0:
                    diff_percent = ((enhanced_avg - base_avg) / base_avg) * 100
                    diff_str = f"{diff_percent:+.2f}%"
                else:
                    diff_str = "N/A"
                    
                print(f"{op:<15} {base_avg:<12.2f} {enhanced_avg:<12.2f} {diff_str:<12}")


class TestPQCBenchmark(unittest.TestCase):
    """Benchmark tests for post-quantum cryptography implementations"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment for all tests"""
        # Initialize implementations
        cls.base_falcon = FALCON_1024()
        cls.enhanced_falcon = EnhancedFALCON_1024()
        cls.base_mlkem = MLKEM_1024()
        cls.enhanced_mlkem = EnhancedMLKEM_1024()
        
        # Generate test data
        cls.test_messages = [
            b"Small message",
            b"Medium sized message for testing",
            b"A longer message that requires more processing " * 5
        ]
        
        # Test parameters
        cls.iterations = 5  # Number of iterations for each benchmark
        cls.warmup_iterations = 1  # Number of warmup iterations
        
        # Create benchmark result storage
        cls.results = {
            'falcon_base': {},
            'falcon_enhanced': {},
            'mlkem_base': {},
            'mlkem_enhanced': {}
        }
        
        # Run the benchmarks
        cls._run_falcon_benchmarks()
        cls._run_mlkem_benchmarks()
    
    @classmethod
    def _run_falcon_benchmarks(cls):
        """Run benchmarks for FALCON implementations"""
        log.info("Running FALCON benchmarks...")
        
        # Generate keypairs for both implementations
        base_pk, base_sk = cls.base_falcon.keygen()
        enhanced_pk, enhanced_sk = cls.enhanced_falcon.keygen()
        
        # Benchmark key generation
        cls.results['falcon_base']['keygen'] = BenchmarkUtils.measure_time(
            cls.base_falcon.keygen, iterations=cls.iterations
        )
        cls.results['falcon_enhanced']['keygen'] = BenchmarkUtils.measure_time(
            cls.enhanced_falcon.keygen, iterations=cls.iterations
        )
        
        # Benchmark signing (medium message)
        message = cls.test_messages[1]
        cls.results['falcon_base']['sign'] = BenchmarkUtils.measure_time(
            cls.base_falcon.sign, base_sk, message, iterations=cls.iterations
        )
        cls.results['falcon_enhanced']['sign'] = BenchmarkUtils.measure_time(
            cls.enhanced_falcon.sign, enhanced_sk, message, iterations=cls.iterations
        )
        
        # Get signatures for verification
        base_sig = cls.base_falcon.sign(base_sk, message)
        enhanced_sig = cls.enhanced_falcon.sign(enhanced_sk, message)
        
        # Benchmark verification
        cls.results['falcon_base']['verify'] = BenchmarkUtils.measure_time(
            cls.base_falcon.verify, base_pk, message, base_sig, iterations=cls.iterations
        )
        cls.results['falcon_enhanced']['verify'] = BenchmarkUtils.measure_time(
            cls.enhanced_falcon.verify, enhanced_pk, message, enhanced_sig, iterations=cls.iterations
        )
        
        log.info("FALCON benchmarks completed")
    
    @classmethod
    def _run_mlkem_benchmarks(cls):
        """Run benchmarks for ML-KEM implementations"""
        log.info("Running ML-KEM benchmarks...")
        
        # Generate keypairs for both implementations
        base_pk, base_sk = cls.base_mlkem.keygen()
        enhanced_pk, enhanced_sk = cls.enhanced_mlkem.keygen()
        
        # Benchmark key generation
        cls.results['mlkem_base']['keygen'] = BenchmarkUtils.measure_time(
            cls.base_mlkem.keygen, iterations=cls.iterations
        )
        cls.results['mlkem_enhanced']['keygen'] = BenchmarkUtils.measure_time(
            cls.enhanced_mlkem.keygen, iterations=cls.iterations
        )
        
        # Benchmark encapsulation
        cls.results['mlkem_base']['encaps'] = BenchmarkUtils.measure_time(
            cls.base_mlkem.encaps, base_pk, iterations=cls.iterations
        )
        cls.results['mlkem_enhanced']['encaps'] = BenchmarkUtils.measure_time(
            cls.enhanced_mlkem.encaps, enhanced_pk, iterations=cls.iterations
        )
        
        # Get ciphertexts for decapsulation
        base_ct, _ = cls.base_mlkem.encaps(base_pk)
        enhanced_ct, _ = cls.enhanced_mlkem.encaps(enhanced_pk)
        
        # Benchmark decapsulation
        cls.results['mlkem_base']['decaps'] = BenchmarkUtils.measure_time(
            cls.base_mlkem.decaps, base_sk, base_ct, iterations=cls.iterations
        )
        cls.results['mlkem_enhanced']['decaps'] = BenchmarkUtils.measure_time(
            cls.enhanced_mlkem.decaps, enhanced_sk, enhanced_ct, iterations=cls.iterations
        )
        
        log.info("ML-KEM benchmarks completed")
    
    def test_report_benchmark_results(self):
        """Report benchmark results"""
        # Compare FALCON results
        BenchmarkUtils.compare_implementations(
            "FALCON-1024",
            self.results['falcon_base'],
            self.results['falcon_enhanced']
        )
        
        # Compare ML-KEM results
        BenchmarkUtils.compare_implementations(
            "ML-KEM-1024",
            self.results['mlkem_base'],
            self.results['mlkem_enhanced']
        )
        
        # Create performance summary
        self._create_performance_report()
        
        # No assertions needed - this is just a benchmark report
        self.assertTrue(True)
    
    def _create_performance_report(self):
        """Create a summary performance report"""
        # Calculate overhead percentages for FALCON operations
        falcon_overhead = {
            op: ((self.results['falcon_enhanced'][op]['avg'] / self.results['falcon_base'][op]['avg']) - 1) * 100
            if self.results['falcon_base'][op]['avg'] > 0 else 0
            for op in self.results['falcon_base'].keys()
        }
        
        # Calculate overhead percentages for ML-KEM operations
        mlkem_overhead = {
            op: ((self.results['mlkem_enhanced'][op]['avg'] / self.results['mlkem_base'][op]['avg']) - 1) * 100
            if self.results['mlkem_base'][op]['avg'] > 0 else 0
            for op in self.results['mlkem_base'].keys()
        }
        
        # Print security enhancement overhead summary
        print("\n=== Security Enhancement Overhead ===")
        print("FALCON Operations:")
        for op, overhead in falcon_overhead.items():
            print(f"  - {op}: {overhead:+.2f}%")
            
        print("ML-KEM Operations:")
        for op, overhead in mlkem_overhead.items():
            print(f"  - {op}: {overhead:+.2f}%")
        
        # Generate summary statistics
        falcon_avg_overhead = statistics.mean(falcon_overhead.values())
        mlkem_avg_overhead = statistics.mean(mlkem_overhead.values())
        total_avg_overhead = (falcon_avg_overhead + mlkem_avg_overhead) / 2
        
        print(f"\nAverage Overhead:")
        print(f"  - FALCON: {falcon_avg_overhead:+.2f}%")
        print(f"  - ML-KEM: {mlkem_avg_overhead:+.2f}%")
        print(f"  - Overall: {total_avg_overhead:+.2f}%")
        
        # Assess the performance impact
        print("\nPerformance Impact Assessment:")
        if total_avg_overhead < 10:
            print("[+] Minimal impact: Security enhancements add less than 10% overhead")
        elif total_avg_overhead < 25:
            print("[!] Moderate impact: Security enhancements add 10-25% overhead")
        else:
            print("[!] High impact: Security enhancements add over 25% overhead")
        
        # Optionally create a plot if matplotlib is available
        if self.results and HAVE_MATPLOTLIB:
            # Implementation of plot creation
            pass


if __name__ == "__main__":
    unittest.main() 