#!/usr/bin/env python3
"""
Destroyer_P2P Security Test Suite Runner

This script runs all the security-focused tests in the test suite and 
generates a comprehensive security report.
"""

import unittest
import os
import sys
import time
import logging
import json
import datetime
import argparse
from collections import defaultdict

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import test modules
import tests.test_cert_auth_security
import tests.test_hybrid_kex_security
import tests.test_double_ratchet_security
import tests.test_tls_channel_security
import tests.test_crypto_suite
import tests.test_padding

# Configure logging for test output
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("security_test_run.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("security_tests")

class SecurityTestResult(unittest.TextTestResult):
    """Custom test result class that collects security-relevant information"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.security_issues = []
        self.vulnerability_count = 0
        self.security_passed = []
        self.component_results = defaultdict(lambda: {"passed": [], "failed": []})
    
    def addError(self, test, err):
        """Called when a test raises an unexpected exception"""
        super().addError(test, err)
        self._record_security_issue(test, err, "ERROR")
    
    def addFailure(self, test, err):
        """Called when a test fails"""
        super().addFailure(test, err)
        self._record_security_issue(test, err, "FAIL")
    
    def addSuccess(self, test):
        """Called when a test succeeds"""
        super().addSuccess(test)
        self.security_passed.append(self._get_test_info(test))
        
        # Record component result
        component = self._get_test_component(test)
        self.component_results[component]["passed"].append(self._get_test_info(test))
    
    def _record_security_issue(self, test, err, status):
        """Record security issue details"""
        issue_info = self._get_test_info(test)
        issue_info["error_type"] = err[0].__name__
        issue_info["error_message"] = str(err[1])
        issue_info["status"] = status
        issue_info["timestamp"] = datetime.datetime.now().isoformat()
        
        # Check if this might be a vulnerability
        if any(keyword in test.id() for keyword in [
            "vulnerability", "replay", "secure", "tampering", "leak", "overflow"
        ]):
            self.vulnerability_count += 1
            issue_info["potential_vulnerability"] = True
        else:
            issue_info["potential_vulnerability"] = False
            
        self.security_issues.append(issue_info)
        
        # Record component result
        component = self._get_test_component(test)
        self.component_results[component]["failed"].append(issue_info)
    
    def _get_test_info(self, test):
        """Extract useful information from the test case"""
        test_id = test.id()
        class_name = test.__class__.__name__
        test_method = test._testMethodName
        docstring = test._testMethodDoc or ""
        
        return {
            "id": test_id,
            "class": class_name,
            "method": test_method,
            "description": docstring.strip()
        }
    
    def _get_test_component(self, test):
        """Determine which component is being tested"""
        test_id = test.id()
        if "cert_auth_security" in test_id:
            return "Certificate Authentication"
        elif "hybrid_kex_security" in test_id:
            return "Hybrid Key Exchange"
        elif "double_ratchet_security" in test_id:
            return "Double Ratchet Messaging"
        elif "tls_channel_security" in test_id:
            return "TLS Channel Security"
        elif "crypto_suite" in test_id:
            return "Cryptographic Suite"
        elif "padding" in test_id:
            return "Padding Security"
        else:
            return "Other Security Tests"


class SecurityReportGenerator:
    """Generates a comprehensive security report from test results"""
    
    def __init__(self, test_result):
        self.result = test_result
        self.report_data = {}
        self.output_filename = None
    
    def generate_report(self):
        """Generate the security test report"""
        # Overall statistics
        self.report_data["timestamp"] = datetime.datetime.now().isoformat()
        self.report_data["summary"] = {
            "total_tests": self.result.testsRun,
            "passed": len(self.result.security_passed),
            "failures": len(self.result.failures),
            "errors": len(self.result.errors),
            "potential_vulnerabilities": self.result.vulnerability_count
        }
        
        # Calculate pass rate
        total = self.report_data["summary"]["total_tests"]
        passed = self.report_data["summary"]["passed"]
        self.report_data["summary"]["pass_rate"] = (passed / total) * 100 if total > 0 else 0
        
        # Add component-specific results
        self.report_data["components"] = {}
        for component, results in self.result.component_results.items():
            component_passed = len(results["passed"])
            component_failed = len(results["failed"])
            component_total = component_passed + component_failed
            
            self.report_data["components"][component] = {
                "total_tests": component_total,
                "passed": component_passed,
                "failed": component_failed,
                "pass_rate": (component_passed / component_total) * 100 if component_total > 0 else 0,
                "issues": results["failed"]
            }
        
        # Add detailed results
        self.report_data["failed_tests"] = self.result.security_issues
        
        # Add timestamp and execution info
        self.report_data["execution_time"] = time.time()
        self.report_data["execution_date"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return self.report_data
    
    def save_report(self, filename="security_report.json"):
        """Save the security report to a file"""
        with open(filename, 'w') as f:
            json.dump(self.report_data, f, indent=2)
        
        self.output_filename = filename
        return filename
    
    def print_summary(self):
        """Print a summary of the security test results to the console"""
        summary = self.report_data["summary"]
        
        print("\n" + "=" * 80)
        print(f"SECURITY TEST SUMMARY - {self.report_data['execution_date']}")
        print("=" * 80)
        print(f"Total Tests: {summary['total_tests']}")
        print(f"Passed: {summary['passed']} ({summary['pass_rate']:.1f}%)")
        print(f"Failed: {summary['failures'] + summary['errors']}")
        print(f"Potential Vulnerabilities: {summary['potential_vulnerabilities']}")
        print("\n" + "-" * 80)
        print("RESULTS BY COMPONENT")
        print("-" * 80)
        
        # Print component results
        for component, data in self.report_data["components"].items():
            print(f"{component}: {data['passed']}/{data['total_tests']} tests passed ({data['pass_rate']:.1f}%)")
            if data['failed'] > 0:
                print(f"  • {data['failed']} test(s) failed in this component")
        
        # Print vulnerability summary if any exist
        if summary['potential_vulnerabilities'] > 0:
            print("\n" + "!" * 80)
            print("POTENTIAL SECURITY VULNERABILITIES DETECTED")
            print("!" * 80)
            for issue in self.report_data["failed_tests"]:
                if issue.get("potential_vulnerability", False):
                    print(f"- {issue['description']} ({issue['id']})")
                    print(f"  {issue['error_message']}\n")
        
        print("\n" + "=" * 80)
        if self.output_filename:
            print(f"Detailed report saved to: {self.output_filename}")
        print("=" * 80 + "\n")


def create_security_test_suite():
    """Create a test suite containing all security tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add specific test modules
    suite.addTests(loader.loadTestsFromModule(tests.test_cert_auth_security))
    suite.addTests(loader.loadTestsFromModule(tests.test_hybrid_kex_security))
    suite.addTests(loader.loadTestsFromModule(tests.test_double_ratchet_security))
    suite.addTests(loader.loadTestsFromModule(tests.test_tls_channel_security))
    suite.addTests(loader.loadTestsFromModule(tests.test_crypto_suite))
    suite.addTests(loader.loadTestsFromModule(tests.test_padding))
    
    return suite


def run_security_tests(verbosity=1, output_file="security_report.json"):
    """Run all security tests and generate a report"""
    logger.info("Starting security test suite")
    
    # Create test suite
    suite = create_security_test_suite()
    
    # Run tests with custom result class
    runner = unittest.TextTestRunner(verbosity=verbosity, resultclass=SecurityTestResult)
    result = runner.run(suite)
    
    # Generate and save report
    generator = SecurityReportGenerator(result)
    report_data = generator.generate_report()
    filename = generator.save_report(output_file)
    generator.print_summary()
    
    return report_data, filename


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run security tests for Destroyer_P2P")
    parser.add_argument("-v", "--verbosity", type=int, choices=[0, 1, 2], default=1,
                        help="Test output verbosity (0=minimal, 1=normal, 2=verbose)")
    parser.add_argument("-o", "--output", default="security_report.json",
                        help="Output file for the security report (JSON format)")
    
    args = parser.parse_args()
    
    # Run tests
    run_security_tests(verbosity=args.verbosity, output_file=args.output) 