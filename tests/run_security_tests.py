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
import importlib

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set environment variable to disable anti-debugging during tests
os.environ["DISABLE_ANTI_DEBUGGING"] = "false"

# Import test modules
import tests.test_cert_auth_security
import tests.test_hybrid_kex_security
import tests.test_double_ratchet_security
import tests.test_tls_channel_security
import tests.test_crypto_suite
import tests.test_padding
import tests.test_dep_security
import tests.test_chacha20poly1305_key_vulnerability
import tests.test_traffic_analysis
import tests.test_additional_security
import tests.test_attributes
import tests.test_secure_connect
import tests.test_double_ratchet
import tests.test_ca_exchange
import tests.test_server_startup
import tests.test_military_grade_security
import tests.test_dep_impl
import tests.test_secure_memory
import tests.test_secure_memory_app
import tests.test_dep

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
        self.test_details = []  # For storing detailed results of all tests
    
    def addError(self, test, err):
        """Called when a test raises an unexpected exception"""
        super().addError(test, err)
        issue_info = self._record_security_issue(test, err, "ERROR")
        self.test_details.append(issue_info)
    
    def addFailure(self, test, err):
        """Called when a test fails"""
        super().addFailure(test, err)
        issue_info = self._record_security_issue(test, err, "FAIL")
        self.test_details.append(issue_info)
    
    def addSuccess(self, test):
        """Called when a test succeeds"""
        super().addSuccess(test)
        test_info = self._get_test_info(test)
        test_info["status"] = "PASS"
        test_info["timestamp"] = datetime.datetime.now().isoformat()
        self.security_passed.append(test_info)
        self.test_details.append(test_info)
        
        # Record component result
        component = self._get_test_component(test)
        self.component_results[component]["passed"].append(test_info)
    
    def addSkip(self, test, reason):
        """Called when a test is skipped"""
        super().addSkip(test, reason)
        test_info = self._get_test_info(test)
        test_info["status"] = "SKIP"
        test_info["reason"] = reason
        test_info["timestamp"] = datetime.datetime.now().isoformat()
        self.test_details.append(test_info)
    
    def _record_security_issue(self, test, err, status):
        """Record security issue details"""
        issue_info = self._get_test_info(test)
        issue_info["error_type"] = err[0].__name__
        issue_info["error_message"] = str(err[1])
        issue_info["traceback"] = self._exc_info_to_string(err, test)
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
        
        return issue_info
    
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
            "description": docstring.strip(),
            "module": test.__module__
        }
    
    def _get_test_component(self, test):
        """Determine which component is being tested"""
        test_id = test.id()
        if "cert_auth_security" in test_id or "test_ca_exchange" in test_id:
            return "Certificate Authentication"
        elif "hybrid_kex_security" in test_id:
            return "Hybrid Key Exchange"
        elif "double_ratchet_security" in test_id or "test_double_ratchet" in test_id:
            return "Double Ratchet Messaging"
        elif "tls_channel_security" in test_id:
            return "TLS Channel Security"
        elif "crypto_suite" in test_id:
            return "Cryptographic Suite"
        elif "padding" in test_id:
            return "Padding Security"
        elif "dep_security" in test_id or "test_dep_impl" in test_id or "test_dep" in test_id:
            return "DEP Security"
        elif "chacha20poly1305" in test_id:
            return "ChaCha20-Poly1305 Vulnerability"
        elif "traffic_analysis" in test_id:
            return "Traffic Analysis Protection"
        elif "additional_security" in test_id:
            return "Additional Security Features"
        elif "secure_memory" in test_id:
            return "Secure Memory Management"
        elif "test_attributes" in test_id:
            return "Core Attributes"
        elif "test_secure_connect" in test_id or "test_server_startup" in test_id:
            return "Secure Connection Flow"
        elif "military_grade_security" in test_id:
            return "Military-Grade Security Features"
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
            "skipped": len(self.result.skipped),
            "potential_vulnerabilities": self.result.vulnerability_count,
            "anti_debugging_protection": os.environ.get("DISABLE_ANTI_DEBUGGING", "false").lower() == "false"
        }
        
        # Calculate pass rate
        total = self.report_data["summary"]["total_tests"] - self.report_data["summary"]["skipped"]
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
        
        # Add detailed results for all tests
        self.report_data["all_tests"] = self.result.test_details
        
        # Add detailed results for failed tests only
        self.report_data["failed_tests"] = self.result.security_issues
        
        # Add timestamp and execution info
        self.report_data["execution_time"] = time.time()
        self.report_data["execution_date"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.report_data["execution_environment"] = {
            "platform": sys.platform,
            "python_version": sys.version,
            "anti_debugging_enabled": os.environ.get("DISABLE_ANTI_DEBUGGING", "false").lower() == "false"
        }
        
        return self.report_data
    
    def save_report(self, filename="security_report.json"):
        """Save the security report to a file"""
        with open(filename, 'w') as f:
            json.dump(self.report_data, f, indent=2)
        
        # Also save a detailed HTML report
        html_filename = filename.replace('.json', '.html')
        self._generate_html_report(html_filename)
        
        self.output_filename = filename
        return filename
    
    def _generate_html_report(self, filename="security_report.html"):
        """Generate an HTML report for better readability"""
        try:
            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Military-Grade Security Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #333366; }}
        .summary {{ background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .component {{ background-color: #f9f9f9; padding: 10px; margin-bottom: 15px; border-left: 4px solid #333366; }}
        .pass {{ color: green; }}
        .fail {{ color: red; }}
        .skip {{ color: orange; }}
        .error {{ color: darkred; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #333366; color: white; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .vuln {{ background-color: #ffebee; }}
    </style>
</head>
<body>
    <h1>Military-Grade Security Test Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Date:</strong> {self.report_data["execution_date"]}</p>
        <p><strong>Total Tests:</strong> {self.report_data["summary"]["total_tests"]}</p>
        <p><strong>Passed:</strong> <span class="pass">{self.report_data["summary"]["passed"]}</span> ({self.report_data["summary"]["pass_rate"]:.1f}%)</p>
        <p><strong>Failed:</strong> <span class="fail">{self.report_data["summary"]["failures"]}</span></p>
        <p><strong>Errors:</strong> <span class="error">{self.report_data["summary"]["errors"]}</span></p>
        <p><strong>Skipped:</strong> <span class="skip">{self.report_data["summary"]["skipped"]}</span></p>
        <p><strong>Potential Vulnerabilities:</strong> {self.report_data["summary"]["potential_vulnerabilities"]}</p>
        <p><strong>Anti-Debugging Protection:</strong> {"Enabled" if self.report_data["summary"]["anti_debugging_protection"] else "Disabled for testing"}</p>
        <p><strong>Environment:</strong> {self.report_data["execution_environment"]["platform"]}, Python {self.report_data["execution_environment"]["python_version"].split()[0]}</p>
    </div>
    
    <h2>Components Overview</h2>
"""
            
            # Add component results
            for component, data in self.report_data["components"].items():
                html += f"""
    <div class="component">
        <h3>{component}</h3>
        <p><strong>Tests:</strong> {data["passed"]}/{data["total_tests"]} passed ({data["pass_rate"]:.1f}%)</p>
    </div>"""
            
            # Add detailed test results
            html += """
    <h2>Detailed Test Results</h2>
    <table>
        <tr>
            <th>Status</th>
            <th>Component</th>
            <th>Test</th>
            <th>Description</th>
        </tr>
"""
            
            # Sort tests by component and status
            sorted_tests = sorted(self.report_data["all_tests"], 
                                 key=lambda x: (self._get_component_sort_key(x["id"]), x["status"] != "PASS"))
            
            for test in sorted_tests:
                status_class = ""
                if test["status"] == "PASS":
                    status_class = "pass"
                elif test["status"] == "FAIL":
                    status_class = "fail"
                elif test["status"] == "ERROR":
                    status_class = "error"
                elif test["status"] == "SKIP":
                    status_class = "skip"
                
                component = self._get_component_name(test["id"])
                is_vuln = test.get("potential_vulnerability", False)
                
                html += f"""
        <tr class="{'vuln' if is_vuln else ''}">
            <td class="{status_class}">{test["status"]}</td>
            <td>{component}</td>
            <td>{test["method"]}</td>
            <td>{test["description"]}</td>
        </tr>"""
                
                # If there's an error or failure, display the message
                if "error_message" in test:
                    html += f"""
        <tr class="{'vuln' if is_vuln else ''}">
            <td colspan="4"><strong>Error:</strong> {test["error_message"]}</td>
        </tr>"""
            
            html += """
    </table>
</body>
</html>"""
            
            with open(filename, 'w') as f:
                f.write(html)
                
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
    
    def _get_component_sort_key(self, test_id):
        """Helper to sort components consistently"""
        if "cert_auth_security" in test_id or "test_ca_exchange" in test_id:
            return "01"
        elif "hybrid_kex_security" in test_id:
            return "02"
        elif "double_ratchet_security" in test_id or "test_double_ratchet" in test_id:
            return "03"
        # ... add others as needed
        else:
            return "99"
            
    def _get_component_name(self, test_id):
        """Get component name from test ID - duplicate of the function in SecurityTestResult but needed here"""
        if "cert_auth_security" in test_id or "test_ca_exchange" in test_id:
            return "Certificate Authentication"
        elif "hybrid_kex_security" in test_id:
            return "Hybrid Key Exchange"
        elif "double_ratchet_security" in test_id or "test_double_ratchet" in test_id:
            return "Double Ratchet Messaging"
        # ... similar to _get_test_component
        else:
            return "Other Security Tests"
    
    def print_summary(self):
        """Print a summary of the security test results to the console"""
        summary = self.report_data["summary"]
        
        print("\n" + "=" * 80)
        print(f"SECURITY TEST SUMMARY - {self.report_data['execution_date']}")
        print("=" * 80)
        print(f"Total Tests: {summary['total_tests']}")
        print(f"Passed: {summary['passed']} ({summary['pass_rate']:.1f}%)")
        print(f"Failed: {summary['failures'] + summary['errors']}")
        print(f"Skipped: {summary['skipped']}")
        print(f"Potential Vulnerabilities: {summary['potential_vulnerabilities']}")
        print(f"Anti-Debugging Protection: {'Enabled' if summary['anti_debugging_protection'] else 'Disabled for testing'}")
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
            html_filename = self.output_filename.replace('.json', '.html')
            print(f"HTML report saved to: {html_filename}")
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
    suite.addTests(loader.loadTestsFromModule(tests.test_dep_security))
    suite.addTests(loader.loadTestsFromModule(tests.test_chacha20poly1305_key_vulnerability))
    suite.addTests(loader.loadTestsFromModule(tests.test_traffic_analysis))
    suite.addTests(loader.loadTestsFromModule(tests.test_additional_security))
    
    # Add newly integrated test modules
    suite.addTests(loader.loadTestsFromModule(tests.test_attributes))
    suite.addTests(loader.loadTestsFromModule(tests.test_secure_connect))
    suite.addTests(loader.loadTestsFromModule(tests.test_double_ratchet))
    suite.addTests(loader.loadTestsFromModule(tests.test_ca_exchange))
    suite.addTests(loader.loadTestsFromModule(tests.test_server_startup))
    suite.addTests(loader.loadTestsFromModule(tests.test_military_grade_security))
    suite.addTests(loader.loadTestsFromModule(tests.test_dep_impl))
    suite.addTests(loader.loadTestsFromModule(tests.test_secure_memory))
    suite.addTests(loader.loadTestsFromModule(tests.test_secure_memory_app))
    suite.addTests(loader.loadTestsFromModule(tests.test_dep))
    
    return suite


def verify_test_modules():
    """Verify that all test modules can be imported without errors."""
    logger.info("Verifying test modules can be imported...")
    
    test_modules = [
        # Core security test modules
        'tests.test_cert_auth_security',
        'tests.test_hybrid_kex_security',
        'tests.test_double_ratchet_security',
        'tests.test_tls_channel_security',
        'tests.test_crypto_suite',
        'tests.test_padding',
        'tests.test_dep_security',
        'tests.test_chacha20poly1305_key_vulnerability',
        'tests.test_traffic_analysis',
        'tests.test_additional_security',
        
        # Additional integrated test modules
        'tests.test_attributes',
        'tests.test_secure_connect',
        'tests.test_double_ratchet',
        'tests.test_ca_exchange',
        'tests.test_server_startup',
        'tests.test_military_grade_security',
        'tests.test_dep_impl',
        'tests.test_secure_memory',
        'tests.test_secure_memory_app',
        'tests.test_dep'
    ]
    
    failed_modules = []
    for module_name in test_modules:
        try:
            importlib.import_module(module_name)
        except ImportError as e:
            logger.error(f"FAILED to import test module: {module_name}")
            logger.error(f"  Error: {e}")
            failed_modules.append(module_name)
    
    if failed_modules:
        logger.error("Test suite is broken. Cannot run tests.")
        return False
        
    logger.info("All test modules verified successfully.")
    return True


def run_security_tests(verbosity=1, output_file="security_report.json", skip_verification=False, disable_anti_debugging=False):
    """Run all security tests and generate a report"""
    
    # Set anti-debugging mode based on parameter
    if disable_anti_debugging:
        os.environ["DISABLE_ANTI_DEBUGGING"] = "true"
        print("Anti-debugging protection DISABLED for testing")
    else:
        os.environ["DISABLE_ANTI_DEBUGGING"] = "false"
        print("Anti-debugging protection ENABLED")
    
    # First, verify that the test modules can be imported
    if not skip_verification:
        if not verify_test_modules():
            sys.exit(1) # Exit if verification fails
            
    logger.info("Starting security test suite...")
    
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
    parser.add_argument("--skip-verification", action="store_true",
                        help="Skip the initial verification of test modules")
    parser.add_argument("--disable-anti-debugging", action="store_true",
                        help="Disable anti-debugging protection during tests")
    
    args = parser.parse_args()
    
    # Run tests
    run_security_tests(
        verbosity=args.verbosity, 
        output_file=args.output,
        skip_verification=args.skip_verification,
        disable_anti_debugging=args.disable_anti_debugging
    ) 