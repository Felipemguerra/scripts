from abc import ABC, abstractmethod
import json
from datetime import datetime
from typing import Dict, Any

class TestSuite(ABC):
    
    def __init__(self, name: str):
        self.name = name
        self.results = []

    @abstractmethod
    def run_tests(self, url: str, port: int) -> None:
        # Run all tests in the suite
        pass

    def get_results(self) -> list:
        # Return test results as json array
        return self.results

class SimpleTestSuite(TestSuite):
    
    def run_tests(self, url: str, port: int) -> None:
        # Example implementation
        self.results = [
            {"test": "connectivity", "status": "passed", "timestamp": str(datetime.now())},
            {"test": "response_time", "status": "passed", "timestamp": str(datetime.now())}
        ]

class AdvancedTestSuite(TestSuite):
    
    def run_tests(self, url: str, port: int) -> None:
        # Example implementation
        self.results = [
            {"test": "ssl_check", "status": "passed", "timestamp": str(datetime.now())},
            {"test": "vulnerability_scan", "status": "warning", "timestamp": str(datetime.now())}
        ]

class Application:
    """Class representing an application to be tested"""
    
    def __init__(self, name: str, description: str, agency: str, url: str, 
                 port: int, test_suite: TestSuite):
        self.name = name
        self.description = description
        self.agency = agency
        self.url = url
        self.port = port
        self.test_suite = test_suite
        self.test_results = []

    def run_tests(self) -> None:
        """Execute the test suite"""
        self.test_suite.run_tests(self.url, self.port)
        self.test_results = self.test_suite.get_results()

    def get_json_results(self) -> str:
        """Return test results in JSON format"""
        output = {
            "application": {
                "name": self.name,
                "description": self.description,
                "agency": self.agency,
                "url": self.url,
                "port": self.port,
                "test_suite": self.test_suite.name,
                "results": self.test_results
            }
        }
        return json.dumps(output, indent=2)

# Example usage:
if __name__ == "__main__":
    # Create a test suite
    security_suite = SecurityTestSuite("Security Test Suite")
    
    # Create an application
    app = Application(
        name="MyApp",
        description="Test Application",
        agency="Test Agency",
        url="https://example.com",
        port=443,
        test_suite=security_suite
    )
    
    # Run tests and get results
    app.run_tests()
    print(app.get_json_results())