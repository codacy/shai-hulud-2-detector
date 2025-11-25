"""Load and parse the vulnerable packages CSV from Shai Hulud 2 vulnerability database."""

import csv
import ssl
import urllib.request
from typing import Dict, List, Set
from collections import defaultdict


VULNERABILITY_CSV_URL = (
    "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/"
    "refs/heads/main/reports/shai-hulud-2-packages.csv"
)


def fetch_vulnerability_data(url: str = VULNERABILITY_CSV_URL) -> str:
    """Fetch the vulnerability CSV data from the URL."""
    # Try requests first (preferred)
    try:
        import requests
        response = requests.get(url, verify=True, timeout=30)
        response.raise_for_status()
        return response.text
    except ImportError:
        # Fallback to urllib if requests not available
        pass
    except Exception:
        # If requests fails, try urllib with SSL context
        pass
    
    # Fallback to urllib with SSL context
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    with urllib.request.urlopen(url, context=ssl_context) as response:
        return response.read().decode('utf-8')


def parse_vulnerability_csv(csv_data: str) -> Dict[str, Set[str]]:
    """
    Parse the vulnerability CSV and build a lookup structure.
    
    Returns a dictionary mapping package names to sets of vulnerable version constraints.
    Version constraints can be like "= 1.2.3" or "= 1.2.3 || = 1.2.4"
    """
    vulnerabilities = defaultdict(set)
    
    lines = csv_data.strip().split('\n')
    reader = csv.DictReader(lines)
    
    for row in reader:
        package = row['Package'].strip()
        version_constraint = row['Version'].strip()
        
        if package and version_constraint:
            # Store the version constraint string as-is
            # It may contain "= 1.2.3" or "= 1.2.3 || = 1.2.4"
            vulnerabilities[package].add(version_constraint)
    
    return dict(vulnerabilities)


def load_vulnerabilities(url: str = VULNERABILITY_CSV_URL) -> Dict[str, Set[str]]:
    """Load vulnerabilities from the CSV URL and return the lookup dictionary."""
    csv_data = fetch_vulnerability_data(url)
    return parse_vulnerability_csv(csv_data)


def get_vulnerable_versions(package_name: str, vulnerabilities: Dict[str, Set[str]]) -> Set[str]:
    """Get the vulnerable version constraints for a given package name."""
    return vulnerabilities.get(package_name, set())

