"""Load and parse the vulnerable packages CSV from Shai Hulud 2 vulnerability database."""

import csv
import ssl
import urllib.request
from pathlib import Path
from typing import Dict, List, Set, Optional
from collections import defaultdict


VULNERABILITY_CSV_URL = (
    "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/"
    "refs/heads/main/reports/shai-hulud-2-packages.csv"
)

# Default CSV filename in the root directory
DEFAULT_CSV_FILENAME = "shai-hulud-2-packages.csv"


def find_csv_file() -> Optional[Path]:
    """
    Find the CSV file in the project root directory.
    Looks for shai-hulud-2-packages.csv in the root directory.
    """
    # Get the root directory (parent of src directory)
    current_file = Path(__file__).resolve()
    root_dir = current_file.parent.parent
    
    csv_file = root_dir / DEFAULT_CSV_FILENAME
    
    if csv_file.exists() and csv_file.is_file():
        return csv_file
    
    return None


def read_local_csv_file(csv_path: Path) -> str:
    """Read the CSV file from the local filesystem."""
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            return f.read()
    except (IOError, OSError) as e:
        raise FileNotFoundError(f"Could not read CSV file {csv_path}: {e}")


def fetch_vulnerability_data(url: str = VULNERABILITY_CSV_URL) -> str:
    """Fetch the vulnerability CSV data from the URL (fallback only)."""
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


def load_vulnerabilities(csv_path: Optional[Path] = None, 
                         url: Optional[str] = None) -> Dict[str, Set[str]]:
    """
    Load vulnerabilities from a local CSV file or URL.
    
    Priority:
    1. Use csv_path if provided
    2. Look for shai-hulud-2-packages.csv in the root directory
    3. Fall back to downloading from URL if local file not found
    
    Args:
        csv_path: Optional path to CSV file. If None, looks for default file in root.
        url: Optional URL to fetch from if local file not found. Defaults to VULNERABILITY_CSV_URL.
    
    Returns:
        Dictionary mapping package names to sets of vulnerable version constraints.
    """
    # Try to use provided path or find local file
    if csv_path is None:
        csv_path = find_csv_file()
    
    if csv_path and csv_path.exists():
        try:
            csv_data = read_local_csv_file(csv_path)
            return parse_vulnerability_csv(csv_data)
        except Exception as e:
            # If reading local file fails, fall back to URL
            pass
    
    # Fall back to downloading from URL if local file not found or read failed
    if url is None:
        url = VULNERABILITY_CSV_URL
    
    csv_data = fetch_vulnerability_data(url)
    return parse_vulnerability_csv(csv_data)


def get_vulnerable_versions(package_name: str, vulnerabilities: Dict[str, Set[str]]) -> Set[str]:
    """Get the vulnerable version constraints for a given package name."""
    return vulnerabilities.get(package_name, set())

