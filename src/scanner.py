"""Main scanning logic for detecting vulnerable packages and malware."""

from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict

from vulnerabilities import load_vulnerabilities, get_vulnerable_versions
from version_matcher import is_version_vulnerable, get_matching_constraints
from npm_parser import parse_npm_file
from malware_detector import scan_for_malware_files, is_malware_file, check_file_hash


# Common ignore patterns
DEFAULT_IGNORE_PATTERNS = [
    '.git',
    'node_modules',
    '.next',
    'dist',
    'build',
    '.cache',
    '.venv',
    'venv',
    '__pycache__',
    '.pytest_cache',
    '.idea',
    '.vscode',
]


class ScanResult:
    """Container for scan results."""
    
    def __init__(self):
        self.vulnerable_packages: List[Dict] = []
        self.malware_files: List[Dict] = []
    
    def add_vulnerable_package(self, file_path: str, package: str, version: str, 
                              vulnerable_versions: List[str], line: Optional[int] = None):
        """Add a vulnerable package finding."""
        self.vulnerable_packages.append({
            'file': file_path,
            'package': package,
            'version': version,
            'vulnerable_versions': vulnerable_versions,
            'line': line
        })
    
    def add_malware_file(self, file_path: str, sha1: str, matched: bool):
        """Add a malware file finding."""
        self.malware_files.append({
            'file': file_path,
            'sha1': sha1,
            'matched': matched
        })
    
    @property
    def vulnerable_packages_found(self) -> int:
        return len(self.vulnerable_packages)
    
    @property
    def malware_files_found(self) -> int:
        return len([m for m in self.malware_files if m['matched']])


def should_ignore_path(path: Path, ignore_patterns: List[str]) -> bool:
    """Check if a path should be ignored."""
    path_str = str(path)
    for pattern in ignore_patterns:
        if pattern in path_str:
            return True
    return False


def scan_directory(directory: Path, 
                   vulnerabilities: Optional[Dict[str, Set[str]]] = None,
                   ignore_patterns: Optional[List[str]] = None,
                   verbose: bool = False) -> ScanResult:
    """
    Scan a directory for vulnerable packages and malware files.
    
    Args:
        directory: Directory to scan
        vulnerabilities: Pre-loaded vulnerability data (will load if None)
        ignore_patterns: Additional ignore patterns beyond defaults
        verbose: Enable verbose output
    
    Returns:
        ScanResult object with findings
    """
    result = ScanResult()
    
    # Load vulnerabilities if not provided
    if vulnerabilities is None:
        try:
            vulnerabilities = load_vulnerabilities()
        except Exception as e:
            if verbose:
                print(f"Warning: Could not load vulnerabilities: {e}")
            vulnerabilities = {}
    
    # Combine ignore patterns
    all_ignore_patterns = DEFAULT_IGNORE_PATTERNS.copy()
    if ignore_patterns:
        all_ignore_patterns.extend(ignore_patterns)
    
    # Scan for package files
    package_files = ['package.json', 'package-lock.json', 'yarn.lock']
    
    def scan_recursive(dir_path: Path):
        """Recursively scan directory."""
        try:
            for item in dir_path.iterdir():
                if should_ignore_path(item, all_ignore_patterns):
                    continue
                
                if item.is_file():
                    # Check if it's a package file
                    if item.name in package_files:
                        try:
                            dependencies = parse_npm_file(item)
                            for pkg_name, pkg_version, line_num in dependencies:
                                # Check if this package is vulnerable
                                vulnerable_versions = get_vulnerable_versions(pkg_name, vulnerabilities)
                                if vulnerable_versions:
                                    # Check if the version matches
                                    if is_version_vulnerable(pkg_version, vulnerable_versions):
                                        matching_constraints = get_matching_constraints(
                                            pkg_version, vulnerable_versions
                                        )
                                        result.add_vulnerable_package(
                                            str(item.relative_to(directory)),
                                            pkg_name,
                                            pkg_version,
                                            matching_constraints,
                                            line_num
                                        )
                        except Exception as e:
                            if verbose:
                                print(f"Warning: Error parsing {item}: {e}")
                    
                    # Check if it's a malware file
                    elif is_malware_file(item):
                        is_malware, sha1_hash = check_file_hash(item)
                        result.add_malware_file(
                            str(item.relative_to(directory)),
                            sha1_hash,
                            is_malware
                        )
                
                elif item.is_dir():
                    scan_recursive(item)
        
        except (PermissionError, OSError) as e:
            if verbose:
                print(f"Warning: Could not access {dir_path}: {e}")
    
    scan_recursive(directory)
    
    return result

