"""Version matching logic for comparing package versions against vulnerability constraints."""

import re
from typing import List, Set
from packaging import version


def parse_version_constraint(constraint: str) -> List[str]:
    """
    Parse a version constraint string into individual version requirements.
    
    Examples:
    "= 1.2.3" -> ["= 1.2.3"]
    "= 1.2.3 || = 1.2.4" -> ["= 1.2.3", "= 1.2.4"]
    """
    # Split by || to handle OR conditions
    parts = [part.strip() for part in constraint.split('||')]
    return parts


def normalize_version(version_str: str) -> str:
    """
    Normalize a version string for comparison.
    Removes leading 'v', handles common version formats.
    """
    if not version_str:
        return ""
    
    # Remove leading 'v' if present
    version_str = version_str.lstrip('vV')
    
    # Remove any leading/trailing whitespace
    version_str = version_str.strip()
    
    return version_str


def extract_exact_version(constraint: str) -> str:
    """
    Extract the exact version from a constraint like "= 1.2.3".
    Returns empty string if not an exact match constraint.
    """
    match = re.match(r'=\s*(.+)', constraint.strip())
    if match:
        return normalize_version(match.group(1))
    return ""


def is_version_vulnerable(package_version: str, vulnerable_constraints: Set[str]) -> bool:
    """
    Check if a package version matches any of the vulnerable version constraints.
    
    Args:
        package_version: The version of the package to check (e.g., "1.2.3")
        vulnerable_constraints: Set of vulnerable version constraints (e.g., {"= 1.2.3", "= 1.2.4 || = 1.2.5"})
    
    Returns:
        True if the version matches any constraint, False otherwise
    """
    if not package_version or not vulnerable_constraints:
        return False
    
    normalized_pkg_version = normalize_version(package_version)
    
    if not normalized_pkg_version:
        return False
    
    # Try to parse as a version for comparison
    try:
        pkg_ver = version.parse(normalized_pkg_version)
    except version.InvalidVersion:
        # If we can't parse it, fall back to exact string matching
        for constraint in vulnerable_constraints:
            parts = parse_version_constraint(constraint)
            for part in parts:
                exact_ver = extract_exact_version(part)
                if exact_ver and normalized_pkg_version == exact_ver:
                    return True
        return False
    
    # Check each constraint
    for constraint in vulnerable_constraints:
        parts = parse_version_constraint(constraint)
        for part in parts:
            exact_ver = extract_exact_version(part)
            if exact_ver:
                try:
                    constraint_ver = version.parse(exact_ver)
                    # For exact matches, compare versions
                    if pkg_ver == constraint_ver:
                        return True
                except version.InvalidVersion:
                    # Fall back to string comparison
                    if normalized_pkg_version == exact_ver:
                        return True
    
    return False


def get_matching_constraints(package_version: str, vulnerable_constraints: Set[str]) -> List[str]:
    """
    Get all vulnerable constraints that match the package version.
    
    Returns a list of constraint strings that match.
    """
    matching = []
    
    if not package_version or not vulnerable_constraints:
        return matching
    
    normalized_pkg_version = normalize_version(package_version)
    
    if not normalized_pkg_version:
        return matching
    
    try:
        pkg_ver = version.parse(normalized_pkg_version)
    except version.InvalidVersion:
        # Fall back to exact string matching
        for constraint in vulnerable_constraints:
            parts = parse_version_constraint(constraint)
            for part in parts:
                exact_ver = extract_exact_version(part)
                if exact_ver and normalized_pkg_version == exact_ver:
                    matching.append(constraint)
                    break
        return matching
    
    # Check each constraint
    for constraint in vulnerable_constraints:
        parts = parse_version_constraint(constraint)
        for part in parts:
            exact_ver = extract_exact_version(part)
            if exact_ver:
                try:
                    constraint_ver = version.parse(exact_ver)
                    if pkg_ver == constraint_ver:
                        matching.append(constraint)
                        break
                except version.InvalidVersion:
                    if normalized_pkg_version == exact_ver:
                        matching.append(constraint)
                        break
    
    return matching

