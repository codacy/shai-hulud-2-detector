"""Parse npm/yarn package files: package.json, package-lock.json, yarn.lock."""

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional


def parse_package_json(file_path: Path) -> List[Tuple[str, str, Optional[int]]]:
    """
    Parse package.json and extract all dependencies.
    
    Returns a list of tuples: (package_name, version, line_number)
    Line numbers are approximate based on JSON structure.
    """
    dependencies = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            data = json.loads(content)
        
        # Read lines for approximate line number calculation
        lines = content.split('\n')
        
        # Check dependencies, devDependencies, optionalDependencies, peerDependencies
        dep_sections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']
        
        for section in dep_sections:
            if section in data and isinstance(data[section], dict):
                for pkg_name, pkg_version in data[section].items():
                    # Strip version prefixes like ^, ~, >=, etc. for exact version matching
                    # We'll keep the original for display but extract clean version
                    clean_version = strip_version_prefix(pkg_version)
                    # Find approximate line number
                    line_num = find_line_number(lines, f'"{pkg_name}"', section)
                    dependencies.append((pkg_name, clean_version, line_num))
    
    except (json.JSONDecodeError, IOError) as e:
        # Return empty list on parse errors
        pass
    
    return dependencies


def strip_version_prefix(version_str: str) -> str:
    """Strip version prefixes like ^, ~, >=, <=, >, <, =, etc."""
    if not version_str:
        return ""
    
    version_str = version_str.strip()
    
    # Remove common prefixes
    prefixes = ['^', '~', '>=', '<=', '>', '<', '=']
    for prefix in prefixes:
        if version_str.startswith(prefix):
            version_str = version_str[len(prefix):].strip()
    
    # Remove 'v' prefix if present
    if version_str.startswith('v') or version_str.startswith('V'):
        version_str = version_str[1:]
    
    return version_str.strip()


def find_line_number(lines: List[str], search_text: str, section: str) -> Optional[int]:
    """Find the approximate line number for a dependency."""
    in_section = False
    for i, line in enumerate(lines, 1):
        if f'"{section}"' in line or f"'{section}'" in line:
            in_section = True
        elif in_section and search_text in line:
            return i
        elif in_section and line.strip().startswith('}'):
            break
    return None


def parse_package_lock_json(file_path: Path) -> List[Tuple[str, str, Optional[int]]]:
    """
    Parse package-lock.json and extract all dependencies.
    
    Returns a list of tuples: (package_name, version, line_number)
    """
    dependencies = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            data = json.loads(content)
        
        lines = content.split('\n')
        
        # Check packages field (npm v7+)
        if 'packages' in data and isinstance(data['packages'], dict):
            for pkg_path, pkg_data in data['packages'].items():
                if isinstance(pkg_data, dict) and 'version' in pkg_data:
                    # Extract package name from path
                    # Empty string means root package, skip it
                    if pkg_path:
                        # Convert path to package name
                        # e.g., "node_modules/@scope/pkg" -> "@scope/pkg"
                        pkg_name = pkg_path.replace('node_modules/', '').strip('/')
                        if pkg_name:
                            version = pkg_data['version']
                            line_num = find_line_number(lines, f'"{pkg_path}"', 'packages')
                            dependencies.append((pkg_name, version, line_num))
        
        # Also check dependencies field (npm v6 and earlier)
        if 'dependencies' in data and isinstance(data['dependencies'], dict):
            extract_nested_deps(data['dependencies'], dependencies, lines, 'dependencies')
    
    except (json.JSONDecodeError, IOError) as e:
        pass
    
    return dependencies


def extract_nested_deps(deps: dict, result: List[Tuple[str, str, Optional[int]]], 
                       lines: List[str], prefix: str, visited: Optional[set] = None):
    """Recursively extract nested dependencies from package-lock.json."""
    if visited is None:
        visited = set()
    
    for pkg_name, pkg_data in deps.items():
        if not isinstance(pkg_data, dict):
            continue
        
        if 'version' in pkg_data:
            version = pkg_data['version']
            # Avoid duplicates
            key = (pkg_name, version)
            if key not in visited:
                visited.add(key)
                line_num = find_line_number(lines, f'"{pkg_name}"', prefix)
                result.append((pkg_name, version, line_num))
        
        # Recursively check dependencies
        if 'dependencies' in pkg_data and isinstance(pkg_data['dependencies'], dict):
            extract_nested_deps(pkg_data['dependencies'], result, lines, prefix, visited)


def parse_yarn_lock(file_path: Path) -> List[Tuple[str, str, Optional[int]]]:
    """
    Parse yarn.lock and extract all dependencies.
    
    Returns a list of tuples: (package_name, version, line_number)
    """
    dependencies = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        current_package = None
        current_version = None
        current_line = None
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Package entry starts with package name and version in quotes
            # Format: "package-name@version", "package-name@^version", etc.
            if stripped.startswith('"') and '@' in stripped:
                # Extract package name and version
                match = re.match(r'"([^"@]+)@([^"]+)"', stripped)
                if match:
                    pkg_name = match.group(1)
                    version_spec = match.group(2)
                    current_package = pkg_name
                    current_line = i
                    # Continue to find the actual version
                    current_version = None
            
            # Version field
            elif stripped.startswith('version') and current_package:
                version_match = re.search(r'version\s+"([^"]+)"', stripped)
                if version_match:
                    current_version = version_match.group(1)
                    if current_package and current_version:
                        dependencies.append((current_package, current_version, current_line))
                        current_package = None
                        current_version = None
                        current_line = None
            
            # Reset on empty line or new entry
            elif not stripped and current_package:
                current_package = None
                current_version = None
                current_line = None
    
    except IOError:
        pass
    
    return dependencies


def parse_npm_file(file_path: Path) -> List[Tuple[str, str, Optional[int]]]:
    """
    Automatically detect and parse the appropriate npm/yarn file.
    
    Returns a list of tuples: (package_name, version, line_number)
    """
    filename = file_path.name.lower()
    
    if filename == 'package.json':
        return parse_package_json(file_path)
    elif filename == 'package-lock.json':
        return parse_package_lock_json(file_path)
    elif filename == 'yarn.lock':
        return parse_yarn_lock(file_path)
    else:
        return []

