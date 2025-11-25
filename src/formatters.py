"""Output formatters for text, JSON, and SARIF formats."""

import json
from typing import Dict, List, Any
from datetime import datetime

from scanner import ScanResult


def format_text(result: ScanResult) -> str:
    """Format scan results as human-readable text."""
    output = []
    
    total_vuln = result.vulnerable_packages_found
    total_malware = result.malware_files_found
    
    if total_vuln == 0 and total_malware == 0:
        output.append("No vulnerabilities or malware files found.")
        return "\n".join(output)
    
    output.append(f"Found {total_vuln} vulnerable package(s) and {total_malware} malware file(s):\n")
    
    if result.vulnerable_packages:
        output.append("Vulnerable Packages:")
        for i, pkg in enumerate(result.vulnerable_packages, 1):
            file_path = pkg['file']
            package = pkg['package']
            version = pkg['version']
            vuln_versions = ', '.join(pkg['vulnerable_versions'])
            line_info = f":{pkg['line']}" if pkg.get('line') else ""
            
            output.append(f"{i}. {file_path}{line_info}")
            output.append(f"   {package}@{version} (vulnerable version(s): {vuln_versions})")
            output.append("")
    
    if result.malware_files:
        output.append("Malware Files:")
        for i, malware in enumerate(result.malware_files, 1):
            file_path = malware['file']
            sha1 = malware['sha1']
            matched = malware['matched']
            status = "MATCH" if matched else "NO MATCH"
            
            output.append(f"{i}. {file_path}")
            output.append(f"   SHA1: {sha1} ({status})")
            output.append("")
    
    return "\n".join(output)


def format_json(result: ScanResult) -> str:
    """Format scan results as JSON."""
    output = {
        "vulnerable_packages_found": result.vulnerable_packages_found,
        "malware_files_found": result.malware_files_found,
        "vulnerable_packages": result.vulnerable_packages,
        "malware_files": result.malware_files
    }
    return json.dumps(output, indent=2)


def format_sarif(result: ScanResult, tool_version: str = "1.0.0") -> str:
    """Format scan results as SARIF 2.1.0."""
    
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Shai Hulud 2 Detector",
                        "version": tool_version,
                        "informationUri": "https://github.com/wiz-sec-public/wiz-research-iocs",
                        "rules": [
                            {
                                "id": "SH2-VULN-PKG",
                                "name": "Shai Hulud 2 Vulnerable Package",
                                "shortDescription": {
                                    "text": "Package version matches Shai Hulud 2 vulnerability database"
                                },
                                "fullDescription": {
                                    "text": "The package version installed matches a known vulnerable version from the Shai Hulud 2 vulnerability database."
                                },
                                "defaultConfiguration": {
                                    "level": "error"
                                },
                                "help": {
                                    "text": "Update the package to a non-vulnerable version or remove it if not needed."
                                },
                                "helpUri": "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv"
                            },
                            {
                                "id": "SH2-MALWARE",
                                "name": "Shai Hulud 2 Malware File",
                                "shortDescription": {
                                    "text": "Malware file detected with known malicious SHA1 hash"
                                },
                                "fullDescription": {
                                    "text": "A file matching known malware from the Shai Hulud 2 attack has been detected. Files include bun_environment.js and setup_bun.js with specific SHA1 hashes."
                                },
                                "defaultConfiguration": {
                                    "level": "error"
                                },
                                "help": {
                                    "text": "Remove the malicious file immediately and investigate how it was introduced into the codebase."
                                }
                            }
                        ]
                    }
                },
                "results": [],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "exitCode": 0 if (result.vulnerable_packages_found == 0 and result.malware_files_found == 0) else 1
                    }
                ]
            }
        ]
    }
    
    # Add vulnerable package results
    for pkg in result.vulnerable_packages:
        result_obj = {
            "ruleId": "SH2-VULN-PKG",
            "level": "error",
            "message": {
                "text": f"Vulnerable package {pkg['package']}@{pkg['version']} detected. Vulnerable versions: {', '.join(pkg['vulnerable_versions'])}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": pkg['file']
                        },
                        "region": {}
                    },
                    "logicalLocations": [
                        {
                            "name": pkg['package'],
                            "kind": "package"
                        }
                    ]
                }
            ],
            "properties": {
                "package": pkg['package'],
                "version": pkg['version'],
                "vulnerable_versions": pkg['vulnerable_versions']
            }
        }
        
        # Add line number if available
        if pkg.get('line'):
            result_obj["locations"][0]["physicalLocation"]["region"] = {
                "startLine": pkg['line']
            }
        
        sarif["runs"][0]["results"].append(result_obj)
    
    # Add malware file results
    for malware in result.malware_files:
        if malware['matched']:
            result_obj = {
                "ruleId": "SH2-MALWARE",
                "level": "error",
                "message": {
                    "text": f"Malware file detected: {malware['file']} (SHA1: {malware['sha1']})"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": malware['file']
                            }
                        }
                    }
                ],
                "properties": {
                    "sha1": malware['sha1'],
                    "file": malware['file']
                }
            }
            
            sarif["runs"][0]["results"].append(result_obj)
    
    return json.dumps(sarif, indent=2)


def format_output(result: ScanResult, format_type: str, tool_version: str = "1.0.0") -> str:
    """
    Format scan results according to the specified format.
    
    Args:
        result: ScanResult object
        format_type: One of 'text', 'json', 'sarif'
        tool_version: Tool version for SARIF format
    
    Returns:
        Formatted output string
    """
    if format_type == 'text':
        return format_text(result)
    elif format_type == 'json':
        return format_json(result)
    elif format_type == 'sarif':
        return format_sarif(result, tool_version)
    else:
        raise ValueError(f"Unknown format type: {format_type}")

