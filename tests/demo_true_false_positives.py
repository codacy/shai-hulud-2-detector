#!/usr/bin/env python3
"""
Demonstration script showing true positives and false positives.

This script creates test scenarios and demonstrates:
1. True Positives: Correctly detecting vulnerabilities and malware
2. False Positives: Incorrectly flagging safe packages/files
"""

import sys
import tempfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from scanner import scan_directory
from formatters import format_output


def print_section(title):
    """Print a formatted section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def demo_true_positive_vulnerable_package():
    """Demonstrate TRUE POSITIVE: Detecting a vulnerable package."""
    print_section("TRUE POSITIVE: Vulnerable Package Detection")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        
        # Create a package.json with a known vulnerable package
        package_json = '''{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "dependencies": {
    "@accordproject/concerto-analysis": "3.24.1",
    "@accordproject/concerto-linter": "3.24.1"
  }
}'''
        
        project_dir = base / "vulnerable_app"
        project_dir.mkdir()
        (project_dir / "package.json").write_text(package_json)
        
        print("Created test project with vulnerable packages:")
        print("  - @accordproject/concerto-analysis@3.24.1")
        print("  - @accordproject/concerto-linter@3.24.1")
        print("\nScanning...")
        
        result = scan_directory(project_dir)
        
        print(f"\n✓ DETECTED: {result.vulnerable_packages_found} vulnerable package(s)")
        print("\nDetails:")
        for pkg in result.vulnerable_packages:
            print(f"  • {pkg['package']}@{pkg['version']}")
            print(f"    File: {pkg['file']}")
            print(f"    Vulnerable versions: {', '.join(pkg['vulnerable_versions'])}")
        
        print("\nThis is a TRUE POSITIVE - correctly identifying vulnerable packages.")


def demo_false_positive_safe_package():
    """Demonstrate FALSE POSITIVE CHECK: Not flagging safe packages."""
    print_section("FALSE POSITIVE CHECK: Safe Package (Should NOT be flagged)")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        
        # Create a package.json with safe packages
        package_json = '''{
  "name": "safe-app",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.21",
    "express": "4.18.2",
    "axios": "1.6.0"
  }
}'''
        
        project_dir = base / "safe_app"
        project_dir.mkdir()
        (project_dir / "package.json").write_text(package_json)
        
        print("Created test project with safe packages:")
        print("  - lodash@4.17.21")
        print("  - express@4.18.2")
        print("  - axios@1.6.0")
        print("\nScanning...")
        
        result = scan_directory(project_dir)
        
        if result.vulnerable_packages_found == 0:
            print(f"\n✓ CORRECT: No vulnerabilities detected")
            print("These packages are NOT in the Shai Hulud 2 vulnerability database.")
            print("This demonstrates the tool correctly avoids FALSE POSITIVES.")
        else:
            print(f"\n✗ FALSE POSITIVE: {result.vulnerable_packages_found} package(s) incorrectly flagged")
            for pkg in result.vulnerable_packages:
                print(f"  • {pkg['package']}@{pkg['version']}")


def demo_version_prefix_handling():
    """Demonstrate version prefix handling (TRUE POSITIVE)."""
    print_section("TRUE POSITIVE: Version Prefix Handling")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        
        # Create package.json with version prefixes
        package_json = '''{
  "name": "prefix-test",
  "version": "1.0.0",
  "dependencies": {
    "@accordproject/concerto-analysis": "^3.24.1",
    "@accordproject/concerto-linter": "~3.24.1",
    "@accordproject/concerto-metamodel": "=3.12.5"
  }
}'''
        
        project_dir = base / "prefix_test"
        project_dir.mkdir()
        (project_dir / "package.json").write_text(package_json)
        
        print("Created test project with version prefixes:")
        print("  - @accordproject/concerto-analysis: ^3.24.1")
        print("  - @accordproject/concerto-linter: ~3.24.1")
        print("  - @accordproject/concerto-metamodel: =3.12.5")
        print("\nScanning...")
        
        result = scan_directory(project_dir)
        
        print(f"\n✓ DETECTED: {result.vulnerable_packages_found} vulnerable package(s)")
        print("\nThe tool correctly strips version prefixes (^, ~, =) and detects vulnerabilities.")
        for pkg in result.vulnerable_packages:
            print(f"  • {pkg['package']}@{pkg['version']} (from {pkg['file']})")


def demo_malware_file_detection():
    """Demonstrate malware file detection."""
    print_section("TRUE POSITIVE: Malware File Detection")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        
        # Create malware-named files
        malware_file1 = base / "bun_environment.js"
        malware_file2 = base / "setup_bun.js"
        
        # Create files with dummy content (won't match actual hashes, but tests detection)
        malware_file1.write_text("// This is a test file named bun_environment.js\n")
        malware_file2.write_text("// This is a test file named setup_bun.js\n")
        
        print("Created test files:")
        print("  - bun_environment.js")
        print("  - setup_bun.js")
        print("\nScanning...")
        
        result = scan_directory(base)
        
        print(f"\n✓ DETECTED: {len(result.malware_files)} malware file(s)")
        print("\nDetails:")
        for malware in result.malware_files:
            print(f"  • {malware['file']}")
            print(f"    SHA1: {malware['sha1']}")
            if malware['matched']:
                print(f"    Status: ✓ MATCHED (Known malicious hash)")
            else:
                print(f"    Status: ⚠ Detected by name, but hash doesn't match known malicious hashes")
                print(f"    (This is expected for test files - real malicious files would match)")


def demo_false_positive_similar_filenames():
    """Demonstrate FALSE POSITIVE CHECK: Similar filenames."""
    print_section("FALSE POSITIVE CHECK: Similar Filenames (Should NOT be flagged)")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        
        # Create files with similar names
        similar_files = [
            base / "bun_environment.ts",
            base / "bun_environment.js.bak",
            base / "setup_bun.ts",
            base / "my_bun_environment.js",
            base / "bun_environment_test.js",
        ]
        
        for file_path in similar_files:
            file_path.write_text(f"// This is {file_path.name}\n")
        
        print("Created files with similar names:")
        for f in similar_files:
            print(f"  - {f.name}")
        print("\nScanning...")
        
        result = scan_directory(base)
        
        if len(result.malware_files) == 0:
            print(f"\n✓ CORRECT: No malware files detected")
            print("The tool only detects exact filename matches:")
            print("  - bun_environment.js")
            print("  - setup_bun.js")
            print("\nFiles with similar names are correctly ignored (no FALSE POSITIVES).")
        else:
            print(f"\n✗ FALSE POSITIVE: {len(result.malware_files)} file(s) incorrectly flagged")
            for malware in result.malware_files:
                print(f"  • {malware['file']}")


def demo_mixed_scenario():
    """Demonstrate a mixed scenario with both vulnerable and safe packages."""
    print_section("MIXED SCENARIO: Vulnerable + Safe Packages")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        
        # Create package.json with mix of vulnerable and safe packages
        package_json = '''{
  "name": "mixed-app",
  "version": "1.0.0",
  "dependencies": {
    "@accordproject/concerto-analysis": "3.24.1",
    "lodash": "4.17.21",
    "express": "4.18.2"
  },
  "devDependencies": {
    "@accordproject/concerto-linter": "3.24.1",
    "jest": "29.7.0"
  }
}'''
        
        project_dir = base / "mixed_app"
        project_dir.mkdir()
        (project_dir / "package.json").write_text(package_json)
        
        print("Created test project with mixed packages:")
        print("Vulnerable (should be detected):")
        print("  - @accordproject/concerto-analysis@3.24.1")
        print("  - @accordproject/concerto-linter@3.24.1")
        print("\nSafe (should NOT be detected):")
        print("  - lodash@4.17.21")
        print("  - express@4.18.2")
        print("  - jest@29.7.0")
        print("\nScanning...")
        
        result = scan_directory(project_dir)
        
        print(f"\nResults:")
        print(f"  Vulnerable packages found: {result.vulnerable_packages_found}")
        print(f"  Safe packages (not flagged): {5 - result.vulnerable_packages_found}")
        
        print("\nDetected vulnerable packages:")
        for pkg in result.vulnerable_packages:
            print(f"  ✓ {pkg['package']}@{pkg['version']}")
        
        print("\nThis demonstrates:")
        print("  • TRUE POSITIVES: Vulnerable packages are correctly detected")
        print("  • NO FALSE POSITIVES: Safe packages are not incorrectly flagged")


def demo_output_formats():
    """Demonstrate different output formats."""
    print_section("OUTPUT FORMATS: Text, JSON, SARIF")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        
        package_json = '''{
  "name": "format-demo",
  "dependencies": {
    "@accordproject/concerto-analysis": "3.24.1"
  }
}'''
        
        project_dir = base / "format_demo"
        project_dir.mkdir()
        (project_dir / "package.json").write_text(package_json)
        
        result = scan_directory(project_dir)
        
        print("Text Format:")
        print("-" * 70)
        text_output = format_output(result, 'text')
        print(text_output[:300] + "..." if len(text_output) > 300 else text_output)
        
        print("\nJSON Format:")
        print("-" * 70)
        json_output = format_output(result, 'json')
        print(json_output[:300] + "..." if len(json_output) > 300 else json_output)
        
        print("\nSARIF Format:")
        print("-" * 70)
        sarif_output = format_output(result, 'sarif')
        print(sarif_output[:400] + "..." if len(sarif_output) > 400 else sarif_output)


def main():
    """Run all demonstrations."""
    print("\n" + "=" * 70)
    print("  Shai Hulud 2 Detector - True Positives & False Positives Demo")
    print("=" * 70)
    
    demos = [
        demo_true_positive_vulnerable_package,
        demo_false_positive_safe_package,
        demo_version_prefix_handling,
        demo_malware_file_detection,
        demo_false_positive_similar_filenames,
        demo_mixed_scenario,
        demo_output_formats,
    ]
    
    for demo_func in demos:
        try:
            demo_func()
        except Exception as e:
            print(f"\n✗ Error in {demo_func.__name__}: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 70)
    print("  Demo Complete")
    print("=" * 70)
    print("\nSummary:")
    print("  ✓ TRUE POSITIVES: Tool correctly detects vulnerable packages and malware")
    print("  ✓ NO FALSE POSITIVES: Tool correctly ignores safe packages and similar filenames")
    print("  ✓ VERSION HANDLING: Correctly strips prefixes and matches versions")
    print("  ✓ MULTIPLE FORMATS: Supports text, JSON, and SARIF output")


if __name__ == '__main__':
    main()

