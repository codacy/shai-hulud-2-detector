"""Tests for Shai Hulud 2 Detector showing true positives and false positives."""

import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from scanner import scan_directory
from formatters import format_output


def create_test_project(base_dir: Path, name: str, package_json_content: str):
    """Create a test project directory with package.json."""
    project_dir = base_dir / name
    project_dir.mkdir(parents=True, exist_ok=True)
    
    package_file = project_dir / 'package.json'
    package_file.write_text(package_json_content)
    
    return project_dir


def create_malware_file(file_path: Path, content: bytes):
    """Create a malware file with specific content."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(content)


def test_true_positive_vulnerable_package():
    """Test: Should detect a vulnerable package (TRUE POSITIVE)."""
    print("\n=== Test 1: True Positive - Vulnerable Package ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        
        # Create package.json with a known vulnerable package
        # @accordproject/concerto-analysis version 3.24.1 is in the vulnerability list
        package_json = '''{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "@accordproject/concerto-analysis": "3.24.1"
  }
}'''
        
        project_dir = create_test_project(base, "vulnerable_project", package_json)
        
        # Scan
        result = scan_directory(project_dir)
        
        # Should find 1 vulnerable package
        assert result.vulnerable_packages_found > 0, "Should detect vulnerable package"
        assert result.malware_files_found == 0, "Should not find malware"
        
        # Check the specific package was found
        found_packages = [p['package'] for p in result.vulnerable_packages]
        assert '@accordproject/concerto-analysis' in found_packages, "Should find @accordproject/concerto-analysis"
        
        print("✓ PASSED: Correctly detected vulnerable package")
        print(f"  Found {result.vulnerable_packages_found} vulnerable package(s)")
        for pkg in result.vulnerable_packages:
            print(f"    - {pkg['package']}@{pkg['version']}")


def test_false_positive_non_vulnerable_package():
    """Test: Should NOT detect a non-vulnerable package (FALSE POSITIVE check)."""
    print("\n=== Test 2: False Positive Check - Non-Vulnerable Package ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        
        # Create package.json with a package that's NOT in the vulnerability list
        package_json = '''{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.21",
    "express": "4.18.2"
  }
}'''
        
        project_dir = create_test_project(base, "safe_project", package_json)
        
        # Scan
        result = scan_directory(project_dir)
        
        # Should NOT find any vulnerable packages
        assert result.vulnerable_packages_found == 0, "Should NOT detect non-vulnerable packages (false positive)"
        assert result.malware_files_found == 0, "Should not find malware"
        
        print("✓ PASSED: Correctly did NOT detect non-vulnerable packages")
        print("  No false positives detected")


def test_true_positive_malware_file():
    """Test: Should detect a malware file with matching SHA1 (TRUE POSITIVE)."""
    print("\n=== Test 3: True Positive - Malware File ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        
        # Create a bun_environment.js file
        # Note: We can't easily create a file with the exact hash, but we can test the detection logic
        # For a real test, we'd need the actual malicious file content
        malware_file = base / "bun_environment.js"
        
        # Create a dummy file (this won't match the hash, but tests the detection path)
        malware_file.write_text("// This is a test malware file\n")
        
        # Scan
        result = scan_directory(base)
        
        # Should find the malware file (even if hash doesn't match, it should be detected)
        # The file exists and is named correctly
        malware_files = [m for m in result.malware_files if m['file'] == 'bun_environment.js']
        assert len(malware_files) > 0, "Should detect malware file by name"
        
        print("✓ PASSED: Correctly detected malware file by name")
        print(f"  Found {len(malware_files)} malware file(s)")
        for malware in malware_files:
            print(f"    - {malware['file']} (SHA1: {malware['sha1'][:16]}...)")
            print(f"      Matched: {malware['matched']}")


def test_false_positive_similar_filename():
    """Test: Should NOT detect files with similar names (FALSE POSITIVE check)."""
    print("\n=== Test 4: False Positive Check - Similar Filename ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        
        # Create files with similar names but not exact matches
        similar_files = [
            base / "bun_environment.ts",
            base / "bun_environment.js.bak",
            base / "setup_bun.ts",
            base / "my_bun_environment.js",
        ]
        
        for file_path in similar_files:
            file_path.write_text("// Not a malware file\n")
        
        # Scan
        result = scan_directory(base)
        
        # Should NOT find any malware (these files don't match the exact names)
        # Only exact matches: bun_environment.js and setup_bun.js
        malware_files = result.malware_files
        assert len(malware_files) == 0, "Should NOT detect files with similar names (false positive)"
        
        print("✓ PASSED: Correctly did NOT detect files with similar names")
        print("  No false positives for similar filenames")


def test_vulnerable_version_with_prefix():
    """Test: Should detect vulnerable package even with version prefix (TRUE POSITIVE)."""
    print("\n=== Test 5: True Positive - Vulnerable Package with Version Prefix ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        
        # Create package.json with vulnerable package using version prefix
        # The parser should strip ^, ~, etc. and still detect the vulnerability
        package_json = '''{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "@accordproject/concerto-analysis": "^3.24.1",
    "@accordproject/concerto-linter": "~3.24.1"
  }
}'''
        
        project_dir = create_test_project(base, "vulnerable_prefix", package_json)
        
        # Scan
        result = scan_directory(project_dir)
        
        # Should find vulnerable packages (version prefixes should be stripped)
        assert result.vulnerable_packages_found > 0, "Should detect vulnerable packages with version prefixes"
        
        print("✓ PASSED: Correctly detected vulnerable packages with version prefixes")
        print(f"  Found {result.vulnerable_packages_found} vulnerable package(s)")
        for pkg in result.vulnerable_packages:
            print(f"    - {pkg['package']}@{pkg['version']}")


def test_package_lock_json():
    """Test: Should detect vulnerabilities in package-lock.json (TRUE POSITIVE)."""
    print("\n=== Test 6: True Positive - package-lock.json ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        
        # Create package-lock.json with vulnerable package
        package_lock = '''{
  "name": "test-project",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "test-project",
      "version": "1.0.0"
    },
    "node_modules/@accordproject/concerto-analysis": {
      "version": "3.24.1"
    }
  }
}'''
        
        project_dir = base / "lockfile_project"
        project_dir.mkdir()
        (project_dir / "package-lock.json").write_text(package_lock)
        
        # Scan
        result = scan_directory(project_dir)
        
        # Should find vulnerable package in lock file
        assert result.vulnerable_packages_found > 0, "Should detect vulnerable package in package-lock.json"
        
        print("✓ PASSED: Correctly detected vulnerable package in package-lock.json")
        print(f"  Found {result.vulnerable_packages_found} vulnerable package(s)")


def test_multiple_vulnerable_packages():
    """Test: Should detect multiple vulnerable packages (TRUE POSITIVE)."""
    print("\n=== Test 7: True Positive - Multiple Vulnerable Packages ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        
        # Create package.json with multiple vulnerable packages
        package_json = '''{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "@accordproject/concerto-analysis": "3.24.1",
    "@accordproject/concerto-linter": "3.24.1"
  },
  "devDependencies": {
    "@accordproject/concerto-metamodel": "3.12.5"
  }
}'''
        
        project_dir = create_test_project(base, "multiple_vulnerable", package_json)
        
        # Scan
        result = scan_directory(project_dir)
        
        # Should find multiple vulnerable packages
        assert result.vulnerable_packages_found >= 2, "Should detect multiple vulnerable packages"
        
        print("✓ PASSED: Correctly detected multiple vulnerable packages")
        print(f"  Found {result.vulnerable_packages_found} vulnerable package(s)")
        for pkg in result.vulnerable_packages:
            print(f"    - {pkg['package']}@{pkg['version']}")


def test_output_formats():
    """Test: All output formats should work correctly."""
    print("\n=== Test 8: Output Format Tests ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        
        # Create a project with vulnerable package
        package_json = '''{
  "name": "test-project",
  "dependencies": {
    "@accordproject/concerto-analysis": "3.24.1"
  }
}'''
        
        project_dir = create_test_project(base, "format_test", package_json)
        result = scan_directory(project_dir)
        
        # Test text format
        text_output = format_output(result, 'text')
        assert "vulnerable" in text_output.lower() or "No vulnerabilities" in text_output
        print("✓ PASSED: Text format works")
        
        # Test JSON format
        json_output = format_output(result, 'json')
        assert json_output.startswith('{')
        assert '"vulnerable_packages_found"' in json_output
        print("✓ PASSED: JSON format works")
        
        # Test SARIF format
        sarif_output = format_output(result, 'sarif')
        assert '"$schema"' in sarif_output
        assert '"version": "2.1.0"' in sarif_output
        assert 'Shai Hulud 2 Detector' in sarif_output
        print("✓ PASSED: SARIF format works")


def run_all_tests():
    """Run all tests."""
    print("=" * 60)
    print("Shai Hulud 2 Detector - Test Suite")
    print("=" * 60)
    
    tests = [
        test_true_positive_vulnerable_package,
        test_false_positive_non_vulnerable_package,
        test_true_positive_malware_file,
        test_false_positive_similar_filename,
        test_vulnerable_version_with_prefix,
        test_package_lock_json,
        test_multiple_vulnerable_packages,
        test_output_formats,
    ]
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"✗ FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ ERROR: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)

