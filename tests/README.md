# Test Suite for Shai Hulud 2 Detector

This test suite validates the detector's ability to correctly identify true positives and avoid false positives.

## Test Cases

### True Positives (Should Detect)

1. **Vulnerable Package Detection**
   - Tests detection of packages listed in the Shai Hulud 2 vulnerability database
   - Example: `@accordproject/concerto-analysis@3.24.1`

2. **Malware File Detection**
   - Tests detection of files named `bun_environment.js` and `setup_bun.js`
   - Verifies SHA1 hash matching against known malicious hashes

3. **Version Prefix Handling**
   - Tests that version prefixes (^, ~, =) are correctly stripped
   - Ensures vulnerable packages are detected even with version ranges

4. **Multiple Vulnerable Packages**
   - Tests detection of multiple vulnerable packages in the same project

5. **Package Lock Files**
   - Tests detection in `package-lock.json` files

### False Positives (Should NOT Detect)

1. **Non-Vulnerable Packages**
   - Tests that safe packages are not flagged
   - Example: `lodash@4.17.21`, `express@4.18.2`

2. **Similar Filenames**
   - Tests that files with similar names are not flagged
   - Example: `bun_environment.ts`, `setup_bun.js.bak`

## Running Tests

```bash
# Run all tests
python3 tests/test_scanner.py

# Run with verbose output
python3 tests/test_scanner.py -v
```

## Expected Behavior

- **True Positives**: The tool should detect all vulnerable packages and malware files
- **False Positives**: The tool should NOT flag safe packages or files with similar names

## Test Coverage

- Package.json parsing
- Package-lock.json parsing
- Version matching logic
- Malware file detection
- Output format generation (text, JSON, SARIF)
- Version prefix stripping

