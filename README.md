# Shai Hulud 2 Detector

A command-line tool that scans JavaScript/Node.js repositories for:

1. **Vulnerable packages and versions** from the Shai Hulud 2 vulnerability database
2. **Malware files** with specific SHA1 hashes (bun_environment.js, setup_bun.js)

## Installation

```bash
# Clone or download this repository
cd shai-hulud2-detector

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

Scan the current directory:
```bash
./shai-hulud2-detector
```

Scan a specific directory:
```bash
./shai-hulud2-detector /path/to/project
```

### Options

- `--format <text|json|sarif>` - Output format (default: text)
- `--exit-code` - Exit with code 1 if vulnerabilities found (default: 0)
- `--verbose, -v` - Show detailed output
- `--ignore <pattern>` - Additional ignore patterns (can be specified multiple times)
- `--version` - Show version information
- `--help` - Show help message

### Examples

**Text output (default):**
```bash
./shai-hulud2-detector --format text
```

**JSON output:**
```bash
./shai-hulud2-detector --format json
```

**SARIF output:**
```bash
./shai-hulud2-detector --format sarif > results.sarif
```

**With exit code:**
```bash
./shai-hulud2-detector --exit-code
# Exit code will be 1 if vulnerabilities found, 0 otherwise
```

**Ignore additional patterns:**
```bash
./shai-hulud2-detector --ignore ".test" --ignore "temp"
```

## Supported File Formats

The tool scans for:

- **Package files:**
  - `package.json` - npm dependencies
  - `package-lock.json` - npm lock file
  - `yarn.lock` - Yarn lock file

- **Malware files:**
  - `bun_environment.js` - Checked against known malicious SHA1 hashes
  - `setup_bun.js` - Checked against known malicious SHA1 hashes

## Output Formats

### Text Format

Human-readable text output showing vulnerable packages and malware files:

```
Found 2 vulnerable packages and 1 malware file:

Vulnerable Packages:
1. package.json:12
   @scope/vulnerable-package@1.2.3 (vulnerable version(s): = 1.2.3)

2. package-lock.json:45
   vulnerable-lib@1.0.0 (vulnerable version(s): = 1.0.0)

Malware Files:
1. node_modules/some-package/bun_environment.js
   SHA1: d60ec97eea19fffb4809bc35b91033b52490ca11 (MATCH)
```

### JSON Format

Structured JSON output:

```json
{
  "vulnerable_packages_found": 2,
  "malware_files_found": 1,
  "vulnerable_packages": [
    {
      "file": "package.json",
      "line": 12,
      "package": "@scope/vulnerable-package",
      "version": "1.2.3",
      "vulnerable_versions": ["= 1.2.3"]
    }
  ],
  "malware_files": [
    {
      "file": "node_modules/some-package/bun_environment.js",
      "sha1": "d60ec97eea19fffb4809bc35b91033b52490ca11",
      "matched": true
    }
  ]
}
```

### SARIF Format

SARIF 2.1.0 compliant output for integration with security tools and CI/CD pipelines:

- Tool metadata and version information
- Results array with rule IDs:
  - `SH2-VULN-PKG` - Vulnerable package detection
  - `SH2-MALWARE` - Malware file detection
- Locations with file paths and line numbers
- Severity levels and help text

## Default Ignore Patterns

The tool automatically ignores common directories:
- `.git`
- `node_modules`
- `.next`
- `dist`
- `build`
- `.cache`
- `.venv`, `venv`
- `__pycache__`
- `.pytest_cache`
- `.idea`
- `.vscode`

## Vulnerability Database

The tool uses a local CSV file `shai-hulud-2-packages.csv` in the root directory. If the file is not found, it will fall back to downloading from:
https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv

To update the local CSV file:
```bash
curl -o shai-hulud-2-packages.csv \
  "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv"
```

This CSV contains package names and vulnerable version constraints in the format:
- `= 1.2.3` - Exact version match
- `= 1.2.3 || = 1.2.4` - Multiple vulnerable versions

## Malware Detection

The tool scans for specific malware files and compares their SHA1 hashes against known malicious hashes:

- `bun_environment.js`: 
  - `d60ec97eea19fffb4809bc35b91033b52490ca11`
  - `3d7570d14d34b0ba137d502f042b27b0f37a59fa`
- `setup_bun.js`:
  - `d1829b4708126dcc7bea7437c04d1f10eacd4a16`

## Requirements

- Python 3.8+
- Dependencies listed in `requirements.txt`

## Testing

The tool includes a comprehensive test suite that validates true positives and false positives:

```bash
# Run automated tests
python3 tests/test_scanner.py

# Run demonstration script showing true/false positives
python3 tests/demo_true_false_positives.py
```

### Test Coverage

**True Positives (Correctly Detected):**
- Vulnerable packages from Shai Hulud 2 database
- Malware files with matching SHA1 hashes
- Packages with version prefixes (^, ~, =)
- Multiple vulnerable packages in the same project
- Vulnerabilities in package-lock.json files

**False Positives (Correctly Ignored):**
- Safe packages not in the vulnerability database
- Files with similar names (e.g., `bun_environment.ts`, `setup_bun.js.bak`)
- Non-vulnerable versions of packages

See `tests/README.md` for more details.

## License

This tool is provided for security scanning purposes. Please refer to the Wiz Research IOCs repository for more information about the Shai Hulud 2 vulnerability.

