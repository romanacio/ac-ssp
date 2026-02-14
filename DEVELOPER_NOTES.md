# Developer Notes

Quick reference for developers working on the System Service Profiler.

---

## Quick Facts

- **Current Version**: 1.1.0
- **Release Date**: 2026-02-12
- **Main File**: `system_profiler.py` (846 lines)
- **Language**: Python 3.6+
- **Dependencies**: None (pure stdlib)
- **Target OS**: Linux (Debian/Ubuntu, RHEL/CentOS/Rocky/AlmaLinux)

---

## File Structure

```
/Users/romanmc/app-test/ac-ssp/
├── system_profiler.py      # Main executable (846 lines)
├── README.md               # User documentation
├── EXAMPLES.md             # Usage examples
├── SUMMARY.md              # Project summary
├── CHANGELOG.md            # Detailed version history
├── VERSION.md              # Version tracking and technical details
└── DEVELOPER_NOTES.md      # This file
```

---

## Code Architecture

### Class: SystemProfiler (lines 156-537)

**Initialization**:
```python
def __init__(self, use_color=True):
    self.use_color = use_color
    self.results = {
        'system': [],
        'network': [],
        'services': [],
        'cloud_apps': [],
        'wordpress': [],
        'mounts': [],
        'systemd_issues': [],
        'disk': [],
        'updates': []
    }
    self.is_root = os.geteuid() == 0
```

### Key Methods

| Method | Lines | Purpose | Returns |
|--------|-------|---------|---------|
| `run_command()` | 172-191 | Execute shell commands safely | stdout or None |
| `format_message()` | 192-206 | Apply color codes to output | Formatted string |
| `add_result()` | 207-210 | Store check results | None |
| `detect_os_info()` | 211-253 | System information | Stores in results['system'] |
| `check_network_connectivity()` | 254-286 | Network diagnostics | Stores in results['network'] |
| `check_service_status()` | 287-359 | Single service check | Stores in results['services'] |
| `check_services()` | 360-363 | All service checks | Stores in results['services'] |
| `detect_cloud_apps()` | 365-400 | Cloud app detection | Stores in results['cloud_apps'] |
| `detect_wordpress_sites()` | 401-492 | WordPress discovery | Stores in results['wordpress'] |
| `check_remote_mounts()` | 493-540 | Network mount check | Stores in results['mounts'] |
| `check_failed_systemd_services()` | 541-613 | Systemd health | Stores in results['systemd_issues'] |
| `check_disk_usage()` | 614-644 | Disk space analysis | Stores in results['disk'] |
| `check_updates()` | 645-684 | Update detection | Stores in results['updates'] |
| `run_all_checks()` | 685-695 | Orchestrate all checks | None |
| `display_results()` | 696-746 | Output formatting | None (prints) |

---

## Data Structures

### SERVICES Dictionary (lines 26-163)

Structure:
```python
'service_name': {
    'binary': 'binary_name',              # Primary binary
    'alt_binary': 'alternative_binary',   # Optional alternative
    'process_names': ['proc1', 'proc2'],  # Process names in ps
    'config_paths': ['/path/to/config'],  # Configuration files
    'systemd_name': 'service_name',       # Systemd unit name
    'alt_systemd': 'alt_service_name'     # Optional alternative
}
```

**Current Services** (22 total):
- Web: apache, nginx
- Database: mysql, postgresql, mongodb, redis
- Container: docker, kubernetes, podman
- CI/CD: jenkins, gitlab-runner, teamcity, bamboo, drone, circleci, buildkite-agent
- Other: sshd, php-fpm, memcached, elasticsearch, rabbitmq, varnish

### CLOUD_APPS Dictionary (lines 166-153)

Structure:
```python
'app_name': {
    'paths': ['/path1', '/path2'],  # Search locations
    'version_file': 'version.php'   # File containing version info
}
```

**Current Apps** (7 total):
- nextcloud, owncloud, seafile, webmin, plesk, directadmin, wordpress

---

## How To Add Features

### Adding a New Service

1. **Add to SERVICES dictionary** (lines 26-163):
```python
'myservice': {
    'binary': 'myservice',
    'process_names': ['myservice', 'myservice-daemon'],
    'config_paths': ['/etc/myservice/config.conf'],
    'systemd_name': 'myservice'
}
```

2. **That's it!** The existing `check_services()` method will automatically detect it.

**No code changes needed** - just add the dictionary entry.

---

### Adding a New Cloud App

1. **Add to CLOUD_APPS dictionary** (lines 166-153):
```python
'myapp': {
    'paths': ['/var/www/myapp', '/opt/myapp'],
    'version_file': 'version.txt'
}
```

2. **That's it!** The existing `detect_cloud_apps()` method will automatically detect it.

**No code changes needed** - just add the dictionary entry.

---

### Adding a New Check Type

For features that don't fit the service/cloud app model:

1. **Add result category** in `__init__()` (line 159):
```python
self.results = {
    # ... existing categories ...
    'my_new_check': []
}
```

2. **Create detection method**:
```python
def check_my_feature(self):
    """Check for my feature"""
    # Your detection logic here

    # Store results using add_result()
    self.add_result('my_new_check', 'success', '✓', 'Feature found')
    self.add_result('my_new_check', 'warning', '⚠', 'Feature has issues')
    self.add_result('my_new_check', 'critical', '🔴', 'Feature failed')
```

3. **Call in run_all_checks()** (line 685):
```python
def run_all_checks(self):
    # ... existing checks ...
    self.check_my_feature()  # Add this line
```

4. **Add to display** (line 717):
```python
categories = [
    # ... existing categories ...
    ('my_new_check', 'MY NEW FEATURE')
]
```

---

## Coding Standards

### Style Guidelines
- Follow existing code style (PEP 8 compatible)
- Use descriptive variable names
- Add docstrings to new methods
- Keep methods under 100 lines when possible
- Use early returns to reduce nesting

### Error Handling
- Always use try/except for file operations
- Commands should have timeouts (default 5s)
- Gracefully handle missing binaries/files
- Never crash - always return None or empty results

### Output Standards
- Use `add_result()` to store findings
- Severity levels: 'success', 'warning', 'critical', 'info'
- Symbols: ✓ (success), ⚠ (warning), 🔴 (critical), ℹ (info)
- Keep messages concise (under 150 chars)
- Only show detected items (no "NOT FOUND" messages)

---

## Testing Checklist

### Before Committing

```bash
# 1. Syntax check
python3 -m py_compile system_profiler.py

# 2. Help output
python3 system_profiler.py --help

# 3. No-color mode
python3 system_profiler.py --no-color

# 4. Root execution (if possible)
sudo python3 system_profiler.py

# 5. Non-root execution
python3 system_profiler.py

# 6. Line count
wc -l system_profiler.py
```

### Manual Testing
- [ ] Verify new features appear in output
- [ ] Check color coding is correct
- [ ] Ensure no crashes on missing features
- [ ] Verify execution time is still < 10s
- [ ] Test on both Debian and RHEL if possible

---

## Common Patterns

### Running Commands
```python
# Simple command
output = self.run_command('ls -la')

# With timeout
output = self.run_command('slow_command', timeout=10)

# Check return code
output, returncode = self.run_command('command', check_output=False)
```

### File Checks
```python
# Check if file exists
if os.path.exists('/path/to/file'):
    # Do something

# Glob patterns
import glob
matches = glob.glob('/etc/*/config.conf')

# Read file safely
try:
    with open('/path/to/file', 'r') as f:
        content = f.read(1000)  # Limit read size
except:
    pass
```

### Regex Patterns
```python
import re

# Extract version number
ver_match = re.search(r'(\d+\.\d+[\.\d]*)', output)
if ver_match:
    version = ver_match.group(1)

# Remove ANSI codes
clean_text = re.sub(r'\x1b\[[0-9;]*m', '', text)
```

---

## Performance Guidelines

### Timeouts
- Network operations: 3-5 seconds
- File searches: 10 seconds max
- Service checks: 5 seconds default
- Package manager queries: 10-15 seconds

### Optimization Tips
- Use `--no-legend` with systemctl
- Limit find depth to 3 levels
- Use `head -N` to limit large outputs
- Avoid recursive searches when possible
- Cache expensive operations if called multiple times

---

## Version Update Checklist

When releasing a new version:

1. **Update version numbers**:
   - README.md (bottom)
   - SUMMARY.md (Version section)
   - CHANGELOG.md (add new section)
   - VERSION.md (update current version)

2. **Update documentation**:
   - Add new features to README.md
   - Update example output if changed
   - Update feature counts in SUMMARY.md

3. **Test thoroughly**:
   - Run all tests from testing checklist
   - Test on production-like system if possible
   - Verify backward compatibility

4. **Update this file**:
   - Add any new patterns or guidelines
   - Update line number references if significantly changed
   - Add new sections for major features

---

## Known Issues & Limitations

### Current Limitations
1. **WordPress Detection**:
   - Max search depth: 3 levels
   - 10s timeout per search path
   - May miss non-standard installations

2. **Systemd Checks**:
   - Requires root privileges
   - Only checks first 50 enabled services
   - Some distributions have different output formats

3. **Remote Mounts**:
   - Basic accessibility check only
   - Doesn't verify actual data availability
   - Limited to common filesystem types

4. **General**:
   - No JSON output option yet
   - No configuration file support
   - No parallel execution
   - Single-threaded (sequential checks)

### Technical Debt
- `datetime` module imported but unused (line 13)
- Some error messages could be more specific
- No unit tests (manual testing only)
- Could benefit from logging framework

---

## Future Feature Ideas

### Planned for v1.2.0
- [ ] JSON output format (`--json` flag)
- [ ] Configuration file support
- [ ] WordPress plugin detection
- [ ] Docker container listing
- [ ] SSL certificate expiration

### Under Consideration
- [ ] Memory usage analysis
- [ ] Firewall rule detection
- [ ] Failed login attempts (from logs)
- [ ] Open ports scan
- [ ] Cron job listing
- [ ] Parallel check execution
- [ ] Custom service definitions via config
- [ ] HTML report generation

---

## Debugging Tips

### Enable Verbose Output
Add temporary debug prints:
```python
def check_my_feature(self):
    print(f"DEBUG: Starting check...")  # Temporary
    # Your code
    print(f"DEBUG: Found {len(results)} items")  # Temporary
```

### Test Individual Methods
```python
# At bottom of file, temporarily add:
if __name__ == '__main__':
    profiler = SystemProfiler()
    profiler.check_my_feature()
    profiler.display_results()
```

### Check Command Output
```python
output = self.run_command('mycommand')
print(f"Command output: {repr(output)}")  # Shows exact output
```

---

## Git Workflow (If Using Git)

### Branching
```bash
git checkout -b feature/my-new-feature
# Make changes
git add system_profiler.py
git commit -m "Add my new feature"
```

### Commit Messages
Format: `<type>: <description>`

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `refactor`: Code restructuring
- `perf`: Performance improvement
- `test`: Adding tests

Examples:
```
feat: Add HAProxy service detection
fix: Handle missing systemctl gracefully
docs: Update README with new examples
perf: Optimize WordPress search with parallel find
```

---

## Support & Contact

- **Project Location**: `/Users/romanmc/app-test/ac-ssp/`
- **Primary Maintainer**: System Administrator Team
- **Last Updated**: 2026-02-12

---

## Quick Reference Commands

```bash
# Run profiler
sudo python3 system_profiler.py

# Test syntax
python3 -m py_compile system_profiler.py

# Count lines
wc -l system_profiler.py

# Search for pattern in code
grep -n "pattern" system_profiler.py

# Find all methods
grep -n "def " system_profiler.py

# Check Python version
python3 --version

# Make executable
chmod +x system_profiler.py

# Create backup
cp system_profiler.py system_profiler.py.backup

# View help
python3 system_profiler.py --help
```

---

**Last Updated**: 2026-02-12
**Document Version**: 1.0
