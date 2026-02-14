# System Service Profiler

A Python-based diagnostic tool for support engineers to quickly assess Linux server state and identify potential issues.

## Overview

The System Service Profiler is inspired by cPanel's SSP (System Status Probe) tool but designed for generic Linux servers. It provides an instant snapshot of system status, running services, network connectivity, disk usage, and available updates.

## Features

- **System Information**: OS version, kernel, uptime, load average
- **Network Diagnostics**: DNS resolution and outbound connectivity tests
- **Service Detection**: Automatically detects common services including:
  - Web servers (Apache, NGINX)
  - Databases (MySQL/MariaDB, PostgreSQL, MongoDB, Redis)
  - Containers (Docker, Kubernetes, Podman)
  - CI/CD Tools (Jenkins, GitLab Runner, TeamCity, Bamboo, Drone, CircleCI, Buildkite)
  - Other services (SSH, PHP-FPM, Memcached, Elasticsearch, RabbitMQ, Varnish)
- **Cloud Application Detection**: Identifies self-hosted applications:
  - Nextcloud, ownCloud, Seafile
  - Control panels (Webmin, Plesk, DirectAdmin)
- **WordPress Detection**: Finds WordPress installations with:
  - Version detection
  - Multisite identification
  - Database name extraction
  - WP-CLI detection
- **Remote Mount Detection**: Identifies network filesystems:
  - NFS, CIFS/SMB, SSHFS
  - GlusterFS, Ceph
  - Mount accessibility status
- **Systemd Service Monitoring**: Detects problematic services:
  - Failed services with error messages
  - Enabled but inactive services
- **Docker Diagnostics** (--docker flag): Comprehensive container monitoring:
  - Docker engine status and version
  - Running containers with health status
  - Stopped containers with exit codes
  - Recent errors from Docker daemon
  - Resource usage (images, volumes, networks)
  - Disk space analysis
- **Kubernetes Diagnostics** (--k8s flag): Comprehensive cluster monitoring:
  - kubectl and cluster connectivity
  - Cluster and API server status
  - Node health and resource usage
  - Pod issues (CrashLoopBackOff, Pending, ImagePullBackOff)
  - Deployment and service status
  - Storage (PVs and PVCs)
  - Recent cluster events
  - Resource summary
- **Disk Space Analysis**: Shows usage with color-coded warnings
- **Update Detection**: Checks for available system updates and security patches
- **Color-coded Output**: Easy-to-read status indicators (✓ success, ⚠ warning, 🔴 critical)

## Requirements

- Python 3.6 or higher
- Linux operating system (Ubuntu/Debian or RHEL/CentOS/Rocky/AlmaLinux)
- Root/sudo access recommended for complete information

**No third-party Python packages required** - uses only standard library modules.

## Installation

1. Download the script:
```bash
wget https://example.com/system_profiler.py
# or
curl -O https://example.com/system_profiler.py
```

2. Make it executable:
```bash
chmod +x system_profiler.py
```

## Usage

### Basic Usage

Run with sudo for complete information:
```bash
sudo python3 system_profiler.py
```

Or as root:
```bash
sudo su
python3 system_profiler.py
```

### Options

```bash
# Disable color output (useful for logging to file)
sudo python3 system_profiler.py --no-color

# Docker diagnostics mode (detailed container information)
sudo python3 system_profiler.py --docker

# Kubernetes diagnostics mode (detailed cluster information)
sudo python3 system_profiler.py --k8s

# Combine flags
sudo python3 system_profiler.py --docker --no-color
sudo python3 system_profiler.py --k8s --no-color

# Show help
python3 system_profiler.py --help
```

### Example Output

```
==================================================
    SYSTEM SERVICE PROFILER
==================================================
Running as: root
Purpose: Quick server diagnostic for support tasks

[SYSTEM INFO]
✓ OS: Ubuntu 22.04.3 LTS
✓ Kernel: 5.15.0-89-generic
✓ Uptime: 45 days, 3 hours, 22 minutes
✓ Load Average: 0.45, 0.52, 0.48

[NETWORK]
✓ DNS Resolution: Working (google.com resolves)
✓ Outbound Connectivity: Working
✓ Primary Interface: eth0 (192.168.1.100)

[SERVICES]
✓ APACHE: RUNNING (v2.4.52) - Config: /etc/apache2/apache2.conf
✓ MYSQL: RUNNING (v8.0.35) - Config: /etc/mysql/my.cnf
✓ DOCKER: RUNNING (v24.0.7) - Config: /etc/docker/daemon.json
✓ JENKINS: RUNNING (v2.414.3) - Config: /var/lib/jenkins/config.xml
⚠ NGINX: INSTALLED but NOT RUNNING

[CLOUD/WEB APPLICATIONS]
✓ NEXTCLOUD: DETECTED (v27.1.0) - /var/www/nextcloud

[WORDPRESS INSTALLATIONS]
✓ WORDPRESS: DETECTED - /var/www/html/wordpress (v6.4.2) - DB: wp_production
✓ WORDPRESS: DETECTED - /var/www/html/blog (v6.3.1) [MULTISITE] - DB: wp_multisite
✓ WP-CLI: INSTALLED (WP-CLI 2.9.0)

[REMOTE MOUNTS]
✓ NFS4: 192.168.1.100:/storage → /mnt/nfs-share
✓ CIFS: //fileserver/docs → /mnt/windows-share
⚠ NFS: 192.168.1.200:/backup → /mnt/backup - NOT ACCESSIBLE

[SYSTEMD SERVICE ISSUES]
🔴 FAILED: postgresql.service - Main process exited, code=exited, status=1/FAILURE
⚠ ENABLED but INACTIVE: redis.service

[DISK USAGE]
✓ /: 65% used (325GB / 500GB)
✓ /home: 45% used (90GB / 200GB)
⚠ /var: 85% used (170GB / 200GB)

[UPDATES]
⚠ 23 packages can be updated
🔴 5 security updates available
```

## Output Symbols

- `✓` Green - Success/Normal operation
- `⚠` Yellow - Warning/Attention needed
- `🔴` Red - Critical issue

Note: Only detected services and applications are shown. Items that are not found are omitted from the output.

## Supported Distributions

- **Debian/Ubuntu** (using apt package manager)
- **RHEL/CentOS/Rocky Linux/AlmaLinux** (using yum/dnf package manager)

## Architecture

The script uses a modular class-based design that makes it easy to extend:

```python
class SystemProfiler:
    def detect_os_info()          # System information
    def check_network_connectivity()  # Network tests
    def check_services()          # Service detection
    def detect_cloud_apps()       # Cloud application detection
    def check_disk_usage()        # Disk space analysis
    def check_updates()           # Update detection
```

### Adding New Services

To add detection for a new service, edit the `SERVICES` dictionary:

```python
SERVICES = {
    'myservice': {
        'binary': 'myservice',
        'process_names': ['myservice'],
        'config_paths': ['/etc/myservice/config.conf'],
        'systemd_name': 'myservice'
    },
    # ... other services
}
```

### Adding New Cloud Applications

To add a new cloud application, edit the `CLOUD_APPS` dictionary:

```python
CLOUD_APPS = {
    'myapp': {
        'paths': ['/var/www/myapp', '/opt/myapp'],
        'version_file': 'version.txt'
    },
    # ... other applications
}
```

## Use Cases

- **Initial Server Assessment**: Quick overview when logging into a new server
- **Troubleshooting**: Identify running services and potential issues
- **Pre-maintenance Check**: Verify system state before updates
- **Documentation**: Generate server inventory information
- **Support Tasks**: Provide quick diagnostics for support tickets

## Performance

The script is designed to complete in under 10 seconds, making it suitable for quick diagnostics.

## Limitations

- Requires root/sudo for complete service status information
- Some checks may not work on non-standard configurations
- Network tests assume internet connectivity is expected
- Package update checks may be slow on first run (cache building)

## Contributing

To add new features:

1. Add a new method to the `SystemProfiler` class
2. Call it from `run_all_checks()`
3. Store results using `self.add_result()`
4. The display formatting is automatic

## License

This script is provided as-is for use in system administration and support tasks.

## Author

Created for system administrators and support engineers who need quick server diagnostics.

## Version

1.3.0 - Kubernetes diagnostics release
- Added comprehensive Kubernetes diagnostics mode (`--k8s` flag)
- kubectl and cluster connectivity verification
- Cluster and API server health monitoring
- Node status and resource usage (CPU, Memory)
- Pod issue detection (CrashLoopBackOff, Pending, ImagePullBackOff)
- Deployment and service status analysis
- Storage monitoring (PVs and PVCs)
- Recent cluster events tracking
- Resource summary (pods, namespaces, configmaps, secrets)
- Hint message in normal mode when Kubernetes is detected

1.2.0 - Docker diagnostics release
- Added comprehensive Docker diagnostics mode (`--docker` flag)
- Docker service status and version detection
- Running and stopped container monitoring
- Container health status checking
- Recent Docker error/warning extraction
- Resource usage reporting (images, volumes, networks, disk)
- Hint message in normal mode when Docker is detected

1.1.0 - Enhanced feature release
- Added CI/CD pipeline detection (Jenkins, GitLab Runner, TeamCity, Bamboo, Drone, CircleCI, Buildkite)
- Added WordPress installation detection with version, multisite, and database info
- Added remote mount detection (NFS, CIFS, SSHFS, GlusterFS, Ceph)
- Added systemd service issue detection (failed and inactive services)

1.0.0 - Initial release
