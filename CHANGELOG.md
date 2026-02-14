# Changelog

All notable changes to the System Service Profiler will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.3.0] - 2026-02-12

### 🎉 Summary
Added comprehensive Kubernetes diagnostics mode via `--k8s` flag. This specialized mode provides detailed cluster monitoring, node health checks, pod issue detection, deployment status, storage analysis, and resource summaries for Kubernetes environments. When Kubernetes (kubelet) is detected in normal mode, users receive a hint to run with `--k8s` for detailed diagnostics. This follows the same two-stage pattern established with Docker diagnostics in v1.2.0.

### ✨ Added

#### Kubernetes Diagnostics Mode (`--k8s` or `--kubernetes` flag)
Complete Kubernetes cluster analysis accessible via command-line flag:

**Usage**:
```bash
sudo python3 system_profiler.py --k8s
# or
sudo python3 system_profiler.py --kubernetes
```

**Features**:

1. **Kubernetes Environment Detection**:
   - kubectl installation check and version detection
   - Current context and cluster identification
   - Cluster URL extraction
   - Current namespace detection
   - Configuration validation

2. **Cluster Status Monitoring**:
   - Cluster reachability test via `kubectl cluster-info`
   - API server health check via `/healthz` endpoint
   - API server response time measurement
   - Node readiness summary (Ready vs NotReady counts)
   - Overall cluster health assessment

3. **Node Health and Resource Monitoring**:
   - Individual node status (Ready/NotReady)
   - Node roles (master/worker identification)
   - Kubernetes version per node
   - **Resource usage metrics** (requires metrics-server):
     - CPU usage percentage
     - Memory usage
   - Node health indicators with color coding
   - Limited to 10 nodes for performance

4. **Pod Issue Detection**:
   - **CrashLoopBackOff** pods with restart counts
   - **Pending** pods with reasons
   - **ImagePullBackOff** and image pull errors
   - **Container creation failures**
   - Pod restart counts and age
   - Namespace identification
   - Limited to 20 problem pods
   - Uses field-selector for efficient querying

5. **Deployment Status Analysis**:
   - Replica readiness tracking (ready/desired counts)
   - Per-namespace deployment health
   - Critical warnings for 0-replica deployments
   - Warning status for partial replica availability
   - Limited to 15 deployments

6. **Service Monitoring**:
   - Service types (ClusterIP, LoadBalancer, NodePort)
   - Cluster IPs and external IPs
   - **Endpoint availability check**
   - Service health warnings for missing endpoints
   - Per-namespace service listing
   - Limited to 15 services

7. **Storage Analysis**:
   - **Persistent Volume (PV) summary**:
     - Total PV count
     - Bound vs Available PVs
   - **PersistentVolumeClaim (PVC) status**:
     - Pending PVC detection
     - Provisioning issue identification
     - Shows up to 5 pending PVCs with details

8. **Recent Cluster Events**:
   - Warning-level events from recent operations
   - Sorted by timestamp (most recent last)
   - Event reason and message extraction
   - Error vs warning severity classification
   - Limited to last 5 events

9. **Resource Summary**:
   - Total pod counts by status (Running, Pending, Failed)
   - Namespace count
   - ConfigMaps count
   - Secrets count
   - Services count
   - Comprehensive cluster metrics overview

**Technical Implementation**:
- New method: `check_k8s_details()` (~280 lines)
- 9 new result categories:
  - `k8s_env`: Environment and configuration
  - `k8s_cluster`: Cluster-level status
  - `k8s_nodes`: Node health and resources
  - `k8s_pods`: Pod issues and problems
  - `k8s_deployments`: Deployment status
  - `k8s_services`: Service monitoring
  - `k8s_storage`: PV and PVC analysis
  - `k8s_events`: Recent cluster events
  - `k8s_summary`: Resource summary
- Comprehensive error handling for:
  - kubectl not installed
  - No context configured
  - Cluster unreachable
  - Missing metrics-server
- Timeout protection (5-10s for kubectl commands)
- Supports both `--k8s` and `--kubernetes` flags

**kubectl Commands Used**:
- `kubectl version --client` - Client version
- `kubectl config current-context` - Active context
- `kubectl config view --minify` - Current config
- `kubectl cluster-info` - Cluster connectivity
- `kubectl get --raw /healthz` - API health check
- `kubectl get nodes` - Node listing
- `kubectl top nodes` - Node metrics (optional)
- `kubectl get pods --all-namespaces --field-selector` - Problem pods
- `kubectl get deployments --all-namespaces` - Deployments
- `kubectl get services --all-namespaces` - Services
- `kubectl get endpoints` - Service endpoints
- `kubectl get pv` - Persistent volumes
- `kubectl get pvc --all-namespaces` - PV claims
- `kubectl get events --sort-by=.lastTimestamp` - Recent events
- `kubectl get namespaces` - Namespace list
- `kubectl get configmaps/secrets --all-namespaces` - Config resources

**Example Output**:
```
==================================================
    KUBERNETES DIAGNOSTICS
==================================================

[KUBERNETES ENVIRONMENT]
✓ kubectl: INSTALLED (v1.28.2)
✓ Context: production-cluster (current)
✓ Cluster: https://api.k8s.example.com:6443
✓ Namespace: default (current)

[CLUSTER STATUS]
✓ Cluster: REACHABLE
✓ API Server: HEALTHY (response time: 45ms)
⚠ Nodes: 3/4 Ready (1 node NotReady)

[NODES]
✓ worker-1: Ready (v1.28.2) - CPU: 45%, Memory: 68%
✓ worker-2: Ready (v1.28.2) - CPU: 32%, Memory: 55%
🔴 worker-3: NotReady (v1.28.2)
✓ master-1: Ready,master (v1.28.2) - CPU: 25%, Memory: 42%

[POD ISSUES]
🔴 CrashLoopBackOff: nginx-abc123 (namespace: production) - Restarts: 15 - Age: 2h
⚠ Pending: redis-cache-0 (namespace: cache) - Age: 45m

[DEPLOYMENTS]
✓ nginx-deployment: 3/3 replicas ready (namespace: production)
⚠ api-server: 2/3 replicas ready (namespace: default)

[SERVICES]
✓ kubernetes: ClusterIP (10.96.0.1) (namespace: default)
⚠ redis-service: ClusterIP (10.96.78.12) (namespace: cache) - No endpoints

[STORAGE]
✓ PVs: 12 total (10 Bound, 2 Available)
⚠ PVCs Pending: 2
⚠   - data-postgres-0 (namespace: database): Waiting for volume provisioning

[RECENT EVENTS]
🔴 FailedScheduling: 0/4 nodes available: insufficient cpu
⚠ BackOff: Back-off restarting failed container

[RESOURCE SUMMARY]
✓ Total Pods: 45 (42 Running, 2 Pending, 1 Failed)
✓ Namespaces: 8
✓ ConfigMaps: 23
✓ Secrets: 15
✓ Services: 18
```

---

#### Hint Message in Normal Mode
When Kubernetes (kubelet) is detected during standard system profiling, an informational hint is displayed:

```
[SERVICES]
✓ KUBERNETES: RUNNING (v1.28.2) - Config: /etc/kubernetes/kubelet.conf
ℹ  Run with --k8s flag for detailed Kubernetes diagnostics
```

**Implementation**:
- Modified `check_service_status()` method
- Only shows hint in normal mode (not in k8s or docker modes)
- Non-intrusive informational message
- Prompts users to discover specialized Kubernetes analysis

---

### 🔄 Changed

#### Code Structure
- **File size**: Increased from 1090 to 1462 lines (+372 lines, +34%)
- **Result categories**: Added 9 Kubernetes-specific categories
- **Methods**: Added 1 major new method (`check_k8s_details`)
- **Class parameters**: Added `k8s_mode` boolean to `SystemProfiler.__init__()`
- **Operating modes**: Now supports 3 mutually exclusive modes

#### Command-Line Interface
- **New flags**: `--k8s` and `--kubernetes` for Kubernetes diagnostics mode
- **Help output**: Enhanced with Kubernetes mode documentation
- **Flag combination**: Can combine with `--no-color` flag
- **Mode exclusivity**: k8s, docker, and normal modes are mutually exclusive

#### Execution Flow
`run_all_checks()` method now branches based on mode with priority order:
- **Kubernetes Mode** (`k8s_mode=True`): Only executes `check_k8s_details()`
- **Docker Mode** (`docker_mode=True`): Only executes `check_docker_details()`
- **Normal Mode**: Executes all standard checks
- Mutually exclusive operation ensures focused, specialized output

#### Display Output
`display_results()` method adapted for three-mode operation:
- **Kubernetes Mode Header**: "KUBERNETES DIAGNOSTICS"
- **Docker Mode Header**: "DOCKER DIAGNOSTICS"
- **Normal Mode Header**: "SYSTEM SERVICE PROFILER"
- **Category Selection**: Mode-specific categories only
- Each mode has dedicated result categories

#### Modified Methods
1. **`__init__()`**: Added `k8s_mode` parameter and 9 Kubernetes result categories
2. **`run_all_checks()`**: Added k8s mode conditional execution (checked first)
3. **`display_results()`**: Added k8s mode-specific header and category selection
4. **`check_service_status()`**: Added Kubernetes hint message logic
5. **`main()`**: Added `--k8s` and `--kubernetes` flag parsing

---

### 📊 Statistics

#### Code Metrics
| Metric | v1.2.0 | v1.3.0 | Change |
|--------|--------|--------|--------|
| Total Lines | 1090 | 1462 | +372 (+34%) |
| Methods | 15 | 16 | +1 |
| Result Categories | 14 | 23 | +9 |
| Command-Line Flags | 3 | 4 | +1 |
| Output Modes | 2 | 3 | +1 |

---

### 🔧 Technical Details

#### New Method Added
**`check_k8s_details()`** (~280 lines)
- Checks kubectl installation and configuration
- Validates cluster connectivity
- Queries node health and resource usage
- Detects pod issues across all namespaces
- Analyzes deployment and service status
- Monitors storage (PVs and PVCs)
- Retrieves recent cluster events
- Generates comprehensive resource summary
- Comprehensive error handling for various failure scenarios

#### kubectl Command Categories
**Configuration & Connectivity**:
- `kubectl version --client`
- `kubectl config current-context`
- `kubectl config view --minify`
- `kubectl cluster-info`
- `kubectl get --raw /healthz`

**Resource Monitoring**:
- `kubectl get nodes`
- `kubectl top nodes` (requires metrics-server)
- `kubectl get pods --all-namespaces`
- `kubectl get deployments --all-namespaces`
- `kubectl get services --all-namespaces`

**Storage & Events**:
- `kubectl get pv`
- `kubectl get pvc --all-namespaces`
- `kubectl get events --sort-by=.lastTimestamp`

**Summary Metrics**:
- `kubectl get namespaces`
- `kubectl get configmaps --all-namespaces`
- `kubectl get secrets --all-namespaces`

---

### 🧪 Testing

#### Automated Tests Passed
- ✅ Python syntax validation: `python3 -m py_compile system_profiler.py`
- ✅ Help output includes Kubernetes mode: `--help` flag updated
- ✅ Kubernetes mode flag parsing works: `--k8s` and `--kubernetes` flags recognized
- ✅ Mode separation: k8s, docker, and normal modes mutually exclusive

#### Manual Testing Completed
- ✅ Kubernetes mode with kubectl not installed
- ✅ Kubernetes mode with no context configured
- ✅ Kubernetes mode with cluster unreachable
- ✅ Normal mode shows Kubernetes hint when kubelet detected
- ✅ Flag combinations (`--k8s --no-color`)

#### Production Testing Required
- ⚠️ Kubernetes mode with live cluster
- ⚠️ Node resource metrics with metrics-server
- ⚠️ Pod issue detection on production clusters
- ⚠️ Event extraction on active clusters
- ⚠️ Deployment and service status accuracy

---

### ⚠️ Breaking Changes

**None** - Fully backward compatible with v1.2.0

---

### 🔜 Upgrade Path

#### From v1.2.0 to v1.3.0

**Steps**:
1. Backup current version (optional): `cp system_profiler.py system_profiler.py.v1.2.0`
2. Replace with new version
3. Run as before: `sudo python3 system_profiler.py`
4. Try new Kubernetes mode: `sudo python3 system_profiler.py --k8s`

**New Features**:
- Kubernetes diagnostics mode available via `--k8s` or `--kubernetes` flag
- Hint message appears when Kubernetes is detected in normal mode

**No changes to**:
- Normal mode behavior (unchanged)
- Docker mode behavior (unchanged)
- Existing command-line flags
- Output format for standard profiling
- File permissions or location requirements

---

### 📝 Notes for Future Versions

#### Potential v1.4.0 Features
- Helm release detection and status
- Kubernetes Ingress analysis
- Certificate expiration checks (TLS secrets)
- Resource quota and limit range monitoring
- HorizontalPodAutoscaler (HPA) status
- Network policy analysis
- RBAC permission checks
- Kubernetes distribution detection (EKS, GKE, AKS, OpenShift)
- Multi-cluster context switching
- JSON output format for k8s mode

---

## [1.2.0] - 2026-02-12

### 🎉 Summary
Added comprehensive Docker diagnostics mode via `--docker` flag. This specialized mode provides detailed container monitoring, health checks, error tracking, and resource analysis for Docker environments. When Docker is detected in normal mode, users receive a hint to run with `--docker` for detailed diagnostics.

### ✨ Added

#### Docker Diagnostics Mode (`--docker` flag)
Complete Docker environment analysis accessible via command-line flag:

**Usage**:
```bash
sudo python3 system_profiler.py --docker
```

**Features**:

1. **Docker Service Status**:
   - Docker Engine version detection (`docker --version`)
   - Service running status via systemd
   - Docker socket accessibility check (`/var/run/docker.sock`)
   - Daemon uptime and active status from systemctl
   - Docker root directory location

2. **Running Container Monitoring**:
   - Lists all active containers with full details
   - Shows container name, image, and status
   - Displays port mappings
   - **Health Check Status**: Detects and reports:
     - ✓ Healthy containers
     - ⚠ Unhealthy containers
     - ℹ Containers with health check starting
   - Uses `docker ps` and `docker inspect` for comprehensive data

3. **Stopped Container Analysis**:
   - Shows recently exited containers (limited to 10)
   - Displays exit codes
   - **Exit Code Analysis**: Warns on non-zero exits indicating failures
   - Helps identify containers that crashed or failed to start

4. **Error and Warning Tracking**:
   - Extracts last 24 hours of Docker daemon logs
   - Uses `journalctl -u docker` for systemd-managed installations
   - Filters for warning and error priority messages
   - Shows last 5 errors with ISO timestamps
   - Strips ANSI color codes for clean output
   - Displays "No recent errors" message when clean

5. **Resource Usage Analysis**:
   - **Images**: Count and total disk usage
   - **Volumes**: Docker volume count
   - **Networks**: Total networks with custom network identification (subtracts 3 default networks)
   - **Disk Usage Breakdown**:
     - Per-resource-type analysis (images, containers, volumes, build cache)
     - Shows total size for each resource type
     - **Reclaimable Space Warning**: Highlights resources with significant reclaimable space
     - Uses `docker system df` for accurate reporting

**Technical Implementation**:
- New method: `check_docker_details()` (~180 lines)
- 5 new result categories:
  - `docker_service`: Docker daemon and engine status
  - `docker_containers`: Running container information
  - `docker_stopped`: Stopped container information
  - `docker_errors`: Recent error/warning messages
  - `docker_resources`: Resource usage statistics
- Comprehensive error handling for Docker not installed or not running
- Timeout protection (10s for docker commands, 5s for quick checks)

**Example Output**:
```
==================================================
    DOCKER DIAGNOSTICS
==================================================

[DOCKER SERVICE]
✓ Docker Engine: Docker version 24.0.7, build afdd53b
✓ Docker Socket: /var/run/docker.sock (accessible)
✓ Active: active (running) since Mon 2026-02-10 10:30:00
✓ Docker Root Dir: /var/lib/docker

[RECENT ERRORS/WARNINGS]
✓ No recent errors in last 24 hours

[RUNNING CONTAINERS]
✓ nginx-proxy (nginx:latest) - Up 3 days - 0.0.0.0:80->80/tcp
✓ mysql-db (mysql:8.0) - Up 3 days - 3306/tcp
⚠ redis-cache (redis:alpine) - Up 2 hours (unhealthy)

[STOPPED CONTAINERS]
⚠ old-app (node:14) - Exited (1) 2 days ago
✗ test-container (alpine:latest) - Exited (0) 5 hours ago

[DOCKER RESOURCES]
✓ Images: 15 (Total: 4.2 GB)
✓ Volumes: 8
✓ Networks: 6 (3 custom)
✓ Images: 4.2 GB
✓ Containers: 256 MB
⚠ Build Cache: 1.2 GB (Reclaimable: 850 MB)
```

---

#### Hint Message in Normal Mode
When Docker service is detected during standard system profiling, an informational hint is displayed:

```
[SERVICES]
✓ DOCKER: RUNNING (v24.0.7) - Config: /etc/docker/daemon.json
ℹ  Run with --docker flag for detailed container diagnostics
```

**Implementation**:
- Modified `check_service_status()` method
- Only shows hint in normal mode (not in Docker mode)
- Non-intrusive informational message
- Prompts users to discover specialized Docker analysis

---

### 🔄 Changed

#### Code Structure
- **File size**: Increased from 846 to 1090 lines (+244 lines, +29%)
- **Result categories**: Added 5 Docker-specific categories
- **Methods**: Added 1 major new method (`check_docker_details`)
- **Class parameters**: Added `docker_mode` boolean to `SystemProfiler.__init__()`

#### Command-Line Interface
- **New flag**: `--docker` for Docker diagnostics mode
- **Help output**: Enhanced with Docker mode documentation
- **Flag combination**: Can combine with `--no-color` flag

#### Execution Flow
`run_all_checks()` method now branches based on mode:
- **Docker Mode** (`docker_mode=True`): Only executes `check_docker_details()`
- **Normal Mode** (`docker_mode=False`): Executes all standard checks
- Mutually exclusive operation ensures focused output

#### Display Output
`display_results()` method adapted for mode-specific display:
- **Docker Mode Header**: "DOCKER DIAGNOSTICS" instead of "SYSTEM SERVICE PROFILER"
- **Category Selection**: Shows Docker-specific categories only in Docker mode
- **Normal Mode**: Unchanged behavior for standard profiling

#### Modified Methods
1. **`__init__()`**: Added `docker_mode` parameter and Docker result categories
2. **`run_all_checks()`**: Added conditional execution based on mode
3. **`display_results()`**: Added mode-specific header and category selection
4. **`check_service_status()`**: Added Docker hint message logic
5. **`main()`**: Added `--docker` flag parsing

---

### 📊 Statistics

#### Code Metrics
| Metric | v1.1.0 | v1.2.0 | Change |
|--------|--------|--------|--------|
| Total Lines | 846 | 1090 | +244 (+29%) |
| Methods | 14 | 15 | +1 |
| Result Categories | 9 | 14 | +5 |
| Command-Line Flags | 2 | 3 | +1 |
| Output Modes | 1 | 2 | +1 |

---

### 🔧 Technical Details

#### New Method Added
**`check_docker_details()`** (~180 lines)
- Checks Docker installation and service status
- Queries running and stopped containers
- Extracts health check status
- Retrieves recent Docker daemon errors
- Analyzes resource usage and disk consumption
- Comprehensive error handling for missing Docker

#### Docker Commands Used
- `docker --version` - Engine version
- `docker ps` - Running containers
- `docker ps -a --filter "status=exited"` - Stopped containers
- `docker inspect --format "{{.State.Health.Status}}"` - Health status
- `docker images` - Image list
- `docker volume ls` - Volume list
- `docker network ls` - Network list
- `docker system df` - Disk usage
- `docker info --format "{{.DockerRootDir}}"` - Root directory
- `systemctl is-active docker` - Service status
- `systemctl status docker` - Detailed status
- `journalctl -u docker` - Daemon logs

---

### 🧪 Testing

#### Automated Tests Passed
- ✅ Python syntax validation: `python3 -m py_compile system_profiler.py`
- ✅ Help output includes Docker mode: `--help` flag updated
- ✅ Docker mode flag parsing works: `--docker` flag recognized
- ✅ Mode separation: Docker mode and normal mode mutually exclusive

#### Manual Testing Completed
- ✅ Docker mode with Docker not installed
- ✅ Docker mode with Docker not running
- ✅ Docker mode execution (simulated environment)
- ✅ Normal mode shows Docker hint when Docker detected
- ✅ Flag combinations (`--docker --no-color`)

#### Production Testing Required
- ⚠️ Docker mode with running containers
- ⚠️ Health check status detection
- ⚠️ Error log extraction on active Docker systems
- ⚠️ Resource usage accuracy on production systems

---

### ⚠️ Breaking Changes

**None** - Fully backward compatible with v1.1.0

---

### 🔜 Upgrade Path

#### From v1.1.0 to v1.2.0

**Steps**:
1. Backup current version (optional): `cp system_profiler.py system_profiler.py.v1.1.0`
2. Replace with new version
3. Run as before: `sudo python3 system_profiler.py`
4. Try new Docker mode: `sudo python3 system_profiler.py --docker`

**New Features**:
- Docker diagnostics mode available via `--docker` flag
- Hint message appears when Docker is detected in normal mode

**No changes to**:
- Normal mode behavior (unchanged)
- Existing command-line flags
- Output format for standard profiling
- File permissions or location requirements

---

### 📝 Notes for Future Versions

#### Potential v1.3.0 Features
- JSON output format option (`--json` flag) for Docker mode
- Docker Compose project detection and analysis
- Docker network detailed inspection
- Container resource limits and usage (CPU, memory)
- Volume mount analysis
- Image vulnerability scanning integration
- Docker Swarm mode detection
- Container log tail extraction

---

## [1.1.0] - 2026-02-12

### 🎉 Summary
Major feature enhancement release adding CI/CD tool detection, WordPress installation discovery, remote mount monitoring, and systemd service health checks. This release significantly expands diagnostic capabilities while maintaining full backward compatibility with v1.0.0.

### ✨ Added

#### CI/CD Pipeline Detection (7 new services)
Added comprehensive CI/CD tool detection to the existing service framework:

- **Jenkins** - Java-based automation server
  - Binary: `jenkins`
  - Config: `/etc/default/jenkins`, `/var/lib/jenkins/config.xml`
  - Systemd: `jenkins`

- **GitLab Runner** - GitLab CI/CD runner
  - Binary: `gitlab-runner`
  - Config: `/etc/gitlab-runner/config.toml`
  - Systemd: `gitlab-runner`

- **TeamCity** - JetBrains CI/CD server
  - Binary: `teamcity-server`
  - Config: `/opt/teamcity/conf/server.xml`
  - Systemd: `teamcity`

- **Bamboo** - Atlassian CI/CD server
  - Binary: `bamboo`
  - Config: `/opt/atlassian/bamboo/conf/server.xml`
  - Systemd: `bamboo`

- **Drone CI** - Container-native CI/CD platform
  - Binary: `drone-server`
  - Process: `drone-server`, `drone-agent`
  - Config: `/etc/drone/server.env`
  - Systemd: `drone`

- **CircleCI** - CircleCI local runner
  - Binary: `circleci`
  - Config: `/opt/circleci/config.yaml`
  - Systemd: `circleci`

- **Buildkite Agent** - Buildkite build agent
  - Binary: `buildkite-agent`
  - Config: `/etc/buildkite-agent/buildkite-agent.cfg`
  - Systemd: `buildkite-agent`

**Result**: Total services detected increased from 15 to 22

---

#### WordPress Installation Detection (New feature)
Comprehensive WordPress site discovery and analysis:

**Detection Capabilities**:
- Searches common web root directories:
  - `/var/www/html`
  - `/var/www`
  - `/usr/share/nginx/html`
  - `/opt/bitnami/wordpress`
  - `/srv/www`
  - `/home/*/public_html` (all user directories)
  - `/home/*/www` (all user directories)

- **Version Extraction**: Parses `wp-includes/version.php` for `$wp_version` variable
- **Multisite Detection**: Scans `wp-config.php` for `MULTISITE` and `SUBDOMAIN_INSTALL` constants
- **Database Identification**: Extracts `DB_NAME` value from `wp-config.php`
- **WP-CLI Support**: Detects if WP-CLI is installed and reports version
- **Multiple Sites**: Handles multiple WordPress installations on the same server

**Technical Details**:
- Uses `find` command with max depth of 3 levels
- 10-second timeout per search path
- ~90 lines of code in `detect_wordpress_sites()` method
- New result category: `wordpress`

**Example Output**:
```
[WORDPRESS INSTALLATIONS]
✓ WORDPRESS: DETECTED - /var/www/html/blog (v6.4.2) [MULTISITE] - DB: wp_multisite
✓ WP-CLI: INSTALLED (WP-CLI 2.9.0)
```

---

#### Remote Mount Detection (New feature)
Network filesystem monitoring and accessibility verification:

**Supported Filesystems**:
- **NFS/NFS4** - Network File System (Linux/Unix)
- **CIFS/SMB/SMBFS** - Windows/Samba network shares
- **SSHFS** - SSH-based filesystem mounts (fuse.sshfs)
- **GlusterFS** - Distributed/clustered filesystem
- **Ceph** - Distributed object/block/file storage

**Features**:
- Parses `mount` command output
- Regex-based mount line parsing: `source on mountpoint type fstype (options)`
- Verifies mount accessibility using `os.path.ismount()` and `os.access()`
- Reports inaccessible mounts with warning status

**Technical Details**:
- ~50 lines of code in `check_remote_mounts()` method
- New result category: `mounts`
- No external dependencies

**Example Output**:
```
[REMOTE MOUNTS]
✓ NFS4: 192.168.1.100:/storage → /mnt/nfs-share
⚠ CIFS: //fileserver/backup → /mnt/backup - NOT ACCESSIBLE
```

---

#### Systemd Service Issue Detection (New feature)
Comprehensive systemd service health monitoring:

**Failed Service Detection**:
- Command: `systemctl list-units --state=failed --no-pager --no-legend --plain`
- Extracts service names with bullet character filtering
- Retrieves error messages from `systemctl status`
- Removes ANSI color codes for clean output
- Limits error messages to 150 characters for readability

**Inactive Enabled Service Detection**:
- Command: `systemctl list-unit-files --state=enabled`
- Checks if enabled services are actually running
- Uses `systemctl is-active` for status verification
- Performance optimized: checks first 50 enabled services only

**Requirements**:
- Root/sudo privileges required for full functionality
- Non-root users see: "Skipped (requires root privileges)"

**Technical Details**:
- ~70 lines of code in `check_failed_systemd_services()` method
- New result category: `systemd_issues`
- Regex for ANSI code removal: `\x1b\[[0-9;]*m`

**Example Output**:
```
[SYSTEMD SERVICE ISSUES]
🔴 FAILED: postgresql.service - Active: failed (Result: exit-code)
⚠ ENABLED but INACTIVE: redis.service
✓ All enabled systemd services are running
```

---

### 🔄 Changed

#### Output Behavior
- **Removed "NOT DETECTED" messages** across all detection categories
- Services not found are no longer displayed
- Only detected/found items appear in output
- Results in cleaner, more focused diagnostic reports
- Affected sections:
  - Services: No "NOT INSTALLED" messages
  - Cloud Apps: No "NOT DETECTED" messages
  - WordPress: No "NOT DETECTED" message
  - Remote Mounts: No "No remote mounts detected" message

#### Code Structure
- **File size**: Increased from ~650 to 846 lines (+196 lines, +30%)
- **Result categories**: Added 3 new categories (`wordpress`, `mounts`, `systemd_issues`)
- **Display sections**: Added 3 new output sections
- **Method count**: Added 3 new detection methods

#### Execution Flow
Updated `run_all_checks()` method to include:
```python
self.detect_wordpress_sites()      # New
self.check_remote_mounts()          # New
self.check_failed_systemd_services() # New
```

#### Documentation
- **README.md**: Updated features list, example output, and version history
- **SUMMARY.md**: Updated project statistics and version information
- **VERSION.md**: Created comprehensive version tracking document (NEW)
- **CHANGELOG.md**: This file - complete changelog with technical details

---

### 🐛 Fixed

#### Critical: Systemd Service Name Parsing
**Issue**: Bullet characters (●, ○, ×, ✖) were being extracted as service names instead of the actual service name, resulting in unusable output like `🔴 FAILED: ●`

**Root Cause**:
- `systemctl list-units` output includes Unicode bullet characters
- String split by whitespace treated bullets as first element
- No validation of service name format

**Solution**:
1. Added `--plain` flag to systemctl commands to reduce special characters
2. Implemented bullet character detection and filtering:
   ```python
   if service_name in ['●', '○', '×', '✖']:
       if len(parts) > 1:
           service_name = parts[1]
   ```
3. Added service name validation: must contain `.` character (e.g., `.service`)
4. Falls back to second element if first is a bullet

**Impact**: Systemd section now correctly displays service names and errors

---

#### Enhancement: Systemd Error Message Extraction
**Previous Behavior**:
- Used grep to extract error messages
- Inconsistent results across systemd versions
- ANSI color codes in output
- Short error messages (100 chars)

**Improvements**:
1. Changed to parse `systemctl status --lines=0` output directly
2. Looks for "Active:" line for primary status information
3. Strips ANSI color codes using regex: `re.sub(r'\x1b\[[0-9;]*m', '', line)`
4. Increased error message length to 150 characters
5. Better handling of multi-line status output

**Result**: More informative error messages with cleaner formatting

---

#### Performance: Enabled Service Checks
**Issue**: On systems with hundreds of enabled services, checking status of each service caused significant delays (30+ seconds)

**Solution**:
- Limited check to first 50 enabled services using `head -50`
- Added `--plain` flag for faster parsing
- Removed redundant `is_active` check (was checking twice)

**Impact**:
- Systemd checks now complete in <5 seconds even on busy systems
- Still catches most common service issues
- Trade-off documented in VERSION.md

---

### 📊 Statistics

#### Code Metrics
| Metric | v1.0.0 | v1.1.0 | Change |
|--------|--------|--------|--------|
| Total Lines | 650 | 846 | +196 (+30%) |
| Methods | 11 | 14 | +3 |
| Services | 15 | 22 | +7 (+47%) |
| Cloud Apps | 6 | 7 | +1 |
| Result Categories | 6 | 9 | +3 |
| Output Sections | 6 | 9 | +3 |

#### Feature Distribution
- System Info: 4 checks (unchanged)
- Network: 3 checks (unchanged)
- Services: 22 detections (+7)
- Cloud Apps: 7 detections (+1)
- WordPress: NEW - comprehensive detection
- Mounts: NEW - network filesystem monitoring
- Systemd: NEW - service health checks
- Disk: 1 check (unchanged)
- Updates: 2 checks (unchanged)

---

### 🔧 Technical Details

#### New Methods Added
1. **`detect_wordpress_sites()`** (~90 lines)
   - Searches filesystem for WordPress installations
   - Parses PHP configuration files
   - Extracts version and database information
   - Returns: List of WordPress site dictionaries

2. **`check_remote_mounts()`** (~50 lines)
   - Parses mount command output
   - Filters network filesystem types
   - Verifies mount accessibility
   - Returns: List of remote mount dictionaries

3. **`check_failed_systemd_services()`** (~70 lines)
   - Queries systemd for failed services
   - Checks enabled but inactive services
   - Extracts error messages
   - Returns: Lists of failed and inactive services

#### Modified Methods
1. **`__init__()`**
   - Added 3 new result categories

2. **`run_all_checks()`**
   - Added 3 new method calls

3. **`display_results()`**
   - Added 3 new output sections

#### Data Structures
**SERVICES Dictionary** (lines 26-163):
```python
'jenkins': {
    'binary': 'jenkins',
    'process_names': ['jenkins', 'java'],
    'config_paths': ['/etc/default/jenkins', '/var/lib/jenkins/config.xml'],
    'systemd_name': 'jenkins'
}
# ... 6 more CI/CD tools
```

**CLOUD_APPS Dictionary** (lines 166-153):
```python
'wordpress': {
    'paths': ['/var/www/html', '/var/www', ...],
    'version_file': 'wp-includes/version.php'
}
```

---

### 🧪 Testing

#### Automated Tests Passed
- ✅ Python syntax validation: `python3 -m py_compile system_profiler.py`
- ✅ Help output generation: `--help` flag works correctly
- ✅ No-color mode: `--no-color` flag functions properly
- ✅ Import test: No errors when importing as module

#### Manual Testing Completed
- ✅ Non-root execution with warnings
- ✅ Color output formatting
- ✅ Empty results handling (no crashes)
- ✅ Long output handling

#### Production Testing Required
- ⚠️ WordPress detection on live hosting servers
- ⚠️ Systemd checks with actual failed services
- ⚠️ Remote mount detection on servers with NFS/CIFS
- ⚠️ CI/CD tool detection on build servers

---

### 📦 Dependencies

**No new dependencies added** - Still pure Python 3 standard library:
- `subprocess` - Command execution
- `os` - File system operations
- `sys` - System parameters
- `socket` - Network operations
- `re` - Regular expressions
- `glob` - File pattern matching
- `datetime` - Not actively used (imported but unused)

---

### ⚠️ Breaking Changes

**None** - Fully backward compatible with v1.0.0

---

### 🔜 Upgrade Path

#### From v1.0.0 to v1.1.0

**Steps**:
1. Backup current version (optional): `cp system_profiler.py system_profiler.py.v1.0.0`
2. Replace with new version: `cp system_profiler.py.new system_profiler.py`
3. Run as before: `sudo python3 system_profiler.py`

**Changes You'll See**:
- Additional CI/CD services detected (if installed)
- New WordPress section (if WordPress found)
- New Remote Mounts section (if network mounts exist)
- New Systemd Issues section (if running as root)
- Cleaner output (no "NOT DETECTED" messages)

**No changes needed to**:
- Command-line usage
- Output parsing (if automated)
- File permissions
- Installation location

---

### 📝 Notes for Future Versions

#### Potential v1.2.0 Features
- JSON output format option (`--json` flag)
- Configuration file support (`~/.system_profiler.conf`)
- WordPress plugin detection
- Docker container listing
- SSL certificate expiration checks
- Memory usage analysis
- Firewall rule detection

#### Known Technical Debt
- `datetime` module imported but unused (line 13)
- Some error handling could be more specific
- No unit tests (all testing is manual)
- WordPress search could be more efficient with parallel find

#### Performance Considerations
- WordPress detection can be slow on large filesystems
- Consider adding `--quick` mode that skips slow checks
- Systemd check limited to 50 services (could be configurable)

---

## [1.0.0] - 2026-02-12

### 🎉 Initial Release

#### Summary
First production release of the System Service Profiler - a Python-based diagnostic tool for Linux server assessment. Inspired by cPanel's SSP but designed for generic Linux environments.

#### ✨ Features

**System Information**:
- OS detection via `/etc/os-release`
- Kernel version from `uname -r`
- System uptime (formatted)
- Load average (1, 5, 15 minute)

**Network Diagnostics**:
- DNS resolution test (google.com)
- Outbound connectivity test (8.8.8.8:53)
- Primary network interface detection
- IP address display

**Service Detection** (15 services):

*Web Servers*:
- Apache (httpd/apache2)
- NGINX

*Databases*:
- MySQL/MariaDB
- PostgreSQL
- MongoDB
- Redis

*Container Platforms*:
- Docker
- Kubernetes (kubelet)
- Podman

*Other Services*:
- SSH (sshd)
- PHP-FPM
- Memcached
- Elasticsearch
- RabbitMQ
- Varnish

**Cloud Application Detection** (6 applications):
- Nextcloud
- ownCloud
- Seafile
- Webmin
- Plesk
- DirectAdmin

**Disk Space Analysis**:
- Usage percentage for all mount points
- Color-coded warnings:
  - Green: < 80% used
  - Yellow: 80-90% used
  - Red: > 90% used
- Size information (used/total)

**System Updates**:
- Package manager detection (apt/yum/dnf)
- Available update count
- Security update detection
- Color-coded urgency

**User Experience**:
- Color-coded terminal output
- Clear severity indicators (✓, ⚠, 🔴, ✗)
- Organized sections for easy scanning
- Root privilege detection
- Execution completes in under 10 seconds
- `--no-color` flag for logging
- `--help` flag for usage information

#### 📊 Statistics
- **Lines of Code**: 650
- **Methods**: 11
- **Services Detected**: 15
- **Cloud Apps Detected**: 6
- **Result Categories**: 6
- **Dependencies**: 0 (pure stdlib)

#### 🔧 Technical Architecture

**Class Structure**:
```
SystemProfiler
├── __init__()
├── run_command()
├── format_message()
├── add_result()
├── detect_os_info()
├── check_network_connectivity()
├── check_service_status()
├── check_services()
├── detect_cloud_apps()
├── check_disk_usage()
├── check_updates()
├── run_all_checks()
└── display_results()
```

**Data Structures**:
- `SERVICES` - Service definition dictionary
- `CLOUD_APPS` - Cloud application paths dictionary
- `Colors` - ANSI color code class
- `results` - Nested dictionary for check results

#### 📦 Deliverables
- `system_profiler.py` - Main executable (650 lines)
- `README.md` - User documentation (200 lines)
- `EXAMPLES.md` - Usage examples (200 lines)
- `SUMMARY.md` - Project summary (275 lines)

#### 🎯 Design Goals Achieved
- ✅ Pure Python 3 (no external dependencies)
- ✅ Single file distribution
- ✅ Under 10-second execution time
- ✅ Modular, extensible architecture
- ✅ Color-coded output
- ✅ Root privilege handling
- ✅ Cross-distribution support (Debian/RHEL)

#### 🔒 Security
- Read-only operations
- No external network calls (except connectivity tests)
- No data transmission
- No file modifications
- Safe command execution with timeout protection

#### 📝 Known Limitations
- Requires root/sudo for complete service information
- Some checks may not work on non-standard configurations
- Package update checks may be slow on first run
- Limited to Debian-based and RHEL-based distributions

---

## Version Comparison Table

| Feature | v1.0.0 | v1.1.0 | v1.2.0 | v1.3.0 |
|---------|--------|--------|--------|--------|
| **Release Date** | 2026-02-12 | 2026-02-12 | 2026-02-12 | 2026-02-12 |
| **Code Size** | 650 lines | 846 lines | 1090 lines | 1462 lines |
| **Services** | 15 | 22 | 22 | 22 |
| **Cloud Apps** | 6 | 7 | 7 | 7 |
| **WordPress Detection** | ❌ | ✅ | ✅ | ✅ |
| **Remote Mounts** | ❌ | ✅ | ✅ | ✅ |
| **Systemd Health** | ❌ | ✅ | ✅ | ✅ |
| **CI/CD Detection** | ❌ | ✅ | ✅ | ✅ |
| **Docker Diagnostics** | ❌ | ❌ | ✅ (`--docker`) | ✅ (`--docker`) |
| **Kubernetes Diagnostics** | ❌ | ❌ | ❌ | ✅ (`--k8s`) |
| **Output Modes** | 1 | 1 | 2 | 3 (normal + Docker + K8s) |
| **Output Filtering** | Shows all | Shows only found | Shows only found | Shows only found |
| **Result Categories** | 6 | 9 | 14 | 23 |
| **Command Flags** | 2 | 2 | 3 | 4 |
| **Dependencies** | 0 | 0 | 0 | 0 |

---

**Changelog Maintained By**: Development Team
**Last Updated**: 2026-02-12
**Format Version**: 1.0.0 (Keep a Changelog)
