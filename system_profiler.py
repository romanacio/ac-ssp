#!/usr/bin/env python3
"""
System Service Profiler
A diagnostic tool for support engineers to quickly assess server state
"""

import subprocess
import os
import sys
import socket
import re
import glob
from datetime import datetime

# ANSI Color codes
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# Service definitions for easy extension
SERVICES = {
    'apache': {
        'binary': 'httpd',
        'alt_binary': 'apache2',
        'process_names': ['httpd', 'apache2'],
        'config_paths': ['/etc/httpd/conf/httpd.conf', '/etc/apache2/apache2.conf'],
        'systemd_name': 'httpd',
        'alt_systemd': 'apache2'
    },
    'nginx': {
        'binary': 'nginx',
        'process_names': ['nginx'],
        'config_paths': ['/etc/nginx/nginx.conf'],
        'systemd_name': 'nginx'
    },
    'mysql': {
        'binary': 'mysqld',
        'alt_binary': 'mariadb',
        'process_names': ['mysqld', 'mariadbd'],
        'config_paths': ['/etc/my.cnf', '/etc/mysql/my.cnf', '/etc/mysql/mysql.conf.d/mysqld.cnf'],
        'systemd_name': 'mysqld',
        'alt_systemd': 'mariadb'
    },
    'postgresql': {
        'binary': 'postgres',
        'process_names': ['postgres'],
        'config_paths': ['/etc/postgresql/*/main/postgresql.conf', '/var/lib/pgsql/data/postgresql.conf'],
        'systemd_name': 'postgresql'
    },
    'docker': {
        'binary': 'dockerd',
        'process_names': ['dockerd'],
        'config_paths': ['/etc/docker/daemon.json'],
        'systemd_name': 'docker'
    },
    'redis': {
        'binary': 'redis-server',
        'process_names': ['redis-server'],
        'config_paths': ['/etc/redis/redis.conf', '/etc/redis.conf'],
        'systemd_name': 'redis'
    },
    'mongodb': {
        'binary': 'mongod',
        'process_names': ['mongod'],
        'config_paths': ['/etc/mongod.conf'],
        'systemd_name': 'mongod'
    },
    'sshd': {
        'binary': 'sshd',
        'process_names': ['sshd'],
        'config_paths': ['/etc/ssh/sshd_config'],
        'systemd_name': 'sshd'
    },
    'php-fpm': {
        'binary': 'php-fpm',
        'process_names': ['php-fpm'],
        'config_paths': ['/etc/php-fpm.conf', '/etc/php/*/fpm/php-fpm.conf'],
        'systemd_name': 'php-fpm'
    },
    'memcached': {
        'binary': 'memcached',
        'process_names': ['memcached'],
        'config_paths': ['/etc/memcached.conf'],
        'systemd_name': 'memcached'
    },
    'elasticsearch': {
        'binary': 'elasticsearch',
        'process_names': ['elasticsearch'],
        'config_paths': ['/etc/elasticsearch/elasticsearch.yml'],
        'systemd_name': 'elasticsearch'
    },
    'rabbitmq': {
        'binary': 'rabbitmq-server',
        'process_names': ['rabbitmq-server', 'beam.smp'],
        'config_paths': ['/etc/rabbitmq/rabbitmq.conf'],
        'systemd_name': 'rabbitmq-server'
    },
    'varnish': {
        'binary': 'varnishd',
        'process_names': ['varnishd'],
        'config_paths': ['/etc/varnish/default.vcl'],
        'systemd_name': 'varnish'
    },
    'kubernetes': {
        'binary': 'kubelet',
        'process_names': ['kubelet'],
        'config_paths': ['/etc/kubernetes/kubelet.conf'],
        'systemd_name': 'kubelet'
    },
    'podman': {
        'binary': 'podman',
        'process_names': ['podman'],
        'config_paths': ['/etc/containers/containers.conf'],
        'systemd_name': 'podman'
    },
    'jenkins': {
        'binary': 'jenkins',
        'process_names': ['jenkins', 'java'],
        'config_paths': ['/etc/default/jenkins', '/var/lib/jenkins/config.xml'],
        'systemd_name': 'jenkins'
    },
    'gitlab-runner': {
        'binary': 'gitlab-runner',
        'process_names': ['gitlab-runner'],
        'config_paths': ['/etc/gitlab-runner/config.toml'],
        'systemd_name': 'gitlab-runner'
    },
    'teamcity': {
        'binary': 'teamcity-server',
        'process_names': ['teamcity'],
        'config_paths': ['/opt/teamcity/conf/server.xml'],
        'systemd_name': 'teamcity'
    },
    'bamboo': {
        'binary': 'bamboo',
        'process_names': ['bamboo'],
        'config_paths': ['/opt/atlassian/bamboo/conf/server.xml'],
        'systemd_name': 'bamboo'
    },
    'drone': {
        'binary': 'drone-server',
        'process_names': ['drone-server', 'drone-agent'],
        'config_paths': ['/etc/drone/server.env'],
        'systemd_name': 'drone'
    },
    'circleci': {
        'binary': 'circleci',
        'process_names': ['circleci'],
        'config_paths': ['/opt/circleci/config.yaml'],
        'systemd_name': 'circleci'
    },
    'buildkite-agent': {
        'binary': 'buildkite-agent',
        'process_names': ['buildkite-agent'],
        'config_paths': ['/etc/buildkite-agent/buildkite-agent.cfg'],
        'systemd_name': 'buildkite-agent'
    }
}

# Cloud applications and control panels
CLOUD_APPS = {
    'nextcloud': {
        'paths': ['/var/www/nextcloud', '/var/www/html/nextcloud', '/usr/share/nextcloud'],
        'version_file': 'version.php'
    },
    'owncloud': {
        'paths': ['/var/www/owncloud', '/var/www/html/owncloud'],
        'version_file': 'version.php'
    },
    'seafile': {
        'paths': ['/opt/seafile', '/home/seafile'],
        'version_file': 'seafile-server-latest'
    },
    'webmin': {
        'paths': ['/etc/webmin', '/usr/share/webmin'],
        'version_file': 'version'
    },
    'plesk': {
        'paths': ['/usr/local/psa'],
        'version_file': 'version'
    },
    'directadmin': {
        'paths': ['/usr/local/directadmin'],
        'version_file': 'conf/directadmin.conf'
    },
    'wordpress': {
        'paths': ['/var/www/html', '/var/www', '/usr/share/nginx/html', '/home/*/public_html'],
        'version_file': 'wp-includes/version.php'
    }
}


class SystemProfiler:
    def __init__(self, use_color=True, docker_mode=False, k8s_mode=False):
        self.use_color = use_color
        self.docker_mode = docker_mode
        self.k8s_mode = k8s_mode
        self.results = {
            'system': [],
            'network': [],
            'services': [],
            'cloud_apps': [],
            'wordpress': [],
            'mounts': [],
            'systemd_issues': [],
            'disk': [],
            'updates': [],
            # Docker-specific categories
            'docker_service': [],
            'docker_containers': [],
            'docker_stopped': [],
            'docker_errors': [],
            'docker_resources': [],
            'docker_ports': [],
            # Kubernetes-specific categories
            'k8s_env': [],
            'k8s_cluster': [],
            'k8s_nodes': [],
            'k8s_pods': [],
            'k8s_deployments': [],
            'k8s_services': [],
            'k8s_storage': [],
            'k8s_events': [],
            'k8s_summary': [],
            # Normal mode additional categories
            'apache_proxy': [],
            'filesystem': []
        }
        self.is_root = os.geteuid() == 0

    def run_command(self, cmd, timeout=5, check_output=True):
        """Execute a system command and return output"""
        try:
            if isinstance(cmd, str):
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
            else:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )

            if check_output and result.returncode == 0:
                return result.stdout.strip()
            elif not check_output:
                return result.stdout.strip(), result.returncode
            return None
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            return None

    def format_message(self, severity, symbol, message):
        """Format output with color codes"""
        if not self.use_color:
            return f"{symbol} {message}"

        color_map = {
            'success': Colors.GREEN,
            'warning': Colors.YELLOW,
            'critical': Colors.RED,
            'info': Colors.BLUE
        }

        color = color_map.get(severity, Colors.RESET)
        return f"{color}{symbol}{Colors.RESET} {message}"

    def add_result(self, category, severity, symbol, message):
        """Add a result to the results dictionary"""
        self.results[category].append((severity, symbol, message))

    def detect_os_info(self):
        """Detect operating system information"""
        # Read /etc/os-release
        os_name = "Unknown"
        os_version = "Unknown"

        if os.path.exists('/etc/os-release'):
            try:
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('PRETTY_NAME='):
                            os_name = line.split('=', 1)[1].strip().strip('"')
                            break
            except:
                pass

        # Kernel version
        kernel = self.run_command('uname -r')
        if not kernel:
            kernel = "Unknown"

        # Uptime
        uptime_output = self.run_command('uptime -p')
        if not uptime_output:
            uptime_output = "Unknown"
        else:
            uptime_output = uptime_output.replace('up ', '')

        # Load average
        load_avg = "Unknown"
        if os.path.exists('/proc/loadavg'):
            try:
                with open('/proc/loadavg', 'r') as f:
                    load_parts = f.read().strip().split()[:3]
                    load_avg = ', '.join(load_parts)
            except:
                pass

        self.add_result('system', 'success', '✓', f"OS: {os_name}")
        self.add_result('system', 'success', '✓', f"Kernel: {kernel}")
        self.add_result('system', 'success', '✓', f"Uptime: {uptime_output}")
        self.add_result('system', 'info', '✓', f"Load Average: {load_avg}")

    def check_network_connectivity(self):
        """Check DNS resolution and outbound connectivity"""
        # DNS Resolution test
        dns_working = False
        try:
            socket.getaddrinfo('google.com', 80, socket.AF_INET)
            self.add_result('network', 'success', '✓', "DNS Resolution: Working (google.com resolves)")
            dns_working = True
        except socket.gaierror:
            self.add_result('network', 'critical', '🔴', "DNS Resolution: FAILED")
        except Exception:
            self.add_result('network', 'warning', '⚠', "DNS Resolution: Unable to test")

        # Outbound connectivity test
        if dns_working:
            try:
                sock = socket.create_connection(('8.8.8.8', 53), timeout=3)
                sock.close()
                self.add_result('network', 'success', '✓', "Outbound Connectivity: Working")
            except (socket.timeout, socket.error):
                self.add_result('network', 'critical', '🔴', "Outbound Connectivity: FAILED")
            except Exception:
                self.add_result('network', 'warning', '⚠', "Outbound Connectivity: Unable to test")

        # Primary network interface
        interface_info = self.run_command(r"ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -1")
        interface_name = self.run_command("ip route | grep default | awk '{print $5}' | head -1")

        if interface_info and interface_name:
            self.add_result('network', 'info', '✓', f"Primary Interface: {interface_name} ({interface_info})")
        elif interface_info:
            self.add_result('network', 'info', '✓', f"Primary IP: {interface_info}")

    def check_service_status(self, service_name, service_config):
        """Check if a service is running and get its details"""
        binary = service_config.get('binary')
        alt_binary = service_config.get('alt_binary')
        process_names = service_config.get('process_names', [])
        config_paths = service_config.get('config_paths', [])
        systemd_name = service_config.get('systemd_name')
        alt_systemd = service_config.get('alt_systemd')

        is_running = False
        version = None
        config_file = None

        # Try systemctl first (fastest)
        for svc_name in [systemd_name, alt_systemd]:
            if svc_name:
                status = self.run_command(f'systemctl is-active {svc_name} 2>/dev/null')
                if status == 'active':
                    is_running = True
                    break

        # Fallback to process check
        if not is_running:
            ps_output = self.run_command('ps aux')
            if ps_output:
                for proc_name in process_names:
                    if proc_name in ps_output:
                        is_running = True
                        break

        # Check if installed (even if not running)
        installed = False
        for bin_name in [binary, alt_binary]:
            if bin_name:
                which_result = self.run_command(f'which {bin_name}')
                if which_result:
                    installed = True
                    # Try to get version
                    for version_flag in ['--version', '-v', '-V', 'version']:
                        ver_output = self.run_command(f'{bin_name} {version_flag} 2>&1 | head -1')
                        if ver_output and len(ver_output) < 200:
                            # Extract version number
                            ver_match = re.search(r'(\d+\.\d+[\.\d]*)', ver_output)
                            if ver_match:
                                version = ver_match.group(1)
                                break
                    break

        # Find config file
        for path_pattern in config_paths:
            if '*' in path_pattern:
                matches = glob.glob(path_pattern)
                if matches:
                    config_file = matches[0]
                    break
            elif os.path.exists(path_pattern):
                config_file = path_pattern
                break

        # Format output
        if is_running:
            msg = f"{service_name.upper()}: RUNNING"
            if version:
                msg += f" (v{version})"
            if config_file:
                msg += f" - Config: {config_file}"

            # Add hint for Docker in normal mode
            if service_name == 'docker' and not self.docker_mode:
                self.add_result('services', 'success', '✓', msg)
                self.add_result('services', 'info', 'ℹ', "  Run with --docker flag for detailed container diagnostics")
            # Add hint for Kubernetes in normal mode
            elif service_name == 'kubernetes' and not self.k8s_mode:
                self.add_result('services', 'success', '✓', msg)
                self.add_result('services', 'info', 'ℹ', "  Run with --k8s flag for detailed Kubernetes diagnostics")
            else:
                self.add_result('services', 'success', '✓', msg)
        elif installed:
            msg = f"{service_name.upper()}: INSTALLED but NOT RUNNING"
            if config_file:
                msg += f" - Config: {config_file}"
            self.add_result('services', 'warning', '⚠', msg)

    def check_services(self):
        """Check all defined services"""
        for service_name, service_config in SERVICES.items():
            self.check_service_status(service_name, service_config)

    def detect_cloud_apps(self):
        """Detect cloud applications and control panels"""
        for app_name, app_config in CLOUD_APPS.items():
            detected = False
            app_path = None
            version = None

            for path in app_config['paths']:
                if os.path.exists(path) and os.path.isdir(path):
                    detected = True
                    app_path = path

                    # Try to get version
                    version_file = os.path.join(path, app_config.get('version_file', ''))
                    if os.path.exists(version_file):
                        try:
                            with open(version_file, 'r') as f:
                                content = f.read(500)  # Read first 500 chars
                                # Look for version pattern
                                ver_match = re.search(r'(\d+\.\d+[\.\d]*)', content)
                                if ver_match:
                                    version = ver_match.group(1)
                        except:
                            pass
                    break

            if detected:
                msg = f"{app_name.upper()}: DETECTED"
                if version:
                    msg += f" (v{version})"
                if app_path:
                    msg += f" - {app_path}"
                self.add_result('cloud_apps', 'success', '✓', msg)

    def detect_wordpress_sites(self):
        """Detect WordPress installations"""
        wordpress_sites = []

        # Common web root directories to search
        search_paths = [
            '/var/www/html',
            '/var/www',
            '/usr/share/nginx/html',
            '/opt/bitnami/wordpress',
            '/srv/www'
        ]

        # Also check user home directories
        home_dirs = self.run_command('ls /home 2>/dev/null')
        if home_dirs:
            for user in home_dirs.split('\n'):
                if user.strip():
                    search_paths.append(f'/home/{user.strip()}/public_html')
                    search_paths.append(f'/home/{user.strip()}/www')

        # Search for wp-config.php files
        for search_path in search_paths:
            if not os.path.exists(search_path):
                continue

            # Find wp-config.php files
            find_cmd = f"find {search_path} -maxdepth 3 -name 'wp-config.php' 2>/dev/null"
            wp_configs = self.run_command(find_cmd, timeout=10)

            if wp_configs:
                for config_path in wp_configs.split('\n'):
                    if not config_path.strip():
                        continue

                    site_path = os.path.dirname(config_path)
                    version = None
                    is_multisite = False
                    db_name = None

                    # Get WordPress version
                    version_file = os.path.join(site_path, 'wp-includes/version.php')
                    if os.path.exists(version_file):
                        try:
                            with open(version_file, 'r') as f:
                                content = f.read(1000)
                                ver_match = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", content)
                                if ver_match:
                                    version = ver_match.group(1)
                        except:
                            pass

                    # Check if multisite
                    try:
                        with open(config_path, 'r') as f:
                            config_content = f.read(5000)
                            if 'MULTISITE' in config_content or 'SUBDOMAIN_INSTALL' in config_content:
                                is_multisite = True

                            # Extract database name
                            db_match = re.search(r"define\s*\(\s*['\"]DB_NAME['\"],\s*['\"]([^'\"]+)['\"]", config_content)
                            if db_match:
                                db_name = db_match.group(1)
                    except:
                        pass

                    wordpress_sites.append({
                        'path': site_path,
                        'version': version,
                        'multisite': is_multisite,
                        'db_name': db_name
                    })

        # Display results
        if wordpress_sites:
            for site in wordpress_sites:
                msg = f"WORDPRESS: DETECTED - {site['path']}"
                if site['version']:
                    msg += f" (v{site['version']})"
                if site['multisite']:
                    msg += " [MULTISITE]"
                if site['db_name']:
                    msg += f" - DB: {site['db_name']}"
                self.add_result('wordpress', 'success', '✓', msg)

            # Check for WP-CLI
            wp_cli = self.run_command('which wp')
            if wp_cli:
                wp_version = self.run_command('wp --version 2>/dev/null')
                if wp_version:
                    self.add_result('wordpress', 'info', '✓', f"WP-CLI: INSTALLED ({wp_version})")

    def check_remote_mounts(self):
        """Check for remote/network mounted filesystems"""
        # Read mount information
        mount_output = self.run_command('mount')

        if not mount_output:
            self.add_result('mounts', 'warning', '⚠', "Unable to read mount information")
            return

        # Network filesystem types to look for
        network_fs_types = ['nfs', 'nfs4', 'cifs', 'smb', 'smbfs', 'fuse.sshfs', 'glusterfs', 'ceph']

        remote_mounts = []

        for line in mount_output.split('\n'):
            for fs_type in network_fs_types:
                if f'type {fs_type}' in line:
                    # Parse mount line
                    # Format: source on mountpoint type fstype (options)
                    match = re.match(r'(.+?)\s+on\s+(.+?)\s+type\s+(\S+)\s+\((.+)\)', line)
                    if match:
                        source = match.group(1)
                        mountpoint = match.group(2)
                        fstype = match.group(3)
                        options = match.group(4)

                        # Check if mount is accessible
                        accessible = os.path.ismount(mountpoint) and os.access(mountpoint, os.R_OK)

                        remote_mounts.append({
                            'source': source,
                            'mountpoint': mountpoint,
                            'type': fstype,
                            'accessible': accessible,
                            'options': options
                        })
                    break

        # Display results
        if remote_mounts:
            for mount in remote_mounts:
                msg = f"{mount['type'].upper()}: {mount['source']} → {mount['mountpoint']}"

                if mount['accessible']:
                    self.add_result('mounts', 'success', '✓', msg)
                else:
                    self.add_result('mounts', 'warning', '⚠', f"{msg} - NOT ACCESSIBLE")

    def check_failed_systemd_services(self):
        """Check for failed or inactive systemd services"""
        if not self.is_root:
            self.add_result('systemd_issues', 'info', 'ℹ', "Skipped (requires root privileges)")
            return

        # Check for failed services
        failed_output = self.run_command('systemctl list-units --state=failed --no-pager --no-legend --plain')

        failed_services = []
        if failed_output:
            for line in failed_output.split('\n'):
                if line.strip():
                    parts = line.split()
                    if parts:
                        # The service name is the first part (or second if first is a bullet)
                        service_name = parts[0]
                        # Skip if it's just a bullet or special character
                        if service_name in ['●', '○', '×', '✖']:
                            if len(parts) > 1:
                                service_name = parts[1]
                            else:
                                continue
                        # Only add if it ends with .service or similar
                        if '.' in service_name:
                            failed_services.append(service_name)

        # Check for enabled but inactive services (sample a subset to avoid long delays)
        enabled_output = self.run_command('systemctl list-unit-files --state=enabled --no-pager --no-legend --plain 2>/dev/null | grep ".service" | head -50')
        inactive_enabled = []

        if enabled_output:
            for line in enabled_output.split('\n'):
                if line.strip() and '.service' in line:
                    parts = line.split()
                    if parts:
                        service_name = parts[0]
                        # Check if service is active
                        is_active = self.run_command(f'systemctl is-active {service_name} 2>/dev/null')
                        if is_active and is_active not in ['active', 'activating']:
                            inactive_enabled.append((service_name, is_active))

        # Display failed services
        if failed_services:
            for service in failed_services:
                # Try to get the error message from status
                status_output = self.run_command(f'systemctl status {service} --no-pager --lines=0 2>/dev/null')
                msg = f"FAILED: {service}"

                if status_output:
                    # Look for the main status line
                    for line in status_output.split('\n'):
                        if 'Active:' in line or 'failed' in line.lower():
                            # Clean up the line and extract meaningful info
                            clean_line = line.strip()
                            # Remove ANSI color codes
                            clean_line = re.sub(r'\x1b\[[0-9;]*m', '', clean_line)
                            if clean_line and len(clean_line) > 10:
                                error_msg = clean_line[:150]  # Limit length
                                msg += f" - {error_msg}"
                                break

                self.add_result('systemd_issues', 'critical', '🔴', msg)

        # Display enabled but inactive services
        if inactive_enabled:
            for service, status in inactive_enabled:
                self.add_result('systemd_issues', 'warning', '⚠', f"ENABLED but {status.upper()}: {service}")

        # Summary message if all is well
        if not failed_services and not inactive_enabled:
            self.add_result('systemd_issues', 'success', '✓', "All enabled systemd services are running")

    def check_apache_reverse_proxy(self):
        """Validate Apache reverse proxy configuration and backend connectivity"""
        # Find Apache config files
        config_file = None
        for path in SERVICES['apache']['config_paths']:
            if os.path.exists(path):
                config_file = path
                break

        if not config_file:
            return

        # Gather all config content (main + includes)
        all_configs = []

        try:
            with open(config_file, 'r') as f:
                all_configs.append((config_file, f.read(10000)))
        except (IOError, PermissionError):
            return

        # Check common include directories
        include_dirs = [
            '/etc/apache2/sites-enabled/',
            '/etc/httpd/conf.d/',
            '/etc/apache2/conf-enabled/'
        ]
        for inc_dir in include_dirs:
            if os.path.isdir(inc_dir):
                try:
                    for fname in os.listdir(inc_dir):
                        fpath = os.path.join(inc_dir, fname)
                        if os.path.isfile(fpath) and fname.endswith('.conf'):
                            try:
                                with open(fpath, 'r') as f:
                                    all_configs.append((fpath, f.read(10000)))
                            except (IOError, PermissionError):
                                pass
                except (IOError, PermissionError):
                    pass

        # Parse ProxyPass directives
        proxy_pattern = re.compile(
            r'^\s*ProxyPass\s+\S+\s+(https?://[\w\.\-]+(?::(\d+))?(?:/\S*)?)',
            re.IGNORECASE | re.MULTILINE
        )

        proxy_backends = []
        for conf_path, content in all_configs:
            for match in proxy_pattern.finditer(content):
                backend_url = match.group(1)
                port = match.group(2)
                host_match = re.search(r'https?://([\w\.\-]+)', backend_url)
                if host_match:
                    host = host_match.group(1)
                    if not port:
                        port = '443' if backend_url.startswith('https') else '80'
                    proxy_backends.append({
                        'url': backend_url,
                        'host': host,
                        'port': int(port),
                        'config_file': conf_path
                    })

        if not proxy_backends:
            return

        # Test connectivity to each backend
        for backend in proxy_backends:
            try:
                sock = socket.create_connection(
                    (backend['host'], backend['port']),
                    timeout=3
                )
                sock.close()
                self.add_result('apache_proxy', 'success', '✓',
                    f"ProxyPass -> {backend['url']} - Reachable")
            except (socket.timeout, socket.error, OSError):
                self.add_result('apache_proxy', 'critical', '🔴',
                    f"ProxyPass -> {backend['url']} - UNREACHABLE (from {backend['config_file']})")

        # Cross-reference with Docker container ports if docker is available
        docker_check = self.run_command('which docker 2>/dev/null')
        if docker_check:
            docker_ports_output = self.run_command(
                'docker ps --format "{{.Names}}|{{.Ports}}" 2>/dev/null',
                timeout=10
            )
            if docker_ports_output:
                exposed_ports = set()
                for line in docker_ports_output.split('\n'):
                    if not line.strip():
                        continue
                    port_matches = re.findall(r':(\d+)->', line)
                    for p in port_matches:
                        exposed_ports.add(int(p))

                for backend in proxy_backends:
                    if backend['host'] in ('localhost', '127.0.0.1', '::1'):
                        if backend['port'] not in exposed_ports:
                            self.add_result('apache_proxy', 'warning', '⚠',
                                f"ProxyPass port {backend['port']} ({backend['url']}) "
                                f"not found in Docker exposed ports")

    def check_apache_error_logs(self):
        """Analyze Apache error logs for proxy backend connection failures"""
        log_paths = [
            '/var/log/apache2/error.log',
            '/var/log/httpd/error_log',
            '/var/log/apache2/error_log',
            '/var/log/httpd/error.log'
        ]

        log_file = None
        for path in log_paths:
            if os.path.exists(path) and os.access(path, os.R_OK):
                log_file = path
                break

        if not log_file:
            return

        log_content = self.run_command(
            f'tail -500 {log_file} 2>/dev/null',
            timeout=10
        )
        if not log_content:
            return

        # Search for AH01102: proxy backend connection refused
        ah01102_pattern = re.compile(
            r'AH01102.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?|\S+:\d+)'
        )

        occurrences = []
        for line in log_content.split('\n'):
            if 'AH01102' in line:
                match = ah01102_pattern.search(line)
                backend = match.group(1) if match else 'unknown backend'
                ts_match = re.match(r'\[([^\]]+)\]', line)
                timestamp = ts_match.group(1) if ts_match else ''
                occurrences.append({
                    'backend': backend,
                    'timestamp': timestamp
                })

        if not occurrences:
            return

        unique_backends = set(o['backend'] for o in occurrences)
        self.add_result('apache_proxy', 'warning', '⚠',
            f"Found {len(occurrences)} proxy connection refused errors (AH01102) in {log_file}")

        for backend in unique_backends:
            count = sum(1 for o in occurrences if o['backend'] == backend)
            self.add_result('apache_proxy', 'critical', '🔴',
                f"Backend {backend}: {count} connection refused error(s)")

        if occurrences[-1]['timestamp']:
            self.add_result('apache_proxy', 'info', 'ℹ',
                f"Most recent: {occurrences[-1]['timestamp']}")

    def check_filesystem_health(self):
        """Check filesystem health via dmesg errors and read-only mount detection"""
        # Part A: Parse dmesg for ext4/xfs errors
        dmesg_output = self.run_command(
            'dmesg --level=err,warn 2>/dev/null | grep -iE "(ext4|xfs).*error" | tail -10',
            timeout=10
        )
        if dmesg_output and dmesg_output.strip():
            error_lines = [l for l in dmesg_output.split('\n') if l.strip()]
            self.add_result('filesystem', 'critical', '🔴',
                f"Filesystem errors detected in dmesg ({len(error_lines)} message(s))")
            for line in error_lines[:5]:
                clean_line = line.strip()
                if len(clean_line) > 150:
                    clean_line = clean_line[:150] + '...'
                self.add_result('filesystem', 'info', 'ℹ', f"  {clean_line}")

        # Part B: Detect read-only mounted filesystems
        mount_content = None
        if os.path.exists('/proc/mounts'):
            try:
                with open('/proc/mounts', 'r') as f:
                    mount_content = f.read()
            except (IOError, PermissionError):
                pass

        if not mount_content:
            mount_content = self.run_command('mount')

        if mount_content:
            skip_fs = {
                'proc', 'sysfs', 'devpts', 'tmpfs', 'devtmpfs',
                'cgroup', 'cgroup2', 'pstore', 'securityfs',
                'debugfs', 'configfs', 'fusectl', 'mqueue',
                'hugetlbfs', 'binfmt_misc', 'tracefs', 'bpf',
                'autofs', 'efivarfs', 'ramfs', 'squashfs',
                'iso9660', 'udf', 'overlay'
            }

            for line in mount_content.split('\n'):
                if not line.strip():
                    continue

                parts = line.split()
                if len(parts) < 4:
                    continue

                # /proc/mounts format: device mountpoint fstype options ...
                device = parts[0]
                mountpoint = parts[1]
                fstype = parts[2]
                options = parts[3]

                if fstype in skip_fs:
                    continue

                option_list = options.split(',')
                if 'ro' in option_list:
                    self.add_result('filesystem', 'critical', '🔴',
                        f"READ-ONLY: {mountpoint} ({device}, {fstype})")

    def check_docker_details(self):
        """Detailed Docker diagnostics (--docker flag)"""

        # Check if Docker is installed
        docker_installed = self.run_command('which docker')
        if not docker_installed:
            self.add_result('docker_service', 'critical', '🔴', "Docker is not installed")
            return

        # Check if Docker service is running
        docker_running = self.run_command('systemctl is-active docker 2>/dev/null')
        if docker_running != 'active':
            self.add_result('docker_service', 'critical', '🔴', "Docker service is not running")
            self.add_result('docker_service', 'info', 'ℹ', "Start with: sudo systemctl start docker")
            return

        # Docker version
        version = self.run_command('docker --version 2>/dev/null')
        if version:
            self.add_result('docker_service', 'success', '✓', f"Docker Engine: {version}")

        # Docker API version mismatch check
        api_versions = self.run_command(
            'docker version --format "{{.Client.APIVersion}}|{{.Server.APIVersion}}" 2>/dev/null',
            timeout=10
        )
        if api_versions and '|' in api_versions:
            api_parts = api_versions.split('|')
            if len(api_parts) == 2:
                client_api = api_parts[0].strip()
                server_api = api_parts[1].strip()
                try:
                    client_ver = tuple(int(x) for x in client_api.split('.'))
                    server_ver = tuple(int(x) for x in server_api.split('.'))
                    if client_ver > server_ver:
                        self.add_result('docker_service', 'warning', '⚠',
                            f"API Version Mismatch: Client ({client_api}) > Server ({server_api}) - may cause compatibility issues")
                    else:
                        self.add_result('docker_service', 'success', '✓',
                            f"API Versions: Client {client_api}, Server {server_api}")
                except (ValueError, TypeError):
                    self.add_result('docker_service', 'info', '✓',
                        f"API Versions: Client {client_api}, Server {server_api}")

        # Docker socket accessibility
        socket_path = '/var/run/docker.sock'
        if os.path.exists(socket_path) and os.access(socket_path, os.R_OK):
            self.add_result('docker_service', 'success', '✓', f"Docker Socket: {socket_path} (accessible)")
        elif os.path.exists(socket_path):
            self.add_result('docker_service', 'warning', '⚠', f"Docker Socket: {socket_path} (permission denied)")
        else:
            self.add_result('docker_service', 'warning', '⚠', f"Docker Socket: {socket_path} (not found)")

        # Docker daemon status and uptime
        daemon_status = self.run_command('systemctl status docker --no-pager --lines=0 2>/dev/null')
        if daemon_status:
            for line in daemon_status.split('\n'):
                if 'Active:' in line:
                    clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line.strip())
                    self.add_result('docker_service', 'success', '✓', clean_line)
                    break

        # Docker root directory
        root_dir = self.run_command('docker info --format "{{.DockerRootDir}}" 2>/dev/null', timeout=10)
        if root_dir:
            self.add_result('docker_service', 'info', '✓', f"Docker Root Dir: {root_dir}")

        # Recent errors from journalctl
        recent_errors = self.run_command(
            'journalctl -u docker --no-pager --since "24 hours ago" '
            '-p warning..err --no-hostname -o short-iso 2>/dev/null | tail -10',
            timeout=10
        )
        if recent_errors and recent_errors.strip():
            error_lines = [line for line in recent_errors.split('\n') if line.strip()]
            if error_lines:
                for line in error_lines[-5:]:  # Last 5 errors
                    clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line)
                    if len(clean_line) > 200:
                        clean_line = clean_line[:200] + '...'
                    self.add_result('docker_errors', 'warning', '⚠', clean_line)
        else:
            self.add_result('docker_errors', 'success', '✓', "No recent errors in last 24 hours")

        # Running containers
        containers = self.run_command(
            'docker ps --format "{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}" 2>/dev/null',
            timeout=10
        )
        if containers and containers.strip():
            for line in containers.split('\n'):
                if not line.strip():
                    continue

                parts = line.split('|')
                if len(parts) < 3:
                    continue

                name = parts[0]
                image = parts[1]
                status = parts[2]
                ports = parts[3] if len(parts) > 3 else ''

                # Check health status
                health = self.run_command(
                    f'docker inspect --format "{{{{.State.Health.Status}}}}" {name} 2>/dev/null'
                )

                msg = f"{name} ({image}) - {status}"
                if ports and ports != '':
                    msg += f" - {ports}"

                severity = 'success'
                symbol = '✓'
                if health == 'unhealthy':
                    severity = 'warning'
                    symbol = '⚠'
                    msg += " (unhealthy)"
                elif health == 'starting':
                    severity = 'info'
                    symbol = 'ℹ'
                    msg += " (health: starting)"

                # Check memory limit
                mem_limit = self.run_command(
                    f'docker inspect --format "{{{{.HostConfig.Memory}}}}" {name} 2>/dev/null'
                )
                if mem_limit and mem_limit != '0':
                    try:
                        mem_bytes = int(mem_limit)
                        if mem_bytes > 0:
                            mem_mb = mem_bytes / (1024 * 1024)
                            if mem_mb >= 1024:
                                mem_str = f"{mem_mb / 1024:.1f}GB"
                            else:
                                mem_str = f"{mem_mb:.0f}MB"
                            msg += f" [Mem Limit: {mem_str}]"
                    except (ValueError, TypeError):
                        pass
                else:
                    msg += " [No Mem Limit]"

                self.add_result('docker_containers', severity, symbol, msg)
        else:
            self.add_result('docker_containers', 'info', 'ℹ', "No running containers")

        # Nextcloud AIO mastercontainer health check
        self.check_nextcloud_aio()

        # Stopped containers
        stopped = self.run_command(
            'docker ps -a --filter "status=exited" --format "{{.Names}}|{{.Image}}|{{.Status}}" 2>/dev/null',
            timeout=10
        )
        if stopped and stopped.strip():
            stopped_lines = [line for line in stopped.split('\n') if line.strip()]
            for line in stopped_lines[:10]:  # Limit to 10
                parts = line.split('|')
                if len(parts) >= 3:
                    name = parts[0]
                    image = parts[1]
                    status = parts[2]

                    # Check exit code
                    exit_code_match = re.search(r'Exited \((\d+)\)', status)
                    exit_code = exit_code_match.group(1) if exit_code_match else 'unknown'

                    msg = f"{name} ({image}) - {status}"

                    if exit_code == '137':
                        self.add_result('docker_stopped', 'critical', '🔴',
                            f"{msg} [OOM KILLED]")
                        self.add_result('docker_stopped', 'info', 'ℹ',
                            f"  Hint: Check memory limits or increase host memory for '{name}'")
                    elif exit_code == '143':
                        self.add_result('docker_stopped', 'info', '✗',
                            f"{msg} [SIGTERM]")
                    elif exit_code != '0' and exit_code != 'unknown':
                        self.add_result('docker_stopped', 'warning', '⚠', msg)
                    else:
                        self.add_result('docker_stopped', 'info', '✗', msg)

        # Port binding conflict analysis
        self.check_docker_port_conflicts()

        # Docker resources summary
        images_output = self.run_command('docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null', timeout=10)
        if images_output:
            images_count = len([line for line in images_output.split('\n') if line.strip()])
            images_size = self.run_command('docker images --format "{{.Size}}" 2>/dev/null | head -1', timeout=5)
            msg = f"Images: {images_count}"
            if images_size:
                # Get total size
                total_size_cmd = self.run_command('docker system df --format "{{.Type}}|{{.TotalCount}}|{{.Size}}" 2>/dev/null | grep "^Images"', timeout=10)
                if total_size_cmd:
                    parts = total_size_cmd.split('|')
                    if len(parts) >= 3:
                        msg += f" (Total: {parts[2]})"
            self.add_result('docker_resources', 'info', '✓', msg)

        volumes_count = self.run_command('docker volume ls -q 2>/dev/null | wc -l', timeout=5)
        if volumes_count and volumes_count.strip():
            self.add_result('docker_resources', 'info', '✓', f"Volumes: {volumes_count.strip()}")

        networks_count = self.run_command('docker network ls -q 2>/dev/null | wc -l', timeout=5)
        if networks_count and networks_count.strip():
            count = int(networks_count.strip())
            # Subtract 3 for default networks (bridge, host, none)
            custom_count = max(0, count - 3)
            msg = f"Networks: {count}"
            if custom_count > 0:
                msg += f" ({custom_count} custom)"
            self.add_result('docker_resources', 'info', '✓', msg)

        # Disk usage
        disk_usage = self.run_command('docker system df --format "table {{.Type}}\t{{.TotalCount}}\t{{.Size}}\t{{.Reclaimable}}" 2>/dev/null', timeout=10)
        if disk_usage:
            lines = disk_usage.strip().split('\n')
            if len(lines) > 1:  # Skip header
                for line in lines[1:]:
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 4:
                            resource_type = parts[0].strip()
                            size = parts[2].strip()
                            reclaimable = parts[3].strip()
                            msg = f"{resource_type}: {size}"
                            if reclaimable and reclaimable != '0B':
                                msg += f" (Reclaimable: {reclaimable})"
                                self.add_result('docker_resources', 'warning', '⚠', msg)
                            else:
                                self.add_result('docker_resources', 'info', '✓', msg)

    def check_nextcloud_aio(self):
        """Check Nextcloud AIO mastercontainer health"""
        all_containers = self.run_command(
            'docker ps -a --format "{{.Names}}|{{.Image}}|{{.Status}}" 2>/dev/null',
            timeout=10
        )
        if not all_containers:
            return

        for line in all_containers.split('\n'):
            if not line.strip():
                continue
            parts = line.split('|')
            if len(parts) < 3:
                continue

            name = parts[0]
            image = parts[1]
            status = parts[2]

            if 'nextcloud-aio-mastercontainer' not in name:
                continue

            # Found mastercontainer
            base_msg = f"Nextcloud AIO: {name} ({image}) - {status}"

            # Check for restarting state
            if 'Restarting' in status:
                self.add_result('docker_containers', 'critical', '🔴',
                    f"{base_msg} [RESTART LOOP]")
                self.add_result('docker_containers', 'info', 'ℹ',
                    f"  Check logs: docker logs {name}")
                return

            # Check health status via inspect
            health = self.run_command(
                f'docker inspect --format "{{{{.State.Health.Status}}}}" {name} 2>/dev/null'
            )
            if health == 'unhealthy':
                self.add_result('docker_containers', 'critical', '🔴',
                    f"{base_msg} [UNHEALTHY]")
                self.add_result('docker_containers', 'info', 'ℹ',
                    f"  Check logs: docker logs {name} --tail 50")
                return

            # Check exit codes for stopped mastercontainer
            exit_match = re.search(r'Exited \((\d+)\)', status)
            if exit_match:
                code = exit_match.group(1)
                if code == '0':
                    self.add_result('docker_containers', 'info', '✗',
                        f"{base_msg} [Clean shutdown]")
                elif code == '137':
                    self.add_result('docker_containers', 'critical', '🔴',
                        f"{base_msg} [OOM KILLED - Exit 137]")
                elif code == '143':
                    self.add_result('docker_containers', 'warning', '⚠',
                        f"{base_msg} [SIGTERM - Exit 143]")
                else:
                    self.add_result('docker_containers', 'warning', '⚠',
                        f"{base_msg} [Exit {code}]")
                return

            # Running and healthy
            if health == 'healthy':
                self.add_result('docker_containers', 'success', '✓',
                    f"{base_msg} [Healthy]")
            else:
                self.add_result('docker_containers', 'success', '✓', base_msg)
            return

    def check_docker_port_conflicts(self):
        """Check for port binding conflicts between Docker containers and host services"""
        containers = self.run_command(
            'docker ps --format "{{.Names}}" 2>/dev/null',
            timeout=10
        )
        if not containers or not containers.strip():
            return

        # Collect all port mappings: {host_port: [container_name, ...]}
        port_map = {}

        for container_name in containers.split('\n'):
            container_name = container_name.strip()
            if not container_name:
                continue

            port_output = self.run_command(
                f'docker port {container_name} 2>/dev/null',
                timeout=5
            )
            if not port_output:
                continue

            for port_line in port_output.split('\n'):
                if not port_line.strip():
                    continue
                # Format: "80/tcp -> 0.0.0.0:8080" or "80/tcp -> :::8080"
                match = re.search(r'->\s+[\d.:]*:(\d+)', port_line)
                if match:
                    host_port = match.group(1)
                    if host_port not in port_map:
                        port_map[host_port] = []
                    if container_name not in port_map[host_port]:
                        port_map[host_port].append(container_name)

        if not port_map:
            return

        # Check for duplicate container bindings on same host port
        for port, containers_on_port in port_map.items():
            if len(containers_on_port) > 1:
                names = ', '.join(containers_on_port)
                self.add_result('docker_ports', 'critical', '🔴',
                    f"Port {port}: CONFLICT - Multiple containers bound: {names}")

        # Check for host process conflicts on mapped ports
        has_lsof = self.run_command('which lsof 2>/dev/null')
        if has_lsof:
            for port in port_map:
                lsof_output = self.run_command(
                    f'lsof -i :{port} -sTCP:LISTEN 2>/dev/null',
                    timeout=5
                )
                if not lsof_output:
                    continue

                # Count distinct non-docker processes
                non_docker_procs = []
                for lsof_line in lsof_output.split('\n')[1:]:  # Skip header
                    if lsof_line.strip():
                        lsof_parts = lsof_line.split()
                        if lsof_parts and 'docker' not in lsof_parts[0].lower():
                            non_docker_procs.append(lsof_parts[0])

                if non_docker_procs:
                    procs = ', '.join(set(non_docker_procs))
                    container_names = ', '.join(port_map[port])
                    self.add_result('docker_ports', 'warning', '⚠',
                        f"Port {port}: Host process ({procs}) shares port with container(s): {container_names}")

        # If no conflicts found, report clean
        has_issues = any(
            sev in ('critical', 'warning')
            for sev, _, _ in self.results['docker_ports']
        )
        if not has_issues and port_map:
            self.add_result('docker_ports', 'success', '✓',
                f"No port conflicts detected across {len(port_map)} mapped port(s)")

    def check_k8s_details(self):
        """Detailed Kubernetes diagnostics (--k8s flag)"""

        # Check if kubectl is installed
        kubectl_installed = self.run_command('which kubectl')
        if not kubectl_installed:
            self.add_result('k8s_env', 'critical', '🔴', "kubectl is not installed")
            self.add_result('k8s_env', 'info', 'ℹ', "Install kubectl to use Kubernetes diagnostics")
            return

        # kubectl version
        kubectl_version = self.run_command('kubectl version --client --short 2>/dev/null')
        if not kubectl_version:
            kubectl_version = self.run_command('kubectl version --client -o json 2>/dev/null | grep -oP \'"gitVersion":"\\K[^"]+\'')
        if kubectl_version:
            self.add_result('k8s_env', 'success', '✓', f"kubectl: INSTALLED ({kubectl_version.strip()})")

        # Current context
        current_context = self.run_command('kubectl config current-context 2>/dev/null')
        if current_context:
            self.add_result('k8s_env', 'success', '✓', f"Context: {current_context.strip()} (current)")
        else:
            self.add_result('k8s_env', 'warning', '⚠', "No Kubernetes context configured")
            self.add_result('k8s_env', 'info', 'ℹ', "Configure kubectl context to connect to a cluster")
            return

        # Cluster info
        cluster_info = self.run_command('kubectl cluster-info 2>/dev/null | head -1', timeout=10)
        if cluster_info and 'running at' in cluster_info.lower():
            # Extract cluster URL
            url_match = re.search(r'https?://[^\s]+', cluster_info)
            if url_match:
                self.add_result('k8s_env', 'success', '✓', f"Cluster: {url_match.group(0)}")

        # Current namespace
        current_ns = self.run_command('kubectl config view --minify --output=jsonpath={..namespace} 2>/dev/null')
        if not current_ns:
            current_ns = 'default'
        self.add_result('k8s_env', 'info', '✓', f"Namespace: {current_ns} (current)")

        # Check cluster connectivity
        cluster_reachable = self.run_command('kubectl cluster-info 2>&1 | grep -i "running at"', timeout=10)
        if cluster_reachable:
            self.add_result('k8s_cluster', 'success', '✓', "Cluster: REACHABLE")
        else:
            self.add_result('k8s_cluster', 'critical', '🔴', "Cluster: NOT REACHABLE")
            self.add_result('k8s_cluster', 'info', 'ℹ', "Check your kubeconfig and network connectivity")
            return

        # API server response time (simple check)
        api_start = self.run_command('date +%s%3N')
        api_test = self.run_command('kubectl get --raw /healthz 2>/dev/null', timeout=5)
        api_end = self.run_command('date +%s%3N')
        if api_test == 'ok' and api_start and api_end:
            try:
                response_time = int(api_end) - int(api_start)
                self.add_result('k8s_cluster', 'success', '✓', f"API Server: HEALTHY (response time: {response_time}ms)")
            except:
                self.add_result('k8s_cluster', 'success', '✓', "API Server: HEALTHY")

        # Node status
        nodes_output = self.run_command('kubectl get nodes --no-headers 2>/dev/null', timeout=10)
        if nodes_output:
            node_lines = [line for line in nodes_output.split('\n') if line.strip()]
            total_nodes = len(node_lines)
            ready_nodes = 0
            notready_nodes = 0

            for line in node_lines:
                parts = line.split()
                if len(parts) >= 2:
                    node_name = parts[0]
                    status = parts[1]

                    if 'Ready' in status:
                        ready_nodes += 1
                    else:
                        notready_nodes += 1

            if notready_nodes > 0:
                self.add_result('k8s_cluster', 'warning', '⚠', f"Nodes: {ready_nodes}/{total_nodes} Ready ({notready_nodes} node(s) NotReady)")
            else:
                self.add_result('k8s_cluster', 'success', '✓', f"Nodes: {ready_nodes}/{total_nodes} Ready")

            # Detailed node information
            for line in node_lines[:10]:  # Limit to 10 nodes
                parts = line.split()
                if len(parts) >= 5:
                    node_name = parts[0]
                    status = parts[1]
                    roles = parts[2] if parts[2] != '<none>' else 'worker'
                    version = parts[4]

                    # Get node resource usage if metrics-server is available
                    node_metrics = self.run_command(f'kubectl top node {node_name} --no-headers 2>/dev/null', timeout=5)
                    metrics_info = ""
                    if node_metrics:
                        metrics_parts = node_metrics.split()
                        if len(metrics_parts) >= 5:
                            cpu_usage = metrics_parts[1]
                            mem_usage = metrics_parts[3]
                            metrics_info = f" - CPU: {cpu_usage}, Memory: {mem_usage}"

                    msg = f"{node_name}: {status}"
                    if roles != '<none>':
                        msg += f",{roles}"
                    msg += f" ({version}){metrics_info}"

                    if 'Ready' in status:
                        self.add_result('k8s_nodes', 'success', '✓', msg)
                    elif 'NotReady' in status:
                        self.add_result('k8s_nodes', 'critical', '🔴', msg)
                    else:
                        self.add_result('k8s_nodes', 'warning', '⚠', msg)

        # Pod issues (CrashLoopBackOff, Pending, ImagePullBackOff, etc.)
        problem_pods = self.run_command(
            'kubectl get pods --all-namespaces --field-selector=status.phase!=Running,status.phase!=Succeeded '
            '--no-headers 2>/dev/null',
            timeout=10
        )

        if problem_pods and problem_pods.strip():
            pod_lines = [line for line in problem_pods.split('\n') if line.strip()]
            for line in pod_lines[:20]:  # Limit to 20 problem pods
                parts = line.split()
                if len(parts) >= 4:
                    namespace = parts[0]
                    pod_name = parts[1]
                    ready = parts[2]
                    status = parts[3]
                    restarts = parts[4] if len(parts) > 4 else '0'

                    msg = f"{status}: {pod_name} (namespace: {namespace})"
                    if restarts != '0':
                        msg += f" - Restarts: {restarts}"

                    # Get pod age
                    if len(parts) >= 6:
                        age = parts[5]
                        msg += f" - Age: {age}"

                    # Determine severity
                    if 'CrashLoopBackOff' in status or 'Error' in status or 'ImagePullBackOff' in status:
                        self.add_result('k8s_pods', 'critical', '🔴', msg)
                    elif 'Pending' in status or 'ContainerCreating' in status:
                        self.add_result('k8s_pods', 'warning', '⚠', msg)
                    else:
                        self.add_result('k8s_pods', 'warning', '⚠', msg)

        # Deployment status
        deployments = self.run_command('kubectl get deployments --all-namespaces --no-headers 2>/dev/null', timeout=10)
        if deployments and deployments.strip():
            deploy_lines = [line for line in deployments.split('\n') if line.strip()]
            for line in deploy_lines[:15]:  # Limit to 15 deployments
                parts = line.split()
                if len(parts) >= 4:
                    namespace = parts[0]
                    deploy_name = parts[1]
                    ready = parts[2]

                    msg = f"{deploy_name}: {ready} replicas ready (namespace: {namespace})"

                    # Parse ready/desired
                    if '/' in ready:
                        ready_parts = ready.split('/')
                        if len(ready_parts) == 2:
                            ready_count = ready_parts[0]
                            desired_count = ready_parts[1]

                            if ready_count == desired_count and desired_count != '0':
                                self.add_result('k8s_deployments', 'success', '✓', msg)
                            elif ready_count == '0':
                                self.add_result('k8s_deployments', 'critical', '🔴', msg)
                            else:
                                self.add_result('k8s_deployments', 'warning', '⚠', msg)

        # Services
        services = self.run_command('kubectl get services --all-namespaces --no-headers 2>/dev/null', timeout=10)
        if services and services.strip():
            svc_lines = [line for line in services.split('\n') if line.strip()]
            for line in svc_lines[:15]:  # Limit to 15 services
                parts = line.split()
                if len(parts) >= 4:
                    namespace = parts[0]
                    svc_name = parts[1]
                    svc_type = parts[2]
                    cluster_ip = parts[3]
                    external_ip = parts[4] if len(parts) > 4 else ''

                    msg = f"{svc_name}: {svc_type} ({cluster_ip})"
                    if external_ip and external_ip not in ['<none>', '<pending>']:
                        msg += f", External: {external_ip}"
                    msg += f" (namespace: {namespace})"

                    # Check if service has endpoints
                    endpoints = self.run_command(
                        f'kubectl get endpoints {svc_name} -n {namespace} --no-headers 2>/dev/null | awk "{{print $2}}"',
                        timeout=5
                    )

                    if endpoints and endpoints.strip() and endpoints.strip() != '<none>':
                        self.add_result('k8s_services', 'success', '✓', msg)
                    else:
                        self.add_result('k8s_services', 'warning', '⚠', f"{msg} - No endpoints")

        # Persistent Volume Claims
        pvcs = self.run_command('kubectl get pvc --all-namespaces --no-headers 2>/dev/null', timeout=10)
        pending_pvcs = []
        if pvcs and pvcs.strip():
            pvc_lines = [line for line in pvcs.split('\n') if line.strip()]
            total_pvcs = len(pvc_lines)

            for line in pvc_lines:
                parts = line.split()
                if len(parts) >= 3:
                    namespace = parts[0]
                    pvc_name = parts[1]
                    status = parts[2]

                    if status == 'Pending':
                        pending_pvcs.append(f"{pvc_name} (namespace: {namespace})")

        # PV summary
        pvs = self.run_command('kubectl get pv --no-headers 2>/dev/null | wc -l', timeout=5)
        pv_bound = self.run_command('kubectl get pv --no-headers 2>/dev/null | grep -c "Bound"', timeout=5)

        if pvs and pvs.strip():
            total_pvs = int(pvs.strip()) if pvs.strip().isdigit() else 0
            bound_pvs = int(pv_bound.strip()) if pv_bound and pv_bound.strip().isdigit() else 0
            available_pvs = total_pvs - bound_pvs

            msg = f"PVs: {total_pvs} total ({bound_pvs} Bound, {available_pvs} Available)"
            self.add_result('k8s_storage', 'info', '✓', msg)

        if pending_pvcs:
            self.add_result('k8s_storage', 'warning', '⚠', f"PVCs Pending: {len(pending_pvcs)}")
            for pvc in pending_pvcs[:5]:  # Show first 5
                self.add_result('k8s_storage', 'warning', '⚠', f"  - {pvc}: Waiting for volume provisioning")

        # Recent critical events
        events = self.run_command(
            'kubectl get events --all-namespaces --sort-by=.lastTimestamp '
            '--field-selector type=Warning 2>/dev/null | tail -10',
            timeout=10
        )

        if events and events.strip():
            event_lines = [line for line in events.split('\n') if line.strip() and 'NAMESPACE' not in line]
            if event_lines:
                for line in event_lines[-5:]:  # Last 5 events
                    parts = line.split()
                    if len(parts) >= 5:
                        namespace = parts[0]
                        reason = parts[4] if len(parts) > 4 else 'Unknown'
                        message = ' '.join(parts[5:]) if len(parts) > 5 else ''

                        msg = f"{reason}"
                        if message:
                            msg += f": {message[:100]}"  # Limit message length

                        if 'error' in reason.lower() or 'failed' in reason.lower():
                            self.add_result('k8s_events', 'critical', '🔴', msg)
                        else:
                            self.add_result('k8s_events', 'warning', '⚠', msg)

        # Resource summary
        pods_total = self.run_command('kubectl get pods --all-namespaces --no-headers 2>/dev/null | wc -l', timeout=5)
        pods_running = self.run_command('kubectl get pods --all-namespaces --no-headers 2>/dev/null | grep -c "Running"', timeout=5)
        pods_pending = self.run_command('kubectl get pods --all-namespaces --no-headers 2>/dev/null | grep -c "Pending"', timeout=5)
        pods_failed = self.run_command('kubectl get pods --all-namespaces --no-headers 2>/dev/null | grep -c -E "Failed|Error"', timeout=5)

        if pods_total and pods_total.strip():
            total = int(pods_total.strip()) if pods_total.strip().isdigit() else 0
            running = int(pods_running.strip()) if pods_running and pods_running.strip().isdigit() else 0
            pending = int(pods_pending.strip()) if pods_pending and pods_pending.strip().isdigit() else 0
            failed = int(pods_failed.strip()) if pods_failed and pods_failed.strip().isdigit() else 0

            msg = f"Total Pods: {total} ({running} Running"
            if pending > 0:
                msg += f", {pending} Pending"
            if failed > 0:
                msg += f", {failed} Failed"
            msg += ")"
            self.add_result('k8s_summary', 'info', '✓', msg)

        # Namespaces count
        namespaces = self.run_command('kubectl get namespaces --no-headers 2>/dev/null | wc -l', timeout=5)
        if namespaces and namespaces.strip():
            self.add_result('k8s_summary', 'info', '✓', f"Namespaces: {namespaces.strip()}")

        # ConfigMaps and Secrets
        configmaps = self.run_command('kubectl get configmaps --all-namespaces --no-headers 2>/dev/null | wc -l', timeout=5)
        if configmaps and configmaps.strip():
            self.add_result('k8s_summary', 'info', '✓', f"ConfigMaps: {configmaps.strip()}")

        secrets = self.run_command('kubectl get secrets --all-namespaces --no-headers 2>/dev/null | wc -l', timeout=5)
        if secrets and secrets.strip():
            self.add_result('k8s_summary', 'info', '✓', f"Secrets: {secrets.strip()}")

        # Services count
        svc_count = self.run_command('kubectl get services --all-namespaces --no-headers 2>/dev/null | wc -l', timeout=5)
        if svc_count and svc_count.strip():
            self.add_result('k8s_summary', 'info', '✓', f"Services: {svc_count.strip()}")

    def check_disk_usage(self):
        """Check disk space usage"""
        df_output = self.run_command('df -h --output=target,pcent,size,used,avail -x tmpfs -x devtmpfs')

        if not df_output:
            self.add_result('disk', 'warning', '⚠', "Unable to check disk usage")
            return

        lines = df_output.strip().split('\n')[1:]  # Skip header

        for line in lines:
            parts = line.split()
            if len(parts) >= 5:
                mount = parts[0]
                percent = parts[1].rstrip('%')
                size = parts[2]
                used = parts[3]
                avail = parts[4]

                try:
                    percent_int = int(percent)
                except ValueError:
                    continue

                msg = f"{mount}: {percent}% used ({used} / {size})"

                if percent_int >= 90:
                    self.add_result('disk', 'critical', '🔴', f"{msg} - CRITICAL")
                elif percent_int >= 80:
                    self.add_result('disk', 'warning', '⚠', msg)
                else:
                    self.add_result('disk', 'success', '✓', msg)

    def check_updates(self):
        """Check for available system updates"""
        # Detect package manager
        if os.path.exists('/usr/bin/apt-get') or os.path.exists('/usr/bin/apt'):
            # Debian/Ubuntu
            update_count = 0
            security_count = 0

            # Try to get update count without updating cache (faster)
            output = self.run_command('apt list --upgradable 2>/dev/null | grep -v "Listing"', timeout=10)
            if output:
                update_count = len(output.strip().split('\n'))

            # Check for security updates
            security_output = self.run_command('apt list --upgradable 2>/dev/null | grep -i security', timeout=10)
            if security_output:
                security_count = len(security_output.strip().split('\n'))

            if update_count > 0:
                if security_count > 0:
                    self.add_result('updates', 'critical', '🔴', f"{security_count} security updates available")
                self.add_result('updates', 'warning', '⚠', f"{update_count} packages can be updated")
            else:
                self.add_result('updates', 'success', '✓', "System is up to date")

        elif os.path.exists('/usr/bin/yum') or os.path.exists('/usr/bin/dnf'):
            # RHEL/CentOS/Rocky/AlmaLinux
            cmd = 'dnf' if os.path.exists('/usr/bin/dnf') else 'yum'

            output = self.run_command(f'{cmd} check-update 2>/dev/null | grep -v "^$" | tail -n +2', timeout=15)

            if output:
                update_count = len([l for l in output.strip().split('\n') if l and not l.startswith('Security')])

                # Check for security updates
                security_output = self.run_command(f'{cmd} updateinfo list security 2>/dev/null', timeout=10)
                security_count = 0
                if security_output:
                    security_count = len([l for l in security_output.strip().split('\n') if l and not l.startswith('Update')])

                if security_count > 0:
                    self.add_result('updates', 'critical', '🔴', f"{security_count} security updates available")
                if update_count > 0:
                    self.add_result('updates', 'warning', '⚠', f"{update_count} packages can be updated")
            else:
                self.add_result('updates', 'success', '✓', "System is up to date")
        else:
            self.add_result('updates', 'info', '✗', "Unable to detect package manager")

    def run_all_checks(self):
        """Execute all diagnostic checks"""
        if self.k8s_mode:
            # Kubernetes mode: only run Kubernetes-specific checks
            self.check_k8s_details()
        elif self.docker_mode:
            # Docker mode: only run Docker-specific checks
            self.check_docker_details()
        else:
            # Normal mode: run all standard checks
            self.detect_os_info()
            self.check_network_connectivity()
            self.check_services()
            self.detect_cloud_apps()
            self.detect_wordpress_sites()
            self.check_apache_reverse_proxy()
            self.check_apache_error_logs()
            self.check_remote_mounts()
            self.check_failed_systemd_services()
            self.check_disk_usage()
            self.check_filesystem_health()
            self.check_updates()

    def display_results(self):
        """Display all collected results"""

        # Different header for Kubernetes mode
        if self.k8s_mode:
            if self.use_color:
                print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 50}{Colors.RESET}")
                print(f"{Colors.BOLD}{Colors.CYAN}    KUBERNETES DIAGNOSTICS{Colors.RESET}")
                print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 50}{Colors.RESET}")
            else:
                print("\n" + "=" * 50)
                print("    KUBERNETES DIAGNOSTICS")
                print("=" * 50)

            user = "root" if self.is_root else "non-root"
            print(f"Running as: {user}")

            if not self.is_root:
                if self.use_color:
                    print(f"{Colors.YELLOW}⚠ Warning: Not running as root. Some checks may be limited.{Colors.RESET}")
                else:
                    print("⚠ Warning: Not running as root. Some checks may be limited.")

            print("Purpose: Kubernetes cluster diagnostics and monitoring\n")

            # Kubernetes-specific categories
            categories = [
                ('k8s_env', 'KUBERNETES ENVIRONMENT'),
                ('k8s_cluster', 'CLUSTER STATUS'),
                ('k8s_nodes', 'NODES'),
                ('k8s_pods', 'POD ISSUES'),
                ('k8s_deployments', 'DEPLOYMENTS'),
                ('k8s_services', 'SERVICES'),
                ('k8s_storage', 'STORAGE'),
                ('k8s_events', 'RECENT EVENTS'),
                ('k8s_summary', 'RESOURCE SUMMARY')
            ]
        # Different header for Docker mode
        elif self.docker_mode:
            if self.use_color:
                print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 50}{Colors.RESET}")
                print(f"{Colors.BOLD}{Colors.CYAN}    DOCKER DIAGNOSTICS{Colors.RESET}")
                print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 50}{Colors.RESET}")
            else:
                print("\n" + "=" * 50)
                print("    DOCKER DIAGNOSTICS")
                print("=" * 50)

            user = "root" if self.is_root else "non-root"
            print(f"Running as: {user}")

            if not self.is_root:
                if self.use_color:
                    print(f"{Colors.YELLOW}⚠ Warning: Not running as root. Some checks may be limited.{Colors.RESET}")
                else:
                    print("⚠ Warning: Not running as root. Some checks may be limited.")

            print("Purpose: Detailed Docker container and service diagnostics\n")

            # Docker-specific categories
            categories = [
                ('docker_service', 'DOCKER SERVICE'),
                ('docker_errors', 'RECENT ERRORS/WARNINGS'),
                ('docker_containers', 'RUNNING CONTAINERS'),
                ('docker_stopped', 'STOPPED CONTAINERS'),
                ('docker_ports', 'PORT BINDING ANALYSIS'),
                ('docker_resources', 'DOCKER RESOURCES')
            ]
        else:
            # Normal mode header
            if self.use_color:
                print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 50}{Colors.RESET}")
                print(f"{Colors.BOLD}{Colors.CYAN}    SYSTEM SERVICE PROFILER{Colors.RESET}")
                print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 50}{Colors.RESET}")
            else:
                print("\n" + "=" * 50)
                print("    SYSTEM SERVICE PROFILER")
                print("=" * 50)

            user = "root" if self.is_root else "non-root"
            print(f"Running as: {user}")

            if not self.is_root:
                if self.use_color:
                    print(f"{Colors.YELLOW}⚠ Warning: Not running as root. Some checks may be limited.{Colors.RESET}")
                else:
                    print("⚠ Warning: Not running as root. Some checks may be limited.")

            print("Purpose: Quick server diagnostic for support tasks\n")

            # Normal mode categories
            categories = [
                ('system', 'SYSTEM INFO'),
                ('network', 'NETWORK'),
                ('services', 'SERVICES'),
                ('cloud_apps', 'CLOUD/WEB APPLICATIONS'),
                ('wordpress', 'WORDPRESS INSTALLATIONS'),
                ('apache_proxy', 'APACHE REVERSE PROXY'),
                ('mounts', 'REMOTE MOUNTS'),
                ('systemd_issues', 'SYSTEMD SERVICE ISSUES'),
                ('disk', 'DISK USAGE'),
                ('filesystem', 'FILESYSTEM HEALTH'),
                ('updates', 'UPDATES')
            ]

        for category, title in categories:
            if self.results[category]:
                if self.use_color:
                    print(f"\n{Colors.BOLD}[{title}]{Colors.RESET}")
                else:
                    print(f"\n[{title}]")

                for severity, symbol, message in self.results[category]:
                    print(self.format_message(severity, symbol, message))

        print()


def main():
    # Parse command line arguments
    use_color = True
    docker_mode = False
    k8s_mode = False

    if '--no-color' in sys.argv:
        use_color = False

    if '--docker' in sys.argv:
        docker_mode = True

    if '--k8s' in sys.argv or '--kubernetes' in sys.argv:
        k8s_mode = True

    if '--help' in sys.argv or '-h' in sys.argv:
        print("""
System Service Profiler - Quick server diagnostics for support tasks

Usage: sudo python3 system_profiler.py [options]

Options:
  --no-color    Disable color output
  --docker      Show detailed Docker diagnostics only
  --k8s         Show detailed Kubernetes diagnostics only
  --help, -h    Show this help message

This script checks:
  - Operating system and kernel info
  - Network connectivity (DNS and outbound)
  - Running services and their configuration
  - Cloud applications and control panels
  - Disk space usage
  - Available system updates

Docker Mode (--docker):
  - Docker engine status and version
  - Running and stopped containers
  - Container health status
  - Recent Docker errors/warnings
  - Resource usage (images, volumes, networks)

Kubernetes Mode (--k8s):
  - kubectl and cluster connectivity
  - Cluster and API server status
  - Node health and resource usage
  - Pod issues (CrashLoopBackOff, Pending, etc.)
  - Deployment and service status
  - Storage (PVs and PVCs)
  - Recent cluster events
  - Resource summary

Best run with root/sudo privileges for complete information.
        """)
        sys.exit(0)

    # Run profiler
    profiler = SystemProfiler(use_color=use_color, docker_mode=docker_mode, k8s_mode=k8s_mode)

    try:
        profiler.run_all_checks()
        profiler.display_results()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
