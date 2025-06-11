import hashlib
import os
import json
import time
import logging
import logging.handlers
from pathlib import Path
import sys
import argparse
from typing import Dict, List, Optional, Any, Callable, Tuple, Set
import fnmatch
import platform
import threading
import signal
import gzip
import pickle
from datetime import datetime
from collections import defaultdict
import stat
import re

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileDeletedEvent, FileModifiedEvent
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

DEFAULT_CONFIG = {
    "monitored_directories": [
        str(Path.home() / "Documents"),
        str(Path.home() / "Desktop")
    ],
    "excluded_patterns": [
        "*.tmp",
        "*.log",
        "temp/*",
        "*.bak"
    ],
    "allowed_extensions": [
        ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
        ".jpg", ".png", ".csv", ".sql", ".py", ".js", ".html", ".css"
    ],
    "default_hash_algorithm": "sha256",
    "baseline_compression": True,
    "max_log_files": 10,
    "log_rotation_size": "10MB",
    "alert_thresholds": {
        "mass_deletion": 5,
        "mass_modification": 10
    }
}

def console_event_callback(event):
    event_type = event['type'].upper()
    path = event['path']
    timestamp = event['timestamp']
    
    if event_type == 'ALERT':
        alert_type = event['details']['type'].replace('_', ' ').title()
        message = (f"[{timestamp}] ALERT: {alert_type} - "
                  f"Count: {event['details']['count']} "
                  f"(Threshold: {event['details']['threshold']})")
    else:
        message = f"[{timestamp}] {event_type}: {path}"
        
        if 'details' in event and event['details']:
            details = []
            if 'hash' in event['details']:
                details.append(f"Hash: {event['details']['hash'][:16]}...")
            if 'changes' in event['details']:
                for change, values in event['details']['changes'].items():
                    details.append(f"{change.title()}: {str(values)[:100]}...")
            if details:
                message += "\n  " + "\n  ".join(details)
    
    print(message)

def create_sample_config(config_path: str):
    sample_config = DEFAULT_CONFIG.copy()
    try:
        with open(config_path, 'w') as f:
            json.dump(sample_config, f, indent=4)
        print(f"\n[+] Sample configuration created at {config_path}")
        print("\nConfiguration Contents:")
        print(json.dumps(sample_config, indent=4))
    except Exception as e:
        print(f"\n[!] Error creating sample config: {str(e)}")

class EnhancedLogger:
    """Enhanced logging with rotation and size management"""
    def __init__(self):
        self.logger = logging.getLogger('FIM_Enhanced')
        self.logger.setLevel(logging.INFO)
        self._setup_handlers()

    def _setup_handlers(self):
        log_path = self._get_log_path()
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=self._parse_size(DEFAULT_CONFIG['log_rotation_size']),
            backupCount=DEFAULT_CONFIG['max_log_files']
        )
        file_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s [%(threadName)s]'
        )
        file_handler.setFormatter(file_formatter)
        
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def _get_log_path(self) -> str:
        log_dir = Path(os.environ.get('PROGRAMDATA', Path.home()))
        log_path = log_dir / 'fim_enhanced.log'
        
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            return str(log_path)
        except Exception as e:
            print(f"Couldn't access log location {log_path}: {str(e)}")
            return 'fim_enhanced.log'  # Fallback to local directory

    def _parse_size(self, size_str: str) -> int:
        size_str = size_str.upper().strip()
        if not size_str:
            return 10 * 1024 * 1024  # Default 10MB
        
        match = re.match(r'^(\d+)\s*([KMG]?B?)?$', size_str)
        if not match:
            raise ValueError(f"Invalid size format: {size_str}")
            
        number = int(match.group(1))
        unit = match.group(2) or 'B'
        
        if unit.startswith('K'):
            return number * 1024
        elif unit.startswith('M'):
            return number * 1024 * 1024
        elif unit.startswith('G'):
            return number * 1024 * 1024 * 1024
        else:  # bytes
            return number

logger = EnhancedLogger().logger

class FileIntegrityDatabase:
    def __init__(self, baseline_file: str = None):
        base_dir = Path(os.environ.get('PROGRAMDATA', Path.home()))
        if baseline_file is None:
            self.baseline_file = str(base_dir / 'baseline.fim')
        else:
            self.baseline_file = baseline_file
            
        self.version = "1.2"
        self.lock = threading.Lock()

    def save(self, data: Dict[str, Any]) -> bool:
        temp_file = f"{self.baseline_file}.tmp"
        try:
            Path(self.baseline_file).parent.mkdir(parents=True, exist_ok=True)
            
            with self.lock, gzip.open(temp_file, 'wb') as f:
                pickle.dump({
                    'version': self.version,
                    'timestamp': time.time(),
                    'data': data
                }, f)
            Path(temp_file).replace(self.baseline_file)
            logger.info(f"Successfully saved baseline to {self.baseline_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving baseline: {str(e)}")
            try:
                Path(temp_file).unlink(missing_ok=True)
            except:
                pass
            return False

    def load(self) -> Tuple[Dict[str, Any], float]:
        try:
            with self.lock, gzip.open(self.baseline_file, 'rb') as f:
                content = pickle.load(f)
                if content.get('version') != self.version:
                    raise ValueError("Incompatible baseline version")
                logger.info(f"Successfully loaded baseline from {self.baseline_file}")
                return content['data'], content.get('timestamp', 0)
        except FileNotFoundError:
            logger.warning("Baseline file not found")
            raise
        except Exception as e:
            logger.error(f"Error loading baseline: {str(e)}")
            raise ValueError("Corrupted baseline file")

class RealTimeFileIntegrityMonitor:
    
   def __init__(self, config_file: str = None):
        """Initialize the monitor with configuration"""
        self.config_file = config_file or "fim_config.json"
        self.config = self._load_config()
        self.monitored_dirs = self._resolve_paths(self.config["monitored_directories"])
        self.excluded_patterns = self.config["excluded_patterns"]
        self.allowed_extensions = [ext.lower() for ext in self.config.get("allowed_extensions", [])]
        self.alert_thresholds = self.config.get("alert_thresholds", {})
        
        self.db = FileIntegrityDatabase()
        self.shutdown_flag = threading.Event()
        self.lock = threading.Lock()
        self.event_callbacks = []
        self.stats = defaultdict(int)
        self.suspicious_activity = defaultdict(int)
        
        self._validate_directories()
        
        logger.info("File Integrity Monitor initialized")
        logger.debug(f"Configuration: {json.dumps(self.config, indent=2)}")

    def _resolve_paths(self, paths: List[str]) -> List[str]:
        resolved = []
        for path in paths:
            try:
                expanded_path = os.path.expandvars(os.path.expanduser(path))
                abs_path = str(Path(expanded_path).absolute())
                resolved.append(abs_path)
            except Exception as e:
                logger.warning(f"Could not resolve path {path}: {str(e)}")
        return resolved

    def _load_config(self) -> Dict[str, Any]:
        config = DEFAULT_CONFIG.copy()
        
        try:
            config_path = Path(self.config_file)
            if config_path.exists():
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    config.update(user_config)
                logger.info(f"Loaded configuration from {self.config_file}")
            else:
                logger.warning(f"Config file not found at {self.config_file}, using defaults")
                
            config["monitored_directories"] = [str(p) for p in config["monitored_directories"]]
            return config
        except Exception as e:
            logger.error(f"Error loading config: {str(e)}")
            logger.info("Using default configuration")
            return DEFAULT_CONFIG.copy()

    def _validate_directories(self):
        valid_dirs = []
        
        if not self.monitored_dirs:
            logger.error("No directories specified for monitoring")
            self._suggest_default_directories()
            raise ValueError("No directories to monitor")
        
        for directory in self.monitored_dirs:
            try:
                path = Path(directory)
                if not path.exists():
                    logger.warning(f"Directory does not exist: {directory}")
                    continue
                if not path.is_dir():
                    logger.warning(f"Path is not a directory: {directory}")
                    continue
                if not os.access(directory, os.R_OK):
                    logger.warning(f"Insufficient read permissions for directory: {directory}")
                    continue
                
                valid_dirs.append(directory)
                logger.info(f"Monitoring directory: {directory}")
                
            except Exception as e:
                logger.error(f"Error validating directory {directory}: {str(e)}")
                continue
        
        if not valid_dirs:
            self._suggest_default_directories()
            raise ValueError("No valid directories to monitor")
        
        self.monitored_dirs = valid_dirs

    def _suggest_default_directories(self):
        potential_dirs = [
            str(Path.home() / "Documents"),
            str(Path.home() / "Desktop"),
            str(Path.home() / "Downloads"),
            str(Path.cwd()) 
        ]
        
        logger.info("\nSuggested directories that exist and are accessible:")
        for dir_path in potential_dirs:
            try:
                path = Path(dir_path)
                if path.exists() and path.is_dir() and os.access(dir_path, os.R_OK):
                    logger.info(f"- {dir_path}")
            except:
                continue

    def is_excluded(self, filepath: str) -> bool:
        filepath = str(Path(filepath))
        return any(fnmatch.fnmatch(filepath, pattern) 
                  for pattern in self.excluded_patterns)

    def has_allowed_extension(self, filepath: str) -> bool:
        if not self.allowed_extensions:
            return True
        return Path(filepath).suffix.lower() in self.allowed_extensions

    def calculate_hash(self, filepath: str, algorithm: str = None) -> Optional[str]:
        algorithm = algorithm or self.config["default_hash_algorithm"]
        if algorithm not in hashlib.algorithms_available:
            logger.error(f"Unsupported hash algorithm: {algorithm}")
            return None

        try:
            file_size = os.path.getsize(filepath)
            hash_func = hashlib.new(algorithm)
            last_progress = 0
            
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    hash_func.update(chunk)
                    
                    if file_size > 1024*1024:
                        progress = f.tell() * 100 // file_size
                        if progress > last_progress + 5:
                            logger.debug(f"Hashing {filepath}: {progress}% complete")
                            last_progress = progress
            
            return hash_func.hexdigest()
        except Exception as e:
            logger.error(f"Error hashing {filepath}: {str(e)}")
            return None

    def get_file_metadata(self, filepath: str) -> Dict[str, Any]:
        try:
            stat_info = os.stat(filepath)
            metadata = {
                'size': stat_info.st_size,
                'modified': stat_info.st_mtime,
                'created': stat_info.st_ctime,
                'mode': stat_info.st_mode,
                'uid': stat_info.st_uid,
                'gid': stat_info.st_gid,
                'inode': stat_info.st_ino,
                'device': stat_info.st_dev,
                'security': {
                    'readable': os.access(filepath, os.R_OK),
                    'writable': os.access(filepath, os.W_OK),
                    'executable': os.access(filepath, os.X_OK)
                }
            }
            
            if platform.system() == 'Windows':
                import win32security
                sd = win32security.GetFileSecurity(
                    filepath, win32security.OWNER_SECURITY_INFORMATION
                )
                metadata['owner_sid'] = win32security.ConvertSidToStringSid(
                    sd.GetSecurityDescriptorOwner()
                )
            
            return metadata
        except Exception as e:
            logger.error(f"Error getting metadata for {filepath}: {str(e)}")
            return {}

    def create_baseline(self) -> Dict[str, Dict[str, Any]]:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        baseline = {}
        total_files = 0
        start_time = time.time()
        
        def process_file(filepath: str) -> Optional[Tuple[str, Dict]]:
            if self.is_excluded(filepath) or not self.has_allowed_extension(filepath):
                return None
                
            file_hash = self.calculate_hash(filepath)
            if not file_hash:
                return None
                
            return (filepath, {
                'hash': file_hash,
                'algorithm': self.config["default_hash_algorithm"],
                **self.get_file_metadata(filepath)
            })

        try:
            with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
                futures = []
                
                for directory in self.monitored_dirs:
                    logger.info(f"Scanning directory: {directory}")
                    for root, _, files in os.walk(directory):
                        for filename in files:
                            filepath = str(Path(root) / filename)
                            futures.append(executor.submit(process_file, filepath))
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        baseline[result[0]] = result[1]
                        total_files += 1
                        
                        if total_files % 100 == 0:
                            logger.info(f"Processed {total_files} files...")
            
            self.db.save(baseline)
            duration = time.time() - start_time
            logger.info(
                f"Baseline created with {total_files} files in {duration:.2f} seconds "
                f"({total_files/max(duration, 0.1):.1f} files/sec)"
            )
            
            return baseline
        except Exception as e:
            logger.error(f"Error during baseline creation: {str(e)}")
            raise

    def verify_integrity(self) -> Dict[str, Any]:
        try:
            baseline, baseline_time = self.db.load()
            logger.info(f"Baseline created at: {datetime.fromtimestamp(baseline_time).isoformat()}")
        except (FileNotFoundError, ValueError):
            logger.warning("No valid baseline found. Creating new baseline.")
            baseline = self.create_baseline()
            baseline_time = time.time()

        current_state = {}
        issues = {
            'new_files': [],
            'modified_files': [],
            'deleted_files': [],
            'permission_changes': [],
            'anomalies': [],
            'errors': []
        }
        
        scan_start = time.time()
        
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor() as executor:
            file_paths = []
            for directory in self.monitored_dirs:
                logger.info(f"Verifying directory: {directory}")
                for root, _, files in os.walk(directory):
                    for filename in files:
                        filepath = str(Path(root) / filename)
                        file_paths.append(filepath)
            
            results = executor.map(self._check_file, file_paths)
            
            for result in results:
                if result:
                    filepath, state = result
                    current_state[filepath] = state

        deleted_files = set(baseline.keys()) - set(current_state.keys())
        if deleted_files:
            issues['deleted_files'] = list(deleted_files)
            self._check_mass_deletion(len(deleted_files))
            
            for filepath in deleted_files:
                self.notify_callbacks('deleted', filepath)

        for filepath, file_data in current_state.items():
            if filepath not in baseline:
                issues['new_files'].append(filepath)
                self.notify_callbacks('created', filepath, {
                    'hash': file_data['hash'],
                    'metadata': {k: v for k, v in file_data.items() if k != 'hash'}
                })
            else:
                baseline_data = baseline[filepath]
                changes = self._compare_file_states(baseline_data, file_data)
                
                if changes:
                    issues['modified_files'].append({
                        'path': filepath,
                        'changes': changes
                    })
                    self.notify_callbacks('modified', filepath, {
                        'changes': changes
                    })

        scan_duration = time.time() - scan_start
        self.stats['last_scan_duration'] = scan_duration
        self.stats['files_scanned'] = len(current_state)
        self.stats['changes_detected'] = sum(len(v) for v in issues.values())
        
        return issues

    def _check_file(self, filepath: str) -> Optional[Tuple[str, Dict]]:
        if self.is_excluded(filepath) or not self.has_allowed_extension(filepath):
            return None
            
        file_hash = self.calculate_hash(filepath)
        if not file_hash:
            return None
            
        return (filepath, {
            'hash': file_hash,
            **self.get_file_metadata(filepath)
        })

    def _compare_file_states(self, old: Dict, new: Dict) -> Dict[str, Any]:
        changes = {}
        
        if old['hash'] != new['hash']:
            changes['content'] = {
                'old_hash': old['hash'],
                'new_hash': new['hash']
            }
        
        metadata_changes = {}
        for attr in ['size', 'modified', 'created', 'mode', 'uid', 'gid']:
            if old.get(attr) != new.get(attr):
                metadata_changes[attr] = {
                    'old_value': old.get(attr),
                    'new_value': new.get(attr)
                }
        
        if metadata_changes:
            changes['metadata'] = metadata_changes
        
        security_changes = {}
        for attr in ['readable', 'writable', 'executable']:
            if old.get('security', {}).get(attr) != new.get('security', {}).get(attr):
                security_changes[attr] = {
                    'old_value': old.get('security', {}).get(attr),
                    'new_value': new.get('security', {}).get(attr)
                }
        
        if security_changes:
            changes['security'] = security_changes
        
        return changes

    def _check_mass_deletion(self, count: int):
        threshold = self.alert_thresholds.get('mass_deletion', 5)
        if count >= threshold:
            self.suspicious_activity['mass_deletion'] += 1
            logger.critical(
                f"MASS DELETION ALERT: {count} files deleted "
                f"(threshold: {threshold})"
            )
            self.notify_callbacks('alert', {
                'type': 'mass_deletion',
                'count': count,
                'threshold': threshold
            })

    def start_real_time_monitoring(self, poll_interval: int = 60) -> None:
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
        
        if HAS_WATCHDOG:
            logger.info("Starting real-time monitoring with Watchdog...")
            self._start_watchdog_monitoring()
        else:
            logger.info(f"Starting polling-based monitoring (interval: {poll_interval}s...")
            self._start_polling_monitoring(poll_interval)

    def _handle_signal(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        self.shutdown_flag.set()
        
        if hasattr(self, 'observer'):
            self.observer.stop()

    def _start_watchdog_monitoring(self) -> None:
        class EnhancedEventHandler(FileSystemEventHandler):
            def __init__(self, parent):
                self.parent = parent
                self.event_buffer = []
                self.last_flush = time.time()
                self.buffer_lock = threading.Lock()

            def on_any_event(self, event):
                if event.is_directory:
                    return
                    
                with self.buffer_lock:
                    self.event_buffer.append(event)
                    
                    if (time.time() - self.last_flush >= 1 or 
                        len(self.event_buffer) >= 100):
                        self._flush_buffer()

            def _flush_buffer(self):
                if not self.event_buffer:
                    return
                
                unique_events = {}
                for event in self.event_buffer:
                    key = (event.src_path, type(event))
                    unique_events[key] = event
                
                for event in unique_events.values():
                    if isinstance(event, FileCreatedEvent):
                        self.parent._handle_file_event(event.src_path, 'created')
                    elif isinstance(event, FileModifiedEvent):
                        self.parent._handle_file_event(event.src_path, 'modified')
                    elif isinstance(event, FileDeletedEvent):
                        self.parent._handle_file_event(event.src_path, 'deleted')
                
                self.event_buffer.clear()
                self.last_flush = time.time()

        self.observer = Observer()
        handler = EnhancedEventHandler(self)
        
        for directory in self.monitored_dirs:
            self.observer.schedule(handler, directory, recursive=True)
        
        logger.info("Starting enhanced real-time monitoring...")
        self.observer.start()
        
        try:
            while not self.shutdown_flag.is_set():
                time.sleep(0.5)
        finally:
            self.observer.stop()
            self.observer.join()

    def _start_polling_monitoring(self, interval: int) -> None:
        logger.info(f"Starting enhanced polling (interval: {interval}s)")
        
        try:
            while not self.shutdown_flag.is_set():
                scan_start = time.time()
                
                logger.info("Starting integrity scan...")
                issues = self.verify_integrity()
                self.report_issues(issues)
                
                scan_duration = time.time() - scan_start
                logger.info(
                    f"Scan completed in {scan_duration:.2f} seconds. "
                    f"Files: {self.stats['files_scanned']}, "
                    f"Changes: {self.stats['changes_detected']}"
                )
                
                sleep_time = max(1, interval - scan_duration)
                for _ in range(int(sleep_time * 10)):
                    if self.shutdown_flag.is_set():
                        break
                    time.sleep(0.1)
                
        except Exception as e:
            logger.error(f"Monitoring error: {str(e)}")
        finally:
            logger.info("Monitoring stopped")

    def _handle_file_event(self, filepath: str, event_type: str):
        if self.is_excluded(filepath) or not self.has_allowed_extension(filepath):
            return
            
        if event_type == 'deleted':
            self.notify_callbacks('deleted', filepath)
        else:
            try:
                file_hash = self.calculate_hash(filepath)
                if file_hash:
                    self.notify_callbacks(event_type, filepath, {
                        'hash': file_hash,
                        'metadata': self.get_file_metadata(filepath)
                    })
            except Exception as e:
                logger.error(f"Error processing {event_type} event for {filepath}: {str(e)}")

    def register_callback(self, callback: Callable) -> None:
        with self.lock:
            self.event_callbacks.append(callback)
            logger.debug(f"Registered callback: {callback.__name__}")

    def notify_callbacks(self, event_type: str, path: str, details: Dict = None) -> None:
        details = details or {}
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'path': path,
            'details': details,
            'stats': self.stats.copy()
        }
        
        with self.lock:
            for callback in self.event_callbacks:
                try:
                    callback(event)
                except Exception as e:
                    logger.error(f"Callback error: {str(e)}")

    def report_issues(self, issues: Dict[str, Any]):
        report_lines = []
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report_lines.append(f"\n{' Integrity Report ':=^80}")
        report_lines.append(f"Time: {timestamp}")
        report_lines.append(f"Directories monitored: {len(self.monitored_dirs)}")
        report_lines.append(f"Files scanned: {self.stats['files_scanned']}")
        report_lines.append(f"Scan duration: {self.stats['last_scan_duration']:.2f} seconds")
        report_lines.append("-" * 80)
        
        if issues['new_files']:
            report_lines.append("\n[!] New Files Detected:")
            for i, file in enumerate(issues['new_files'][:20], 1):
                report_lines.append(f" {i:>3}. {file}")
            if len(issues['new_files']) > 20:
                report_lines.append(f" ... and {len(issues['new_files']) - 20} more")

        if issues['deleted_files']:
            report_lines.append("\n[!] Deleted Files Detected:")
            for i, file in enumerate(issues['deleted_files'][:20], 1):
                report_lines.append(f" {i:>3}. {file}")
            if len(issues['deleted_files']) > 20:
                report_lines.append(f" ... and {len(issues['deleted_files']) - 20} more")

        if issues['modified_files']:
            report_lines.append("\n[!] Modified Files Detected:")
            for i, mod in enumerate(issues['modified_files'][:10], 1):
                report_lines.append(f" {i:>3}. {mod['path']}")
                for change_type, change_details in mod['changes'].items():
                    formatted_details = []
                    if isinstance(change_details, dict):
                        for k, v in change_details.items():
                            if isinstance(v, dict):
                                formatted_details.append(f"    - {k}:")
                                for sub_k, sub_v in v.items():
                                    formatted_details.append(f"      {sub_k}: {sub_v}")
                            else:
                                formatted_details.append(f"    - {k}: {v}")
                    else:
                        formatted_details.append(f"    - {change_details}")
                    
                    report_lines.append(f"    Changes in {change_type}:")
                    report_lines.extend(formatted_details)
            if len(issues['modified_files']) > 10:
                report_lines.append(f" ... and {len(issues['modified_files']) - 10} more")

        total_issues = sum(len(v) for v in issues.values())
        if total_issues == 0:
            report_lines.append("\n[+] No integrity issues detected")
        else:
            report_lines.append(f"\n[!] Total issues detected: {total_issues}")
        
        report_lines.append("=" * 80)
        
        print("\n".join(report_lines))

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced File Integrity Monitor",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--config', default=None,
                      help="Path to configuration file")
    parser.add_argument('--create-baseline', action='store_true',
                      help="Create new baseline snapshot")
    parser.add_argument('--monitor', action='store_true',
                      help="Enable real-time monitoring")
    parser.add_argument('--poll-interval', type=int, default=60,
                      help="Polling interval in seconds (when not using Watchdog)")
    parser.add_argument('--sample-config', action='store_true',
                      help="Generate sample configuration file")
    parser.add_argument('--verbose', action='store_true',
                      help="Enable debug logging")
    parser.add_argument('--directories', nargs='+',
                      help="List of directories to monitor (overrides config)")
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    try:
        if args.sample_config:
            config_path = args.config or "fim_config.json"
            create_sample_config(config_path)
            return
        
        if args.directories:
            DEFAULT_CONFIG["monitored_directories"] = args.directories
            logger.info(f"Using command-line directories: {args.directories}")
        
        logger.info("Starting File Integrity Monitor")
        logger.info(f"Python version: {platform.python_version()}")
        logger.info(f"System: {platform.system()} {platform.release()}")
        
        if not HAS_WATCHDOG:
            logger.warning("Watchdog not available. Falling back to polling mode.")
        
        fim = RealTimeFileIntegrityMonitor(args.config)
        
        fim.register_callback(console_event_callback)
        fim.register_callback(lambda e: logger.debug(f"Event: {e}"))
        
        if args.create_baseline:
            logger.info("Creating new baseline...")
            fim.create_baseline()
            logger.info("Baseline creation complete")
        elif args.monitor:
            logger.info("Starting monitoring...")
            fim.start_real_time_monitoring(args.poll_interval)
        else:
            logger.info("Running one-time integrity check...")
            issues = fim.verify_integrity()
            fim.report_issues(issues)
            logger.info("Integrity check complete")

    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
