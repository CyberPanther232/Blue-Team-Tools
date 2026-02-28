import requests
import toons
import os
import feedparser
import re
import glob
import base64
import hashlib
import time
import uuid
import pyotp
import bcrypt
import json
from datetime import datetime
from dotenv import load_dotenv, set_key
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, current_user

db = SQLAlchemy()

FAILURE_THRESHOLD = 3

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=True)
    mfa_secret = db.Column(db.String(32), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    
    # OIDC specific fields
    oidc_sub = db.Column(db.String(120), unique=True, nullable=True)
    oidc_provider = db.Column(db.String(50), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=True)

    # Per-user data (API keys, custom settings)
    _user_data = db.Column(db.Text, default='{}')

    @property
    def user_data(self):
        try:
            return json.loads(self._user_data or '{}')
        except:
            return {}

    @user_data.setter
    def user_data(self, value):
        self._user_data = json.dumps(value)

    def set_password(self, password):
        # Use a more reliable way to hash for simple bcrypt
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def check_password(self, password):
        if not self.password_hash:
            return False
        try:
            return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
        except:
            return False

    def get_totp_uri(self):
        return pyotp.totp.TOTP(self.mfa_secret).now()

    def verify_totp(self, token):
        totp = pyotp.totp.TOTP(self.mfa_secret)
        return totp.verify(token)

    def get_api_key(self, key_name):
        return self.user_data.get('api_keys', {}).get(key_name)

    def set_api_key(self, key_name, value):
        data = self.user_data
        if 'api_keys' not in data:
            data['api_keys'] = {}
        data['api_keys'][key_name] = value
        self.user_data = data

class SettingsManager:
    @staticmethod
    def get_config_value(key, default=None):
        config_path = os.getenv('CONFIG_PATH', 'vantage.conf')
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.startswith(f"{key}="):
                        val = line.strip().split('=', 1)[1]
                        if val.lower() == 'true': return True
                        if val.lower() == 'false': return False
                        return val
        return default

    @staticmethod
    def get_settings():
        if current_user.is_authenticated:
            return current_user.user_data.get('settings', {
                'max_scans_retention': 50,
                'auto_refresh_feeds': True,
                'limit_rss_results': 25
            })
        
        # Fallback for unauthenticated or global defaults
        return {
            'max_scans_retention': 50,
            'auto_refresh_feeds': True,
            'limit_rss_results': 25
        }

    @staticmethod
    def save_settings(new_settings):
        if current_user.is_authenticated:
            data = current_user.user_data
            data['settings'] = new_settings
            current_user.user_data = data
            db.session.commit()

    @staticmethod
    def get_env_vars():
        # Now returns user-specific API keys combined with global env as fallback
        user_keys = current_user.user_data.get('api_keys', {}) if current_user.is_authenticated else {}
        
        # We also still want to see what's in .env for global context if needed
        env_vars = {}
        if os.path.exists('.env'):
            with open('.env', 'r', encoding='utf-8') as f:
                for line in f:
                    if '=' in line and not line.startswith('#'):
                        key, val = line.strip().split('=', 1)
                        env_vars[key] = val
        
        # Merge, user keys take precedence
        env_vars.update(user_keys)
        return env_vars

    @staticmethod
    def save_env_vars(vars_dict):
        if current_user.is_authenticated:
            for key, value in vars_dict.items():
                if key:
                    current_user.set_api_key(key, value)
            db.session.commit()

class ScanManager:
    @staticmethod
    def get_user_scan_dir():
        user_id = str(current_user.id) if current_user.is_authenticated else 'anonymous'
        path = f'app/cache/scans/{user_id}'
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)
        return path

    @staticmethod
    def get_retention_limit():
        settings = SettingsManager.get_settings()
        try:
            return int(settings.get('max_scans_retention', 50))
        except:
            return 50

    @staticmethod
    def extract_summary(results):
        summary_parts = []
        malicious_total = 0
        
        for tool_name, data in results.items():
            if not isinstance(data, dict): continue
            
            if "virustotal" in tool_name.lower():
                stats = None
                if 'data' in data and 'attributes' in data['data']:
                    stats = data['data']['attributes'].get('last_analysis_stats')
                
                if stats and stats.get('malicious', 0) > 0:
                    count = stats['malicious']
                    summary_parts.append(f"VT: {count} flags")
                    malicious_total += count

            if "abuseipdb" in tool_name.lower():
                score = 0
                if 'data' in data: score = data['data'].get('abuseConfidenceScore', 0)
                elif 'abuseConfidenceScore' in data: score = data['abuseConfidenceScore']
                
                if score > 10:
                    summary_parts.append(f"AbuseIPDB: {score}%")
                    if score > 50: malicious_total += 1

            if "alienvault" in tool_name.lower():
                pulse_count = 0
                if 'pulse_info' in data: pulse_count = data['pulse_info'].get('count', 0)
                if pulse_count > 0:
                    summary_parts.append(f"OTX: {pulse_count} pulses")
                    malicious_total += pulse_count

        summary = ", ".join(summary_parts) if summary_parts else "No immediate threats detected"
        risk = "Low"
        if malicious_total > 5: risk = "High"
        elif malicious_total > 0: risk = "Medium"
        
        return summary, risk

    @staticmethod
    def save_scan(query, results):
        scan_id = str(uuid.uuid4())[:8]
        scan_dir = ScanManager.get_user_scan_dir()
        scan_file = os.path.join(scan_dir, f'scan_{scan_id}.toon')
        
        try:
            summary, risk = ScanManager.extract_summary(results)
            
            scan_data = { 
                'scan_info': [{
                    'id': scan_id,
                    'query': query, 
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
                    'risk': risk, 
                    'summary': summary,
                    'full_results': results
                }]
            }
            
            with open(scan_file, 'w', encoding='utf-8') as f: 
                toons.dump(scan_data, f)
            
            ScanManager._enforce_retention()
            
        except Exception as e: print(f"Error saving scan: {e}")

    @staticmethod
    def _enforce_retention():
        limit = ScanManager.get_retention_limit()
        scan_dir = ScanManager.get_user_scan_dir()
        files = glob.glob(os.path.join(scan_dir, 'scan_*.toon'))
        if len(files) > limit:
            files.sort(key=os.path.getmtime)
            for f in files[:-limit]:
                try: os.remove(f)
                except: pass

    @staticmethod
    def get_recent_scans():
        scan_dir = ScanManager.get_user_scan_dir()
        files = glob.glob(os.path.join(scan_dir, 'scan_*.toon'))
        scans = []
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = toons.load(f)
                    info = data.get('scan_info', [])
                    if info:
                        if isinstance(info, list): info = info[0]
                        scans.append(info)
            except: pass
        scans.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return scans

    @staticmethod
    def get_scan_by_id(scan_id):
        scan_dir = ScanManager.get_user_scan_dir()
        scan_file = os.path.join(scan_dir, f'scan_{scan_id}.toon')
        if os.path.exists(scan_file):
            try:
                with open(scan_file, 'r', encoding='utf-8') as f:
                    data = toons.load(f)
                    info = data.get('scan_info', [])
                    if info:
                        if isinstance(info, list): info = info[0]
                        return info
            except: pass
        return None

    @staticmethod
    def clear_history():
        scan_dir = ScanManager.get_user_scan_dir()
        files = glob.glob(os.path.join(scan_dir, 'scan_*.toon'))
        for f in files:
            try: os.remove(f)
            except: pass

class Feed:
    def __init__(self, name, url, enabled=True, consecutive_failures=0):
        self.name = name
        self.url = url
        self.enabled = enabled
        self.consecutive_failures = int(consecutive_failures)

    def to_dict(self):
        return { 'name': self.name, 'url': self.url, 'enabled': str(self.enabled), 'consecutive_failures': str(self.consecutive_failures) }

    def _get_config_path(self):
        clean_name = re.sub(r'[^a-zA-Z0-9]', '_', self.name).lower()
        return f'app/toolkit/feeds/{clean_name}.toon'

    def save(self):
        path = self._get_config_path()
        try:
            with open(path, 'w', encoding='utf-8') as f: toons.dump({'feed_info': [self.to_dict()]}, f)
            return f"Feed {self.name} saved successfully."
        except Exception as e: return f"Error saving feed: {str(e)}"

    def handle_failure(self):
        self.consecutive_failures += 1
        if self.consecutive_failures >= FAILURE_THRESHOLD:
            self.enabled = False
        self.save()

    def handle_success(self):
        if self.consecutive_failures > 0:
            self.consecutive_failures = 0
            self.save()

    @staticmethod
    def delete(name):
        clean_name = re.sub(r'[^a-zA-Z0-9]', '_', name).lower()
        path = f'app/toolkit/feeds/{clean_name}.toon'
        if os.path.exists(path):
            os.remove(path)
            return True
        return False

    @staticmethod
    def get_all():
        feeds = []
        files = glob.glob('app/toolkit/feeds/*.toon')
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = toons.load(f)
                    info = data.get('feed_info', {})
                    if info:
                        if isinstance(info, list): info = info[0]
                        enabled = str(info.get('enabled', 'True')).lower() == 'true'
                        fail_count = info.get('consecutive_failures', 0)
                        feeds.append(Feed(info.get('name'), info.get('url'), enabled, fail_count))
            except: pass
        return feeds

class FeedManager:
    @staticmethod
    def get_all_entries(force_refresh=False):
        settings = SettingsManager.get_settings()
        limit = int(settings.get('limit_rss_results', 25))
        cache_file = 'app/cache/feeds.toon'
        cache_duration = 600
        if os.path.exists(cache_file) and not force_refresh:
            try:
                if os.path.getsize(cache_file) > 0:
                    mtime = os.path.getmtime(cache_file)
                    if (time.time() - mtime) < cache_duration:
                        with open(cache_file, 'r', encoding='utf-8') as f:
                            data = toons.load(f)
                            cached = data.get('entries', [])
                            if cached: return cached[:limit]
            except Exception as e: print(f"Error reading feed cache: {e}")

        all_entries = []
        feeds = Feed.get_all()
        for feed in feeds:
            if feed.enabled:
                try:
                    resp = requests.get(feed.url, headers={'User-Agent': 'VantagePoint-User'}, timeout=4)
                    if resp.status_code == 200:
                        parsed = feedparser.parse(resp.content)
                        for entry in parsed.entries[:limit]:
                            all_entries.append({
                                'title': str(entry.get('title', 'No Title')),
                                'link': str(entry.get('link', '#')),
                                'published': str(entry.get('published', 'N/A')),
                                'source': str(feed.name),
                                'timestamp': entry.get('published_parsed', time.gmtime())
                            })
                        feed.handle_success()
                    else: feed.handle_failure()
                except Exception as e:
                    print(f"Timeout/Error fetching feed {feed.name}: {e}")
                    feed.handle_failure()
        
        all_entries.sort(key=lambda x: x.get('timestamp', time.gmtime()), reverse=True)
        final_entries = all_entries[:limit]
        if final_entries:
            try:
                with open(cache_file, 'w', encoding='utf-8') as f: toons.dump({'entries': final_entries}, f)
            except Exception as e: print(f"Error saving feed cache: {e}")
        return final_entries

class Tool:
    def __init__(self, name, description, api_endpoint, key_required=False, key_env_var=None, env_config=None, enabled=True, author="Unknown", docs_link="", key_header_name="x-apikey", consecutive_failures=0):
        self.name = name
        self.description = description
        self.api_endpoint = api_endpoint
        self.key_required = key_required
        self.key_env_var = key_env_var
        self.enabled = enabled
        self.author = author
        self.docs_link = docs_link
        self.key_header_name = key_header_name or "x-apikey"
        self.consecutive_failures = int(consecutive_failures)
        self.env_config = env_config or { 'IP_SCANNABLE': 'False', 'IP_ROUTE': '', 'DOMAIN_SCANNABLE': 'False', 'DOMAIN_ROUTE': '', 'HASH_SCANNABLE': 'False', 'HASH_ROUTE': '', 'EMAIL_SCANNABLE': 'False', 'EMAIL_ROUTE': '', 'URL_SCANNABLE': 'False', 'URL_ROUTE': '' }
        
    def to_dict(self):
        return { 'name': self.name, 'description': self.description, 'api_endpoint': self.api_endpoint, 'key_required': str(self.key_required), 'key_env_var': self.key_env_var, 'enabled': str(self.enabled), 'author': self.author, 'docs_link': self.docs_link, 'key_header_name': self.key_header_name, 'consecutive_failures': str(self.consecutive_failures) }

    def _get_config_path(self):
        user_id = str(current_user.id) if current_user.is_authenticated else 'global'
        module_dir = f'app/toolkit/modules/{user_id}'
        if not os.path.exists(module_dir):
            os.makedirs(module_dir, exist_ok=True)
        clean_name = re.sub(r'[^a-zA-Z0-9]', '_', self.name).lower()
        return os.path.join(module_dir, f'{clean_name}.toon')

    def save(self) -> str:
        path = self._get_config_path()
        try:
            data = { 'tool_info': [self.to_dict()], 'env_config': [self.env_config] }
            with open(path, 'w', encoding='utf-8') as f: toons.dump(data, f)
            return f"Module {self.name} saved successfully."
        except Exception as e: return f"Error saving module: {str(e)}"

    def handle_failure(self):
        self.consecutive_failures += 1
        if self.consecutive_failures >= FAILURE_THRESHOLD:
            self.enabled = False
        self.save()

    def handle_success(self):
        if self.consecutive_failures > 0:
            self.consecutive_failures = 0
            self.save()

    @staticmethod
    def delete(name):
        user_id = str(current_user.id) if current_user.is_authenticated else 'global'
        clean_name = re.sub(r'[^a-zA-Z0-9]', '_', name).lower()
        path = f'app/toolkit/modules/{user_id}/{clean_name}.toon'
        if os.path.exists(path):
            os.remove(path)
            return True
        return False

    def _detect_ioc_type(self, query):
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', query): return 'IP'
        if re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', query): return 'HASH'
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', query): return 'EMAIL'
        if re.match(r'^https?://', query): return 'URL'
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', query): return 'DOMAIN'
        return 'UNKNOWN'

    def _apply_filters(self, value, filter_type):
        if filter_type == 'base64': return base64.b64encode(value.encode()).decode()
        if filter_type == 'vt_id': return base64.urlsafe_b64encode(value.encode()).decode().strip("=")
        if filter_type == 'sha256': return hashlib.sha256(value.encode()).hexdigest()
        if filter_type == 'md5': return hashlib.md5(value.encode()).hexdigest()
        return value

    def _process_route(self, route_template, query):
        processed_route = route_template
        placeholders = re.findall(r'\{([a-zA-Z0-9_|]+)\}', route_template)
        for p in placeholders:
            if '|' in p:
                key, filter_type = p.split('|')
                val = self._apply_filters(query, filter_type)
                processed_route = processed_route.replace(f'{{{p}}}', val)
            else: processed_route = processed_route.replace(f'{{{p}}}', query)
        return processed_route

    def _send_api_request(self, method, url, headers=None, data=None):
        if headers is None: headers = {}
        headers['User-Agent'] = 'VantagePoint-User'
        try:
            if method.upper() == 'POST': resp = requests.post(url, headers=headers, data=data, timeout=5)
            else: resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code in [200, 201]:
                self.handle_success()
                return resp.json()
            else:
                self.handle_failure()
                return {"error": f"API returned {resp.status_code}", "details": resp.text}
        except Exception as e:
            self.handle_failure()
            return {"error": "Request failed", "details": str(e)}

    def search(self, query):
        if not self.enabled: return {"error": f"Module {self.name} is disabled."}
        
        ioc_type = self._detect_ioc_type(query)
        scannable_key = f"{ioc_type}_SCANNABLE"
        route_key = f"{ioc_type}_ROUTE"
        is_scannable = str(self.env_config.get(scannable_key, 'False')).lower() == 'true'
        route_config = self.env_config.get(route_key, '')
        if not is_scannable or not route_config: return {"error": f"Module {self.name} does not support {ioc_type} scanning."}
        headers = {}
        
        if self.key_required:
            api_key = current_user.get_api_key(self.key_env_var) if current_user.is_authenticated else os.getenv(self.key_env_var)
            if not api_key: return {"error": f"Missing API key: {self.key_env_var}"}
            headers[self.key_header_name] = api_key
            
        routes = [r.strip() for r in route_config.split('||')]
        combined_results = {}
        for route_template in routes:
            method, path = ('GET', route_template)
            if ':/' in route_template and not route_template.startswith('http'): method, path = route_template.split(':', 1)
            final_path = self._process_route(path, query)
            full_url = final_path if final_path.startswith('http') else f"{self.api_endpoint.rstrip('/')}/{final_path.lstrip('/')}"
            payload = {'url': query} if method.upper() == 'POST' else None
            res = self._send_api_request(method, full_url, headers=headers, data=payload)
            combined_results[route_template] = res
        return combined_results if len(combined_results) > 1 else list(combined_results.values())[0]

    @staticmethod
    def get_all_configured_tools():
        tools = []
        user_id = str(current_user.id) if current_user.is_authenticated else 'global'
        
        # Check user specific modules first
        user_module_dir = f'app/toolkit/modules/{user_id}'
        global_module_dir = 'app/toolkit/modules/global'
        
        # Ensure directories exist
        for d in [user_module_dir, global_module_dir]:
            if not os.path.exists(d): os.makedirs(d, exist_ok=True)
            
        files = glob.glob(os.path.join(user_module_dir, '*.toon'))
        
        # If user has no tools, maybe they want the globals? Or maybe we always show globals?
        # User requested per-account, so let's check both or just user.
        # Let's check both but user versions override global ones.
        all_module_files = glob.glob(os.path.join(global_module_dir, '*.toon')) + files
        
        seen_names = set()
        # Sort so user files (later in list) override global ones in our processing logic
        # Actually glob returns them as paths, let's just use a dict.
        tool_paths = {}
        for f in glob.glob(os.path.join(global_module_dir, '*.toon')):
            name = os.path.basename(f)
            tool_paths[name] = f
        for f in glob.glob(os.path.join(user_module_dir, '*.toon')):
            name = os.path.basename(f)
            tool_paths[name] = f # Overwrite global with user version if name matches

        for file_path in tool_paths.values():
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = toons.load(f)
                    info, env = (data.get('tool_info', {}), data.get('env_config', {}))
                    if isinstance(info, list) and len(info) > 0: info = info[0]
                    if isinstance(env, list) and len(env) > 0: env = env[0]
                    if info:
                        enabled, key_required = (str(info.get('enabled', 'True')).lower() == 'true', str(info.get('key_required', 'False')).lower() == 'true')
                        tools.append(Tool(name=info.get('name'), description=info.get('description'), api_endpoint=info.get('api_endpoint'), key_required=key_required, key_env_var=info.get('key_env_var'), env_config=env, enabled=enabled, author=info.get('author', 'Unknown'), docs_link=info.get('docs_link', ''), key_header_name=info.get('key_header_name', 'x-apikey'), consecutive_failures=int(info.get('consecutive_failures', 0))))
            except Exception as e: print(f"Error loading module from {file_path}: {e}")
        return tools

    @staticmethod
    def setup_defaults():
        # Setup defaults in global directory
        global_dir = 'app/toolkit/modules/global'
        if not os.path.exists(global_dir):
            os.makedirs(global_dir, exist_ok=True)
            
        defaults = [
            { 'name': 'VirusTotal', 'description': 'Analyze suspicious files, domains, IPs and URLs.', 'api_endpoint': 'https://www.virustotal.com/api/v3', 'key_required': True, 'key_env_var': 'VIRUSTOTAL_API_KEY', 'author': 'VirusTotal', 'docs_link': 'https://docs.virustotal.com/reference/overview', 'env_config': { 'IP_SCANNABLE': 'True', 'IP_ROUTE': '/ip_addresses/{ip}', 'DOMAIN_SCANNABLE': 'True', 'DOMAIN_ROUTE': '/domains/{domain}', 'HASH_SCANNABLE': 'True', 'HASH_ROUTE': '/files/{hash}', 'URL_SCANNABLE': 'True', 'URL_ROUTE': 'POST:/urls || /urls/{url|vt_id}' } },
            { 'name': 'Shodan', 'description': 'Search engine for Internet-connected devices.', 'api_endpoint': 'https://api.shodan.io', 'key_required': True, 'key_env_var': 'SHODAN_API_KEY', 'author': 'Shodan', 'docs_link': 'https://developer.shodan.io/api', 'env_config': { 'IP_SCANNABLE': 'True', 'IP_ROUTE': '/shodan/host/{ip}?key={SHODAN_API_KEY}' } },
            { 'name': 'AbuseIPDB', 'description': 'IP address abuse database.', 'api_endpoint': 'https://api.abuseipdb.com/api/v2', 'key_required': True, 'key_env_var': 'ABUSEIPDB_API_KEY', 'key_header_name': 'Key', 'author': 'AbuseIPDB', 'docs_link': 'https://www.abuseipdb.com/api.html', 'env_config': { 'IP_SCANNABLE': 'True', 'IP_ROUTE': '/check?ipAddress={ip}' } }
        ]
        for d in defaults:
            clean_name = re.sub(r'[^a-zA-Z0-9]', '_', d['name']).lower()
            path = os.path.join(global_dir, f'{clean_name}.toon')
            if not os.path.exists(path):
                t = Tool(name=d['name'], description=d['description'], api_endpoint=d['api_endpoint'], key_required=d['key_required'], key_env_var=d['key_env_var'], author=d['author'], docs_link=d['docs_link'], key_header_name=d.get('key_header_name', 'x-apikey'), env_config=d['env_config'])
                # Manually save to global path
                data = { 'tool_info': [t.to_dict()], 'env_config': [t.env_config] }
                with open(path, 'w', encoding='utf-8') as f: toons.dump(data, f)

    def _validate_configuration(self) -> bool: return bool(self.name and self.api_endpoint)

class Feed:
    def __init__(self, name, url, enabled=True, consecutive_failures=0):
        self.name = name
        self.url = url
        self.enabled = enabled
        self.consecutive_failures = int(consecutive_failures)

    def to_dict(self):
        return { 'name': self.name, 'url': self.url, 'enabled': str(self.enabled), 'consecutive_failures': str(self.consecutive_failures) }

    def _get_config_path(self):
        clean_name = re.sub(r'[^a-zA-Z0-9]', '_', self.name).lower()
        return f'app/toolkit/feeds/{clean_name}.toon'

    def save(self):
        path = self._get_config_path()
        try:
            with open(path, 'w', encoding='utf-8') as f: toons.dump({'feed_info': [self.to_dict()]}, f)
            return f"Feed {self.name} saved successfully."
        except Exception as e: return f"Error saving feed: {str(e)}"

    def handle_failure(self):
        self.consecutive_failures += 1
        if self.consecutive_failures >= FAILURE_THRESHOLD:
            self.enabled = False
            print(f"CRITICAL: Feed {self.name} auto-disabled after {FAILURE_THRESHOLD} failures.")
        self.save()

    def handle_success(self):
        if self.consecutive_failures > 0:
            self.consecutive_failures = 0
            self.save()

    @staticmethod
    def delete(name):
        clean_name = re.sub(r'[^a-zA-Z0-9]', '_', name).lower()
        path = f'app/toolkit/feeds/{clean_name}.toon'
        if os.path.exists(path):
            os.remove(path)
            return True
        return False

    @staticmethod
    def get_all():
        feeds = []
        files = glob.glob('app/toolkit/feeds/*.toon')
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = toons.load(f)
                    info = data.get('feed_info', {})
                    if info:
                        if isinstance(info, list): info = info[0]
                        enabled = str(info.get('enabled', 'True')).lower() == 'true'
                        fail_count = info.get('consecutive_failures', 0)
                        feeds.append(Feed(info.get('name'), info.get('url'), enabled, fail_count))
            except: pass
        return feeds

class FeedManager:
    @staticmethod
    def get_all_entries(force_refresh=False):
        settings = SettingsManager.get_settings()
        limit = int(settings.get('limit_rss_results', 25))
        cache_file = 'app/cache/feeds.toon'
        cache_duration = 600
        if os.path.exists(cache_file) and not force_refresh:
            try:
                if os.path.getsize(cache_file) > 0:
                    mtime = os.path.getmtime(cache_file)
                    if (time.time() - mtime) < cache_duration:
                        with open(cache_file, 'r', encoding='utf-8') as f:
                            data = toons.load(f)
                            cached = data.get('entries', [])
                            if cached: return cached[:limit]
            except Exception as e: print(f"Error reading feed cache: {e}")

        all_entries = []
        feeds = Feed.get_all()
        for feed in feeds:
            if feed.enabled:
                try:
                    resp = requests.get(feed.url, headers={'User-Agent': 'VantagePoint-User'}, timeout=4)
                    if resp.status_code == 200:
                        parsed = feedparser.parse(resp.content)
                        for entry in parsed.entries[:limit]:
                            all_entries.append({
                                'title': str(entry.get('title', 'No Title')),
                                'link': str(entry.get('link', '#')),
                                'published': str(entry.get('published', 'N/A')),
                                'source': str(feed.name),
                                'timestamp': entry.get('published_parsed', time.gmtime())
                            })
                        feed.handle_success()
                    else: feed.handle_failure()
                except Exception as e:
                    print(f"Timeout/Error fetching feed {feed.name}: {e}")
                    feed.handle_failure()
        
        all_entries.sort(key=lambda x: x.get('timestamp', time.gmtime()), reverse=True)
        final_entries = all_entries[:limit]
        if final_entries:
            try:
                with open(cache_file, 'w', encoding='utf-8') as f: toons.dump({'entries': final_entries}, f)
            except Exception as e: print(f"Error saving feed cache: {e}")
        return final_entries

class Tool:
    def __init__(self, name, description, api_endpoint, key_required=False, key_env_var=None, env_config=None, enabled=True, author="Unknown", docs_link="", key_header_name="x-apikey", consecutive_failures=0):
        self.name = name
        self.description = description
        self.api_endpoint = api_endpoint
        self.key_required = key_required
        self.key_env_var = key_env_var
        self.enabled = enabled
        self.author = author
        self.docs_link = docs_link
        self.key_header_name = key_header_name or "x-apikey"
        self.consecutive_failures = int(consecutive_failures)
        self.env_config = env_config or { 'IP_SCANNABLE': 'False', 'IP_ROUTE': '', 'DOMAIN_SCANNABLE': 'False', 'DOMAIN_ROUTE': '', 'HASH_SCANNABLE': 'False', 'HASH_ROUTE': '', 'EMAIL_SCANNABLE': 'False', 'EMAIL_ROUTE': '', 'URL_SCANNABLE': 'False', 'URL_ROUTE': '' }
        
    def to_dict(self):
        return { 'name': self.name, 'description': self.description, 'api_endpoint': self.api_endpoint, 'key_required': str(self.key_required), 'key_env_var': self.key_env_var, 'enabled': str(self.enabled), 'author': self.author, 'docs_link': self.docs_link, 'key_header_name': self.key_header_name, 'consecutive_failures': str(self.consecutive_failures) }

    def _get_config_path(self):
        clean_name = re.sub(r'[^a-zA-Z0-9]', '_', self.name).lower()
        return f'app/toolkit/modules/{clean_name}.toon'

    def save(self) -> str:
        path = self._get_config_path()
        try:
            data = { 'tool_info': [self.to_dict()], 'env_config': [self.env_config] }
            with open(path, 'w', encoding='utf-8') as f: toons.dump(data, f)
            return f"Module {self.name} saved successfully."
        except Exception as e: return f"Error saving module: {str(e)}"

    def handle_failure(self):
        self.consecutive_failures += 1
        if self.consecutive_failures >= FAILURE_THRESHOLD:
            self.enabled = False
            print(f"CRITICAL: Tool {self.name} auto-disabled after {FAILURE_THRESHOLD} failures.")
        self.save()

    def handle_success(self):
        if self.consecutive_failures > 0:
            self.consecutive_failures = 0
            self.save()

    @staticmethod
    def delete(name):
        clean_name = re.sub(r'[^a-zA-Z0-9]', '_', name).lower()
        path = f'app/toolkit/modules/{clean_name}.toon'
        if os.path.exists(path):
            os.remove(path)
            return True
        return False

    def _detect_ioc_type(self, query):
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', query): return 'IP'
        if re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', query): return 'HASH'
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', query): return 'EMAIL'
        if re.match(r'^https?://', query): return 'URL'
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', query): return 'DOMAIN'
        return 'UNKNOWN'

    def _apply_filters(self, value, filter_type):
        if filter_type == 'base64': return base64.b64encode(value.encode()).decode()
        if filter_type == 'vt_id': return base64.urlsafe_b64encode(value.encode()).decode().strip("=")
        if filter_type == 'sha256': return hashlib.sha256(value.encode()).hexdigest()
        if filter_type == 'md5': return hashlib.md5(value.encode()).hexdigest()
        return value

    def _process_route(self, route_template, query):
        processed_route = route_template
        placeholders = re.findall(r'\{([a-zA-Z0-9_|]+)\}', route_template)
        for p in placeholders:
            if '|' in p:
                key, filter_type = p.split('|')
                val = self._apply_filters(query, filter_type)
                processed_route = processed_route.replace(f'{{{p}}}', val)
            else: processed_route = processed_route.replace(f'{{{p}}}', query)
        return processed_route

    def _send_api_request(self, method, url, headers=None, data=None):
        if headers is None: headers = {}
        headers['User-Agent'] = 'VantagePoint-User'
        try:
            if method.upper() == 'POST': resp = requests.post(url, headers=headers, data=data, timeout=5)
            else: resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code in [200, 201]:
                self.handle_success()
                return resp.json()
            else:
                self.handle_failure()
                return {"error": f"API returned {resp.status_code}", "details": resp.text}
        except Exception as e:
            self.handle_failure()
            return {"error": "Request failed", "details": str(e)}

    def search(self, query):
        if not self.enabled: return {"error": f"Module {self.name} is disabled."}
        load_dotenv(override=True)
        ioc_type = self._detect_ioc_type(query)
        scannable_key = f"{ioc_type}_SCANNABLE"
        route_key = f"{ioc_type}_ROUTE"
        is_scannable = str(self.env_config.get(scannable_key, 'False')).lower() == 'true'
        route_config = self.env_config.get(route_key, '')
        if not is_scannable or not route_config: return {"error": f"Module {self.name} does not support {ioc_type} scanning."}
        headers = {}
        if self.key_required:
            api_key = os.getenv(self.key_env_var)
            if not api_key: return {"error": f"Missing API key in environment: {self.key_env_var}"}
            headers[self.key_header_name] = api_key
        routes = [r.strip() for r in route_config.split('||')]
        combined_results = {}
        for route_template in routes:
            method, path = ('GET', route_template)
            if ':/' in route_template and not route_template.startswith('http'): method, path = route_template.split(':', 1)
            final_path = self._process_route(path, query)
            full_url = final_path if final_path.startswith('http') else f"{self.api_endpoint.rstrip('/')}/{final_path.lstrip('/')}"
            payload = {'url': query} if method.upper() == 'POST' else None
            res = self._send_api_request(method, full_url, headers=headers, data=payload)
            combined_results[route_template] = res
        return combined_results if len(combined_results) > 1 else list(combined_results.values())[0]

    @staticmethod
    def get_all_configured_tools():
        tools = []
        files = glob.glob('app/toolkit/modules/*.toon')
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = toons.load(f)
                    info, env = (data.get('tool_info', {}), data.get('env_config', {}))
                    if isinstance(info, list) and len(info) > 0: info = info[0]
                    if isinstance(env, list) and len(env) > 0: env = env[0]
                    if info:
                        enabled, key_required = (str(info.get('enabled', 'True')).lower() == 'true', str(info.get('key_required', 'False')).lower() == 'true')
                        tools.append(Tool(name=info.get('name'), description=info.get('description'), api_endpoint=info.get('api_endpoint'), key_required=key_required, key_env_var=info.get('key_env_var'), env_config=env, enabled=enabled, author=info.get('author', 'Unknown'), docs_link=info.get('docs_link', ''), key_header_name=info.get('key_header_name', 'x-apikey'), consecutive_failures=info.get('consecutive_failures', info.get('consecutive_failures', 0))))
            except Exception as e: print(f"Error loading module from {file_path}: {e}")
        return tools

    @staticmethod
    def setup_defaults():
        defaults = [
            { 'name': 'VirusTotal', 'description': 'Analyze suspicious files, domains, IPs and URLs.', 'api_endpoint': 'https://www.virustotal.com/api/v3', 'key_required': True, 'key_env_var': 'VIRUSTOTAL_API_KEY', 'author': 'VirusTotal', 'docs_link': 'https://docs.virustotal.com/reference/overview', 'env_config': { 'IP_SCANNABLE': 'True', 'IP_ROUTE': '/ip_addresses/{ip}', 'DOMAIN_SCANNABLE': 'True', 'DOMAIN_ROUTE': '/domains/{domain}', 'HASH_SCANNABLE': 'True', 'HASH_ROUTE': '/files/{hash}', 'URL_SCANNABLE': 'True', 'URL_ROUTE': 'POST:/urls || /urls/{url|vt_id}' } },
            { 'name': 'Shodan', 'description': 'Search engine for Internet-connected devices.', 'api_endpoint': 'https://api.shodan.io', 'key_required': True, 'key_env_var': 'SHODAN_API_KEY', 'author': 'Shodan', 'docs_link': 'https://developer.shodan.io/api', 'env_config': { 'IP_SCANNABLE': 'True', 'IP_ROUTE': '/shodan/host/{ip}?key={SHODAN_API_KEY}' } },
            { 'name': 'AbuseIPDB', 'description': 'IP address abuse database.', 'api_endpoint': 'https://api.abuseipdb.com/api/v2', 'key_required': True, 'key_env_var': 'ABUSEIPDB_API_KEY', 'key_header_name': 'Key', 'author': 'AbuseIPDB', 'docs_link': 'https://www.abuseipdb.com/api.html', 'env_config': { 'IP_SCANNABLE': 'True', 'IP_ROUTE': '/check?ipAddress={ip}' } }
        ]
        for d in defaults:
            t = Tool(name=d['name'], description=d['description'], api_endpoint=d['api_endpoint'], key_required=d['key_required'], key_env_var=d['key_env_var'], author=d['author'], docs_link=d['docs_link'], key_header_name=d.get('key_header_name', 'x-apikey'), env_config=d['env_config'])
            if not os.path.exists(t._get_config_path()): t.save()

    def _validate_configuration(self) -> bool: return bool(self.name and self.api_endpoint)
