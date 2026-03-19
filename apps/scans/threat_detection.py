import socket
import requests
import logging
import time
import base64
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from django.conf import settings
import tldextract

logger = logging.getLogger(__name__)

# Global executor pool to avoid "wait at exit" overhead (Shared across instances)
# Increased max_workers to 64 to handle Deep scans under load
_executor = ThreadPoolExecutor(max_workers=64)

class ThreatDetector:
    """محرك الكشف عن التهديدات - تنبيه: يعتمد كلياً على المصادر الخارجية (GSB/VT) بناءً على طلب المستخدم"""

    def __init__(self):
        self.results = {
            'safe': None,
            'score': 0,
            'details': [],
            'threats_found': [],
            'domain_info': {},
            'ip_info': {},
            'ip_address': None,
            'response_time': 0.0,
            'domain': '',
            'full_url': '',
            'threats_count': 0,
            'final_status': 'unknown',
            'final_message': 'جاري الفحص...',
            'scan_failed': False, # Flag to indicate if both APIs failed
        }

    SCAN_CONFIG = {
        'basic': {
            'services': ['gsb'],
            'overall_timeout': 7.0,
            'gsb_timeout': 3.0,
        },
        'standard': {
            'services': ['vt'],
            'overall_timeout': 10.0,
            'vt_timeout': 8.0,
        },
        'deep': {
            'services': ['gsb', 'vt'],
            'overall_timeout': 15.0,
            'gsb_timeout': 3.0,
            'vt_timeout': 12.0,
        }
    }

    def detect(self, url: str, scan_level: str = 'deep') -> dict:
        """Run threat detection strictly using external GSB and VT lookups."""
        logger.info(f"[ThreatDetector] Starting EXTERNAL scan: {url[:80]}")
        url = self._normalize_url(url)
        start_time = time.time()

        try:
            extracted = tldextract.extract(url)
            full_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        except Exception:
            full_domain = urlparse(url).netloc

        self.results['domain'] = full_domain
        self.results['full_url'] = url

        # IP Resolution (for telemetry)
        try:
            hostname = urlparse(url).netloc or full_domain
            if ':' in hostname: hostname = hostname.split(':')[0]
            self.results['ip_address'] = socket.gethostbyname(hostname)
        except Exception:
            pass

        # Configuration
        if scan_level not in self.SCAN_CONFIG:
            scan_level = 'deep'
        config = self.SCAN_CONFIG[scan_level]
        
        vt_key = getattr(settings, 'VIRUSTOTAL_API_KEY', '')
        gsb_key = getattr(settings, 'GOOGLE_SAFE_BROWSING_API_KEY', '')

        if not vt_key and not gsb_key:
             self.results['scan_failed'] = True
             self.results['details'].append("⚠️ خطأ في النظام: لا توجد مفاتيح API لخدمات الفحص")
             self._calculate_final_score()
             return self.results

        futures_map = {}
        if 'gsb' in config['services'] and gsb_key:
            futures_map[_executor.submit(self._check_google_safe_browsing, url, config.get('gsb_timeout', 3.0))] = 'google_safe'
        if 'vt' in config['services'] and vt_key:
            futures_map[_executor.submit(self._check_virustotal, url, config.get('vt_timeout', 15.0))] = 'virustotal'

        try:
            for future in as_completed(futures_map, timeout=config['overall_timeout']):
                check_name = futures_map[future]
                try:
                    threats = future.result()
                    if threats and isinstance(threats, list):
                        for threat in threats:
                            if threat not in self.results['threats_found']:
                                self.results['threats_found'].append(threat)
                except Exception as e:
                    logger.warning(f"[ThreatDetector] service '{check_name}' error: {e}")
                    if check_name == 'virustotal':
                        self.results['details'].append('⚠️ خدمة VirusTotal لم ترد في الوقت المحدد')
        except FuturesTimeout:
            logger.warning("[ThreatDetector] Overall scan timeout.")
            self.results['scan_failed'] = True

        # Check if both APIs failed completely
        if not self.results['threats_found'] and not any(isinstance(r, list) for r in futures_map):
             # If mapping was empty or all crashed
             if len(self.results['details']) > 0 and '⚠️' in str(self.results['details']):
                 self.results['scan_failed'] = True

        self._calculate_final_score()
        self.results['response_time'] = round(time.time() - start_time, 2)
        return self.results

    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url

    def _check_google_safe_browsing(self, url: str, timeout: float) -> list:
        """GSB Lookup."""
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}"
            payload = {
                "client": {"clientId": "safeclick", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            resp = requests.post(api_url, json=payload, timeout=timeout)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    matches = data.get('matches', [])
                    return [{'type': 'google_safe', 'severity': 5, 'description': 'تم رصده كتهديد من قبل Google Safe Browsing'}] if matches else []
                except ValueError:
                    logger.error("[GSB] Invalid JSON response")
        except Exception as e:
            logger.error(f"[GSB] Connection error: {e}")
        return []

    def _check_virustotal(self, url: str, request_timeout: float) -> list:
        """VT Lookup with budget-aware polling."""
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY, "accept": "application/json"}
        start_time = time.time()
        data = None

        try:
            # 1. Submit
            try:
                 post_resp = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers, timeout=5.0)
            except Exception as e:
                 logger.error(f"[VT] POST failed: {e}")
                 post_resp = None

            if post_resp and post_resp.status_code in (200, 202):
                try:
                    analysis_id = post_resp.json().get('data', {}).get('id')
                except ValueError:
                    analysis_id = None
                
                if analysis_id:
                    # 2. Poll (Optimized: check every 2 seconds)
                    for _ in range(10):
                        if (time.time() - start_time) + 2.0 > request_timeout: break
                        time.sleep(2)
                        try:
                            poll_resp = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=5.0)
                            if poll_resp.status_code == 200:
                                poll_data = poll_resp.json()
                                if poll_data.get('data', {}).get('attributes', {}).get('status') == 'completed':
                                    data = poll_data
                                    break
                        except Exception as e:
                            logger.error(f"[VT] Poll error: {e}")

            # 3. Cache Fallback
            if not data:
                url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
                try:
                    get_resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5.0)
                    if get_resp.status_code == 200:
                        data = get_resp.json()
                except Exception as e:
                    logger.error(f"[VT] GET fallback error: {e}")

            if data:
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values())
                
                if malicious > 0:
                    self.results['details'].append(f"⚠️ VirusTotal: {malicious} محرك رصد تهديداً ({total})")
                    return [{'type': 'virustotal', 'severity': 5, 'description': f'تم اكتشاف الرابط كملغم من {malicious} محرك في VirusTotal'}]
                elif suspicious > 0:
                    self.results['details'].append(f"⚠️ VirusTotal: {suspicious} محرك اشتبه بالرابط ({total})")
                    return [{'type': 'virustotal', 'severity': 3, 'description': f'اشتباه في الرابط من قبل {suspicious} محرك في VirusTotal'}]
                else:
                    self.results['details'].append(f"✅ VirusTotal: الرابط نظيف (أكده {stats.get('harmless', 0)} محرك)")
        except Exception as e:
            logger.error(f"[VT] Error: {e}")
        return []

    def _calculate_final_score(self) -> None:
        """Final decision based ONLY on threats found by external services."""
        threats = self.results['threats_found']
        self.results['threats_count'] = len(threats)
        
        if self.results.get('scan_failed'):
            self.results['score'] = 0
            self.results['safe'] = None
            self.results['final_status'] = 'فشل الفحص'
            self.results['final_message'] = '⚠️ تعذر إكمال الفحص'
            if not self.results['details']:
                self.results['details'] = ['⚠️ تعذر الاتصال بمصادر الفحص الخارجية']
        elif not threats:
            self.results['score'] = 100
            self.results['safe'] = True
            self.results['final_status'] = 'آمن'
            self.results['final_message'] = '✓ نتيحة الفحص: الرابط آمن'
            if not self.results['details']:
                self.results['details'] = ['✓ المصادر الخارجية لم تعثر على أي تهديدات']
        else:
            max_severity = max(t.get('severity', 0) for t in threats)
            if max_severity >= 5:
                self.results['score'] = 10
                self.results['safe'] = False
                self.results['final_status'] = 'خطير'
                self.results['final_message'] = '🔴 تحذير: هذا الرابط خطير جداً!'
            else:
                self.results['score'] = 45
                self.results['safe'] = None
                self.results['final_status'] = 'مشبوه'
                self.results['final_message'] = '⚠️ تنبيه: تم رصد مؤشرات مشبوهة'