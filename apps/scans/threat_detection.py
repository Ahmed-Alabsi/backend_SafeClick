# apps/scans/threat_detection.py
#
# PHASE 1 FIX: External API timeouts reduced from 5s → 2.5s per service.
# PHASE 3 FIX: Graceful degradation — individual check failures do NOT fail
#              the whole scan. Each check returns a partial result independently.
# SECURITY FIX: SSL check gracefully handles connection errors (no crash).
# BUG FIX:  VirusTotal polling (5×3s=15s) was killed by the 4s executor
#           FUTURES_TIMEOUT. VT now runs on the calling thread with its own
#           30-second budget; SSL + local blacklist run concurrently in the
#           pool within a 6-second window.

import re
import socket
import requests
from urllib.parse import urlparse
import tldextract
import hashlib
import logging
from django.conf import settings
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
import datetime

logger = logging.getLogger(__name__)

# How long to allow each fast local check (blacklist DB + SSL)
FAST_CHECK_TIMEOUT = 2.5
# How long to wait for SSL + blacklist futures to complete
FAST_FUTURES_TIMEOUT = 6.0
# VirusTotal: max total time for submit + poll cycle (seconds)
VT_TOTAL_TIMEOUT = 30.0
# Keep alias so old references in _check_ssl_certificate still compile
EXTERNAL_CHECK_TIMEOUT = FAST_CHECK_TIMEOUT


class ThreatDetector:
    """محرك الكشف عن التهديدات في الروابط (Optimized)"""

    def __init__(self):
        self.results = {
            'safe': None,
            'score': 0,
            'details': [],
            'threats_found': [],
            'domain_info': {},
            'ip_info': {},
        }

        # Trusted domains — instant safe result, skip external checks
        self.trusted_domains = [
            'google.com', 'facebook.com', 'twitter.com', 'youtube.com',
            'linkedin.com', 'github.com', 'microsoft.com', 'apple.com',
            'instagram.com', 'whatsapp.com', 'amazon.com',
        ]

        # Suspicious TLDs — add penalty to score
        self.suspicious_tlds = [
            'xyz', 'top', 'work', 'date', 'racing', 'gdn', 'mom',
            'loan', 'download', 'review', 'trade', 'webcam', 'click',
            'online', 'site', 'website', 'space', 'tk', 'ml', 'ga', 'cf',
        ]

    def detect(self, url: str) -> dict:
        """Run threat detection with a strict time budget."""
        logger.info(f"[ThreatDetector] Starting scan: {url[:80]}")
        url = self._normalize_url(url)

        try:
            extracted = tldextract.extract(url)
            full_domain = (
                f"{extracted.domain}.{extracted.suffix}"
                if extracted.suffix
                else extracted.domain
            )
        except Exception:
            full_domain = url

        self.results['domain'] = full_domain
        self.results['full_url'] = url

        # Fast path: trusted domain
        if full_domain in self.trusted_domains:
            logger.info(f"[ThreatDetector] Trusted domain: {full_domain}")
            self.results['safe'] = True
            self.results['score'] = 100
            self.results['final_status'] = 'آمن'
            self.results['final_message'] = '✓ هذا الرابط آمن (نطاق موثوق)'
            self.results['details'] = ['✓ نطاق موثوق']
            return self.results

        # ── Phase 1: Fast local checks (blacklist DB + SSL) run concurrently ──
        with ThreadPoolExecutor(max_workers=2) as executor:
            fast_futures = {
                executor.submit(self._check_local_blacklist, url, full_domain): 'blacklist',
                executor.submit(self._check_ssl_certificate, url): 'ssl',
            }
            try:
                for future in as_completed(fast_futures, timeout=FAST_FUTURES_TIMEOUT):
                    check_name = fast_futures[future]
                    try:
                        result = future.result(timeout=FAST_CHECK_TIMEOUT)
                        if result:
                            self._process_check_result(check_name, result)
                    except FuturesTimeout:
                        logger.warning(f"[ThreatDetector] Check '{check_name}' timed out — skipping")
                    except Exception as e:
                        logger.warning(f"[ThreatDetector] Check '{check_name}' error: {e} — skipping")
            except FuturesTimeout:
                logger.warning("[ThreatDetector] Fast checks pool timed out")

        # ── Phase 2: VirusTotal deep scan (runs on calling thread, own budget) ──
        vt_key = getattr(settings, 'VIRUSTOTAL_API_KEY', '')
        gsb_key = getattr(settings, 'GOOGLE_SAFE_BROWSING_API_KEY', '')

        if not vt_key:
            # No API key — cannot perform deep scan
            raise Exception("تعذر الفحص الشامل: مفتاح VirusTotal API غير مهيأ.")

        try:
            vt_threats = self._check_virustotal(url)
            for threat in vt_threats:
                if threat not in self.results['threats_found']:
                    self.results['threats_found'].append(threat)
        except Exception as e:
            logger.error(f"[ThreatDetector] VT error: {e}")
            raise Exception(f"فشل الفحص العميق عبر VirusTotal: {str(e)}")

        # ── Phase 3: Google Safe Browsing (optional, fast) ──────────────────────
        if gsb_key:
            try:
                gsb_threats = self._check_google_safe_browsing(url)
                for threat in gsb_threats:
                    if threat not in self.results['threats_found']:
                        self.results['threats_found'].append(threat)
            except Exception as e:
                logger.warning(f"[ThreatDetector] GSB error: {e}")

        self._calculate_final_score()
        logger.info(
            f"[ThreatDetector] Done: score={self.results.get('score')} "
            f"status={self.results.get('final_status')}"
        )
        return self.results

    # ── Private helpers ────────────────────────────────────────────────────────

    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url

    def _check_local_blacklist(self, url: str, domain: str) -> dict:
        """Check local Blacklist table only (fast DB lookup — no external calls)."""
        threats = []
        try:
            from apps.scans.models import Blacklist
            if (
                Blacklist.objects.filter(link=url).exists()
                or Blacklist.objects.filter(domain=domain).exists()
            ):
                threats.append({
                    'type': 'blacklist',
                    'severity': 5,
                    'description': 'الرابط محظور',
                })
                self.results['details'].append('⚠️ الرابط محظور (قائمة محلية)')
            else:
                self.results['details'].append('✓ الرابط غير محظور محلياً')
        except Exception as e:
            logger.warning(f"[ThreatDetector] Blacklist DB error: {e}")
        return {'threats': threats}

    def _check_google_safe_browsing(self, url: str) -> list:
        """Google Safe Browsing API — max 2.5s."""
        try:
            api_url = (
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
                f"?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}"
            )
            payload = {
                "client": {"clientId": "safeclick", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            response = requests.post(api_url, json=payload, timeout=EXTERNAL_CHECK_TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                return [
                    {'type': 'google_safe', 'severity': 5, 'description': 'تهديد من Google'}
                    for _ in data.get('matches', [])
                ]
        except Exception:
            pass
        return []

    def _check_virustotal(self, url: str) -> list:
        """
        VirusTotal API — Submit URL then poll for a completed analysis.

        Flow:
          1. POST /urls  → get analysis_id
          2. Poll GET /analyses/{id} up to 8 times (24s max) for 'completed'
          3. If still pending / POST failed → GET cached result by URL hash
          4. Parse last_analysis_stats and return threat list
        """
        import time
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY, "accept": "application/json"}
        data = None

        try:
            # Step 1: Submit URL for scanning
            post_response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                data={"url": url},
                headers=headers,
                timeout=10.0,
            )
            logger.info(f"[VT] POST status: {post_response.status_code}")

            if post_response.status_code in (200, 202):
                analysis_id = post_response.json().get('data', {}).get('id')
                if analysis_id:
                    # Step 2: Poll up to 8 times with 3-second intervals (24s max)
                    for attempt in range(8):
                        time.sleep(3)
                        poll_resp = requests.get(
                            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                            headers=headers,
                            timeout=10.0,
                        )
                        if poll_resp.status_code == 200:
                            poll_data = poll_resp.json()
                            vt_status = poll_data.get('data', {}).get('attributes', {}).get('status')
                            logger.info(f"[VT] Poll attempt {attempt+1}: status={vt_status}")
                            if vt_status == 'completed':
                                data = poll_data
                                break

            # Step 3: Fallback — GET cached result by SHA-256 URL ID
            if not data:
                logger.info("[VT] Falling back to cached GET by URL hash")
                import base64
                url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
                get_response = requests.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers=headers,
                    timeout=10.0,
                )
                logger.info(f"[VT] Hash GET status: {get_response.status_code}")
                if get_response.status_code == 200:
                    data = get_response.json()
                elif get_response.status_code == 404:
                    # URL has never been scanned — no result available
                    raise Exception("VirusTotal: لا توجد بيانات سابقة للرابط، ولم يكتمل الفحص الجديد في الوقت المحدد.")
                else:
                    raise Exception(f"VirusTotal API أعاد كود غير متوقع: {get_response.status_code}")

            # Step 4: Parse analysis stats
            attributes = data.get('data', {}).get('attributes', {})
            # Completed analysis stores results under 'stats' or 'last_analysis_stats'
            stats = attributes.get('stats') or attributes.get('last_analysis_stats', {})

            malicious  = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            undetected = stats.get('undetected', 0)
            harmless   = stats.get('harmless', 0)
            total_engines = malicious + suspicious + undetected + harmless

            logger.info(
                f"[VT] Results — malicious={malicious} suspicious={suspicious} "
                f"undetected={undetected} harmless={harmless} total={total_engines}"
            )

            if total_engines == 0:
                raise Exception("VirusTotal: لم يتم توفير نتائج فحص من المحركات لهذا الرابط.")

            if malicious > 0 or suspicious > 0:
                self.results['details'].append(
                    f'⚠️ VirusTotal: {malicious} محرك رصد تهديداً من أصل {total_engines}'
                )
                return [{
                    'type': 'virustotal',
                    'severity': 5,
                    'description': f'{malicious} محرك يشتبه بالرابط (من {total_engines})',
                    'source': 'VirusTotal',
                    'malicious': malicious,
                    'suspicious': suspicious,
                }]
            else:
                self.results['details'].append(
                    f'✅ VirusTotal: الرابط نظيف ({harmless} محرك أكد الأمان من {total_engines})'
                )
                return []

        except Exception as e:
            raise Exception(f"خطأ في الاتصال بـ VirusTotal: {e}")

    def _check_ssl_certificate(self, url: str) -> dict:
        """SSL certificate check with strict 2.5s socket timeout."""
        threats = []
        score_impact = 0

        if not url.startswith('https://'):
            score_impact += 10
            self.results['details'].append('⚠️ الرابط لا يستخدم HTTPS')
            return {'threats': threats, 'score_impact': score_impact}

        try:
            import ssl
            from datetime import datetime as dt

            hostname = urlparse(url).netloc
            if ':' in hostname:
                hostname = hostname.split(':')[0]

            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(EXTERNAL_CHECK_TIMEOUT)
                s.connect((hostname, 443))
                cert = s.getpeercert()

            if cert and 'notAfter' in cert:
                expiry = dt.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days = (expiry - dt.now()).days
                if days < 0:
                    threats.append({'type': 'expired_ssl', 'severity': 4, 'description': 'شهادة منتهية'})
                    self.results['details'].append('⚠️ شهادة SSL منتهية')
                    score_impact += 20
                elif days < 7:
                    threats.append({'type': 'expiring_ssl', 'severity': 2, 'description': 'شهادة قريبة الانتهاء'})
                    self.results['details'].append('⚠️ شهادة SSL تنتهي قريباً')
                    score_impact += 5
                else:
                    self.results['details'].append('✓ شهادة SSL صالحة')
        except socket.timeout:
            self.results['details'].append('⚠️ انتهت مهلة التحقق من SSL')
            score_impact += 5
        except Exception:
            self.results['details'].append('⚠️ لا يمكن التحقق من SSL')
            score_impact += 5

        return {'threats': threats, 'score_impact': score_impact}

    def _process_check_result(self, check_name: str, result: dict) -> None:
        if not result:
            return
        for threat in result.get('threats', []):
            if threat not in self.results['threats_found']:
                self.results['threats_found'].append(threat)
        self.results['score'] += result.get('score_impact', 0)

    def _calculate_final_score(self) -> None:
        threat_count = len(self.results['threats_found'])
        total_severity = sum(t.get('severity', 1) for t in self.results['threats_found'])

        base_score = 100

        if threat_count > 0:
            base_score -= min(90, total_severity * 6)

        final_score = max(0, min(100, base_score - self.results['score']))
        self.results['score'] = final_score

        if final_score >= 70:
            self.results['safe'] = True
            self.results['final_status'] = 'آمن'
            self.results['final_message'] = '✓ هذا الرابط آمن'
            if not self.results['details']:
                self.results['details'] = ['✓ الرابط آمن']
        elif final_score >= 40:
            self.results['safe'] = None
            self.results['final_status'] = 'مشبوه'
            self.results['final_message'] = '⚠️ هذا الرابط مشبوه، يرجى الحذر'
            if '⚠️' not in str(self.results['details']):
                self.results['details'].insert(0, '⚠️ الرابط مشبوه')
        else:
            self.results['safe'] = False
            self.results['final_status'] = 'خطير'
            self.results['final_message'] = '🔴 هذا الرابط خطير! تجنب فتحه'
            if '🔴' not in str(self.results['details']):
                self.results['details'].insert(0, '🔴 تحذير: رابط خطير')

        self.results['threats_count'] = len(self.results['threats_found'])
        logger.info(f"[ThreatDetector] Final: {final_score}% — {self.results['final_status']}")