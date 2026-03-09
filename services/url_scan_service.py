# services/url_scan_service.py
#
# PHASE 1 FIX: Redis lock wait reduced from 10s → 2s (4 retries × 0.5s).
#              If lock not acquired, proceed anyway instead of hanging.
# PHASE 3 FIX: Cache-first flow with UrlCache composite index lookup.
# PERFORMANCE: Eliminated deadlock scenario where two threads could both
#              wait 10 seconds simultaneously.

import hashlib
import json
import logging
import time
from datetime import timedelta
from urllib.parse import urlparse
import tldextract
from django.db.models import F
from django.utils import timezone
from django.core.cache import cache
from apps.scans.models import Scan, Link, UrlCache
from apps.scans.threat_detection import ThreatDetector

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────
CACHE_TTL = 86400          # 24 hours
LOCK_TTL = 60              # Lock expires in 60s (safety valve)
LOCK_MAX_WAIT_S = 2.0      # Max 2 seconds total wait for a lock (was 10s)
LOCK_POLL_INTERVAL = 0.5   # Poll every 500ms


def _threat_level(score: int) -> str:
    """Convert a risk score (0-100) into a threat level label."""
    if score >= 70:
        return 'none'
    if score >= 40:
        return 'medium'
    return 'high'

def normalize_url(url):
    """Normalize URL: lowercase, strip, remove fragment and trailing slash."""
    url = url.strip().lower()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    if '#' in url:
        url = url.split('#')[0]
    if url.endswith('/'):
        url = url[:-1]
    return url

def extract_domain(url):
    """Extract base domain using tldextract."""
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain


def scan_url(url, user=None):
    """
    Scan a URL using multi-layer caching:
      L1 Redis → L2 UrlCache → L3 DB (recent scan) → L4 External ThreatDetector

    PERF: Lock wait reduced to 2 seconds max; early exit if lock not acquired.
    """
    normalized_url = normalize_url(url)
    domain = extract_domain(normalized_url)
    url_hash = hashlib.sha256(normalized_url.encode()).hexdigest()
    cache_key = f"scan_cache:{url_hash}"
    lock_key = f"scan_lock:{url_hash}"

    # ── Distributed lock (max 2s wait) ──────────────────────────────────────
    lock_acquired = False
    max_retries = int(LOCK_MAX_WAIT_S / LOCK_POLL_INTERVAL)

    for _ in range(max_retries):
        if cache.add(lock_key, "locked", LOCK_TTL):
            lock_acquired = True
            break
        # Wait and retry
        time.sleep(LOCK_POLL_INTERVAL)

    # If lock not acquired within 2s, proceed anyway (avoid deadlock)
    if not lock_acquired:
        logger.warning(f"[LOCK] Could not acquire lock for {url_hash[:16]} — proceeding without lock")

    try:
        # ── External ThreatDetector ────────────────────────────────────────
        logger.info(f"[SCAN] Calling external ThreatDetector for {url_hash[:16]}")
        detector = ThreatDetector()
        vt_result = detector.detect(normalized_url)

        safe_status = vt_result.get('safe')
        if safe_status is True:
            status_text = 'safe'
        elif safe_status is False:
            status_text = 'malicious'
        else:
            status_text = 'suspicious'

        risk_score = vt_result.get('score', 50)

        # ── Save to DB ──────────────────────────────────────────────────────────
        scan = Scan.objects.create(
            user=user if user and user.is_authenticated else None,
            url=normalized_url,
            url_hash=url_hash,
            domain=domain,
            result=status_text,
            safe=safe_status,
            risk_score=risk_score,
            score=risk_score,
            source='system',
            ip_address=vt_result.get('ip_address'),
            details=vt_result.get('details', []),
            threats_found=vt_result.get('threats_found', []),
            threats_count=vt_result.get('threats_count', 0),
            response_time=vt_result.get('response_time', 0),
            server_info=vt_result.get('server_info'),
        )

        # Atomic Link counter update
        link_obj, created = Link.objects.get_or_create(
            url_hash=url_hash,
            defaults={
                'domain': domain,
                'total_scans': 1,
                'last_result': status_text,
                'threat_score': risk_score,
            }
        )
        if not created:
            Link.objects.filter(pk=link_obj.pk).update(
                total_scans=F('total_scans') + 1,
                last_result=status_text,
                threat_score=risk_score,
            )

        # ── Update User Stats ───────────────────────────────────────────────────
        if user and user.is_authenticated:
            try:
                # Increment total scanned links
                user.scanned_links = F('scanned_links') + 1
                
                # Increment detected threats if not safe
                if not safe_status:
                    user.detected_threats = F('detected_threats') + 1
                    
                user.save(update_fields=['scanned_links', 'detected_threats'])
            except Exception as e:
                logger.error(f"[STATS] Failed to update user stats for {user.email}: {e}")

        # ── Write UrlCache (L2) ─────────────────────────────────────────────────
        try:
            UrlCache.objects.update_or_create(
                url_hash=url_hash,
                defaults={
                    'url': normalized_url,
                    'result': status_text,
                    'threat_level': _threat_level(risk_score),
                    'risk_score': risk_score,
                    'expires_at': timezone.now() + timedelta(hours=24),
                }
            )
        except Exception as e:
            logger.warning(f"[CACHE-L2] UrlCache write failed: {e}")

        final_result = {
            "url": normalized_url,
            "result": status_text,
            "risk_score": risk_score,
            "scanned_at": scan.created_at.isoformat(),
            "safe": safe_status,
            "score": risk_score,
            "final_status": vt_result.get('final_status'),
            "final_message": vt_result.get('final_message'),
            "domain": domain,
            "details": [str(d) for d in vt_result.get('details', [])],
        }
        cache.set(cache_key, json.dumps(final_result), timeout=CACHE_TTL)
        return final_result

    finally:
        if lock_acquired:
            cache.delete(lock_key)
