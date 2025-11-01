# Run: pip install streamlit pandas requests

import streamlit as st
import pandas as pd
from datetime import datetime, timezone
import os
from typing import List, Dict, Any, Optional

import time
import requests
import json
import random
import string
from version import get_version_info

# ----------------------------
# Streamlit Page Configuration
# ----------------------------
st.set_page_config(page_title="Instagram Reels Analyzer", layout="wide")

# Lightweight theme to resemble the provided mock
st.markdown(
    """
<style>
:root { --card-bg:#1b1f2a; --tab-bg:#262c3a; --tab-active:#2f3748; --border:rgba(255,255,255,0.08); }
.stApp { background:#0f1421; }
.block-container { padding-top: 2rem; max-width: 1100px; }
.card { background: var(--card-bg); border:1px solid var(--border); border-radius:14px; overflow:hidden; box-shadow:0 8px 30px rgba(0,0,0,.35); }
.stTabs [data-baseweb="tab-list"]{ gap:8px; background:var(--tab-bg); padding:10px 12px; border-bottom:1px solid var(--border); }
.stTabs [data-baseweb="tab"]{ background:transparent; border-radius:10px 10px 0 0; padding:10px 16px; color:#c9d1d9; }
.stTabs [aria-selected="true"]{ background:var(--tab-active); border:1px solid var(--border); border-bottom-color:transparent; }
input, textarea { background:#141925 !important; color:#e6edf3 !important; border:1px solid var(--border) !important; border-radius:10px !important; }
.stButton > button { background:#2d3650; border:1px solid var(--border); color:#e6edf3; border-radius:10px; padding:.5rem 1rem; }
.stButton > button:hover { background:#394261; border-color:#3e4a6b; }
.k-primary { background:#5960ff !important; border-color:#5960ff !important; }
.small-tip { color:#8b949e; font-size:12px; border-top:1px dashed var(--border); padding-top:10px; margin-top:16px; }
.footer-note { color:#6b7280; font-size:12px; text-align:right; }
.header-logo { display:flex; align-items:center; gap:12px; margin-bottom:12px; }
.badge { background:#5960ff; color:#fff; border-radius:10px; padding:6px 10px; font-weight:600; }
</style>
""",
    unsafe_allow_html=True,
)

# ----------------------------
# UI Header
# ----------------------------
# Get version info
version_info = get_version_info()

st.markdown("# Instagram Reels Analyzer")
st.markdown(f"""
<div class='header-logo'>
  <div class='badge'>A</div>
  <div>
    <div style='font-weight:600; font-size:20px;'>Logo</div>
    <div style='color:#9aa4b2; font-size:13px;'>Sleek tabbed interface</div>
    <div style='color:#b8c5d6; font-size:11px; margin-top: 5px;'>Version {version_info['version']} | Built {version_info['build_date']}</div>
  </div>
</div>
""", unsafe_allow_html=True)


# ----------------------------
# Helpers
# ----------------------------
def format_count(n: Optional[int]) -> str:
    if n is None:
        return "—"
    if n < 1_000:
        return str(n)
    if n < 1_000_000:
        return f"{n/1_000:.1f}K"
    if n < 1_000_000_000:
        return f"{n/1_000_000:.1f}M"
    return f"{n/1_000_000_000:.1f}B"

def to_yyyymmdd(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d")

def build_reel_url(shortcode: str) -> str:
    return f"https://www.instagram.com/reel/{shortcode}/"

# ----------------------------
# Web API helper (requires cookies)
# ----------------------------
def get_shared_session() -> requests.Session:
    """Shared HTTP session to reuse TCP connections across requests."""
    sess = st.session_state.get("_shared_http_session")
    if sess is None:
        sess = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50, max_retries=0)
        sess.mount("https://", adapter)
        sess.headers.update({
            "user-agent": "Mozilla/5.0",
            "accept": "*/*",
        })
        st.session_state["_shared_http_session"] = sess
    return sess
def extract_shortcode(reel_url: str) -> Optional[str]:
    try:
        # Accept forms like https://www.instagram.com/reel/<shortcode>/ or /p/<shortcode>/
        # Normalize and strip trailing punctuation/copy artifacts
        import re
        text = (reel_url or "").strip()
        m = re.search(r"/(?:reel|p)/([A-Za-z0-9_]+)/?", text)
        code = m.group(1) if m else None
        if not code:
            return None
        # Safety: allow only instagram shortcode charset (alnum + underscore); strip any extras
        code = re.sub(r"[^A-Za-z0-9_]", "", code)
        return code or None
    except Exception:
        return None

def fetch_play_count_with_cookies(reel_url: str, cookie_header: str) -> Optional[int]:
    shortcode = extract_shortcode(reel_url)
    if not shortcode:
        raise ValueError("Invalid Reel URL")

    url = f"https://www.instagram.com/api/v1/media/shortcode/{shortcode}/info/"
    # Try to forward csrftoken to improve reliability
    def _extract_cookie_value(cookie_str: str, key: str) -> Optional[str]:
        try:
            parts = [p.strip() for p in cookie_str.split(';')]
            for p in parts:
                if p.startswith(key + "="):
                    return p.split('=', 1)[1]
        except Exception:
            return None
        return None

    csrf = _extract_cookie_value(cookie_header, "csrftoken") if cookie_header else None

    headers = {
        "x-ig-app-id": "936619743392459",
        "x-requested-with": "XMLHttpRequest",
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        "referer": f"https://www.instagram.com/reel/{shortcode}/",
        "accept": "*/*",
    }
    if cookie_header:
        headers["cookie"] = cookie_header
    if csrf:
        headers["x-csrftoken"] = csrf
    # Throttle: ensure at least 20s between cookie-based calls
    min_interval = 20
    now = time.time()
    last_ts = st.session_state.get("last_cookie_call_ts", 0)
    if now - last_ts < min_interval:
        time.sleep(min_interval - (now - last_ts))

    # Exponential backoff on 429/5xx
    backoffs = [1.5, 3.0, 6.0]
    for i, wait_s in enumerate([0.0] + backoffs):
        if wait_s:
            time.sleep(wait_s)
        resp = get_shared_session().get(url, headers=headers, timeout=20)
        if resp.status_code == 429 and i < len(backoffs):
            continue
        break

    st.session_state["last_cookie_call_ts"] = time.time()

    if resp.status_code in (401, 403):
        raise PermissionError("Unauthorized or cookies expired")
    if resp.status_code == 429:
        raise ConnectionError("Rate limited (429)")
    resp.raise_for_status()
    data = resp.json()
    item = (data.get("items") or [None])[0] or data
    return (
        item.get("play_count")
        or item.get("video_play_count")
        or item.get("view_count")
        or item.get("video_view_count")
    )

# ----------------------------
# Fetch CSRF token from Instagram homepage (public, no auth needed)
# ----------------------------
def fetch_csrf_token_from_homepage() -> Optional[str]:
    """Fetch CSRF token from Instagram's homepage HTML. This is publicly accessible."""
    try:
        headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.9",
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        }
        # Use a fresh session to avoid any stale cookies or state
        fresh_session = requests.Session()
        resp = fresh_session.get("https://www.instagram.com/", headers=headers, timeout=10)
        if resp.ok:
            # Extract CSRF token from HTML - it's usually in a script tag or meta tag
            import re
            # Look for csrftoken in cookies first
            cookies = resp.cookies
            if "csrftoken" in cookies:
                return cookies["csrftoken"]
            # Or extract from HTML content
            text = resp.text
            # Try multiple patterns for csrf_token
            patterns = [
                r'"csrf_token"\s*:\s*"([^"]+)"',
                r'{"config":\{[^}]*"csrf_token"\s*:\s*"([^"]+)"',
                r'"_csrf_token"\s*:\s*"([^"]+)"',
                r'X-CSRFToken["\']\s*[:=]\s*["\']([^"\']+)',
            ]
            for pattern in patterns:
                m = re.search(pattern, text)
                if m:
                    token = m.group(1)
                    # Validate it looks like a token (alphanumeric and reasonably long)
                    if len(token) >= 10 and len(token) <= 50:
                        return token
    except Exception as e:
        # Log the error for debugging
        pass
    return None

# ----------------------------
# GraphQL: Direct reel metrics fetch (no auth, public content)
# ----------------------------
_cached_public_ip = None

def get_public_ip() -> str:
    """Get the public IP address of the machine. Cached per application run."""
    global _cached_public_ip
    if _cached_public_ip is None:
        try:
            response = requests.get('https://api.ipify.org', timeout=5)
            if response.ok:
                _cached_public_ip = response.text.strip()
            else:
                _cached_public_ip = 'N/A'
        except Exception:
            _cached_public_ip = 'N/A'
    return _cached_public_ip

def fetch_reel_metrics_public(
    shortcode: str,
    max_retries: int = 3,
) -> Dict[str, Any]:
    """Fetch video_view_count and video_play_count for an Instagram Reel without authentication.
    
    Uses Instagram's public GraphQL endpoint with doc_id=8845758582119845.
    
    Args:
        shortcode: Instagram reel shortcode (e.g., "DQcHMG1kmbq")
        max_retries: Maximum retry attempts on 403 errors
    
    Returns:
        dict: {'video_view_count': int, 'video_play_count': int, ...} or {} on failure
    """
    debug_info = []
    last_status_code = None
    
    def debug_log(msg: str):
        debug_info.append(msg)
    
    try:
        # Create session
        session = requests.Session()
        
        # Set initial headers
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.8'
        })
        
        # Step 1: Get CSRF token
        debug_log("Fetching CSRF token from Instagram homepage")
        homepage_resp = session.get('https://www.instagram.com/', timeout=30)
        if not homepage_resp.ok:
            debug_log(f"Failed to fetch homepage: {homepage_resp.status_code}")
            return {'_status_code': homepage_resp.status_code}
        
        csrf_tokens = [c.value for c in session.cookies if c.name == 'csrftoken']
        csrf_token = csrf_tokens[-1] if csrf_tokens else None
        
        if not csrf_token:
            debug_log("No CSRF token found in cookies")
            return {'_status_code': 'no_csrf_token'}
        
        debug_log(f"Got CSRF token: {csrf_token[:20]}...")
        
        # Step 2: Query reel metrics with retries
        url = "https://www.instagram.com/graphql/query/"
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest',
            'X-CSRFToken': csrf_token,
            'X-Instagram-AJAX': '1',
            'Referer': 'https://www.instagram.com/',
            'Origin': 'https://www.instagram.com',
            'authority': 'www.instagram.com'
        }
        
        data = {
            'doc_id': '8845758582119845',
            'variables': json.dumps({'shortcode': shortcode}),
            'server_timestamps': 'true'
        }
        
        debug_log(f"Querying GraphQL endpoint with doc_id=8845758582119845")
        debug_log(f"Variables: {data['variables']}")
        
        for attempt in range(1, max_retries + 1):
            try:
                debug_log(f"Attempt {attempt}/{max_retries}")
                response = session.post(url, headers=headers, data=data, timeout=30)
                last_status_code = response.status_code
                
                if response.status_code == 200:
                    resp_json = response.json()
                    debug_log(f"Response JSON keys: {list(resp_json.keys())}")
                    if resp_json.get('status') == 'ok':
                        media = resp_json.get('data', {}).get('xdt_shortcode_media')
                        debug_log(f"Media keys: {list(media.keys()) if media else 'None'}")
                        if media:
                            debug_log("Successfully fetched reel metrics")
                            
                            # Debug: Log raw response for diagnosis
                            debug_log(f"Raw media response preview: {json.dumps(media, indent=2)[:2000]}")
                            
                            # Extract like and comment counts
                            like_count = ((media.get('edge_liked_by') or {}).get('count') or 
                                         (media.get('edge_media_preview_like') or {}).get('count') or 
                                         0)
                            comment_count = ((media.get('edge_media_preview_comment') or {}).get('count') or 
                                           (media.get('edge_media_to_comment') or {}).get('count') or 
                                           0)
                            
                            # Extract taken_at_timestamp
                            taken_at_timestamp = media.get('taken_at_timestamp')
                            try:
                                posted_on = datetime.fromtimestamp(int(taken_at_timestamp), timezone.utc).strftime("%Y-%m-%d") if taken_at_timestamp else None
                            except Exception:
                                posted_on = None
                            
                            result = {
                                'id': media.get('id'),  # Media ID
                                'video_view_count': media.get('video_view_count'),
                                'video_play_count': media.get('video_play_count'),
                                'shortcode': media.get('shortcode'),
                                'play_count': media.get('video_play_count'),  # Use video_play_count for Total Views column
                                'like_count': like_count,
                                'comment_count': comment_count,
                                'taken_at_timestamp': taken_at_timestamp,
                                'posted_on': posted_on,
                                '_debug': debug_info
                            }
                            debug_log(f"Returning result: view={result['play_count']}, like={like_count}, comment={comment_count}")
                            return result
                        else:
                            debug_log("Response OK but no xdt_shortcode_media in data")
                            debug_log(f"Data keys: {list(resp_json.get('data', {}).keys())}")
                            debug_log(f"Full data: {json.dumps(resp_json.get('data', {}), indent=2)[:1000]}")
                    else:
                        debug_log(f"Response status not OK: {resp_json.get('status')}")
                        debug_log(f"Full response: {json.dumps(resp_json, indent=2)[:1000]}")
                elif response.status_code == 403 and attempt < max_retries:
                    # Refresh session and retry
                    debug_log(f"403 Forbidden, refreshing session (attempt {attempt})")
                    import time
                    time.sleep(2)
                    homepage_resp = session.get('https://www.instagram.com/', timeout=30)
                    csrf_tokens = [c.value for c in session.cookies if c.name == 'csrftoken']
                    csrf_token = csrf_tokens[-1] if csrf_tokens else csrf_token
                    headers['X-CSRFToken'] = csrf_token
                    debug_log(f"New CSRF token: {csrf_token[:20]}...")
                    continue
                else:
                    debug_log(f"Non-200/403 status code: {response.status_code}")
                    debug_log(f"Response text: {response.text[:500]}")
                    return {'_status_code': response.status_code}
                    
            except Exception as e:
                if attempt < max_retries:
                    debug_log(f"Exception on attempt {attempt}: {type(e).__name__}: {e}")
                    import time
                    time.sleep(2)
                    continue
                debug_log(f"Exception on final attempt: {type(e).__name__}: {e}")
                return {'_status_code': f'Exception: {type(e).__name__}'}
        
        # All retries exhausted
        debug_log("All retry attempts exhausted")
        return {'_status_code': last_status_code if last_status_code else 'retry_exhausted'}
        
    except Exception as e:
        debug_log(f"Exception in fetch_reel_metrics_public: {type(e).__name__}: {e}")
        return {'_status_code': f'Exception: {type(e).__name__}'}

# ----------------------------
# GraphQL: Profile Reels tab (per your cURL)
# ----------------------------
def fetch_profile_reels_public(
    target_user_id: str,
    page_size: int = 12,
    max_id: Optional[str] = None,
    referer: str = "https://www.instagram.com/",
    cookie_header: Optional[str] = None,
    _cache_buster: Optional[str] = None,  # Add timestamp to prevent caching
) -> Dict[str, Any]:
    """Fetch profile reels via clips/user endpoint. CSRF token is fetched automatically if not provided.

    Returns the JSON dict which typically includes an "items" list with media objects under "media".
    Note: This function does NOT cache to ensure fresh data on every call.
    """
    def _extract_cookie_value(cookie_str: str, key: str) -> Optional[str]:
        try:
            parts = [p.strip() for p in cookie_str.split(';')]
            for p in parts:
                if p.startswith(key + "="):
                    return p.split('=', 1)[1]
        except Exception:
            return None
        return None

    headers = {
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
        "content-type": "application/x-www-form-urlencoded",
        "origin": "https://www.instagram.com",
        "referer": referer,
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        "x-asbd-id": "359341",
        "x-ig-app-id": "936619743392459",
        "x-ig-www-claim": "0",
        "x-instagram-ajax": "1029208420",
        "x-requested-with": "XMLHttpRequest",
    }
    
    # Extract or fetch CSRF token
    csrf_token = None
    if cookie_header:
        headers["cookie"] = cookie_header
        csrf_token = _extract_cookie_value(cookie_header, "csrftoken")
    
    # If no CSRF token from cookies, fetch it from Instagram homepage
    if not csrf_token:
        csrf_token = fetch_csrf_token_from_homepage()
    
    if csrf_token:
        headers["x-csrftoken"] = csrf_token
    
    # Generate a random jazoest value (Instagram sometimes requires this)
    jazoest = ''.join(random.choices(string.digits, k=5))
    data = {
        "include_feed_video": "true",
        "page_size": str(int(page_size)),
        "target_user_id": str(target_user_id),
        "jazoest": jazoest,
    }
    if max_id:
        data["max_id"] = str(max_id)

    # Throttle requests to be conservative
    min_interval = 5
    now = time.time()
    last_ts = st.session_state.get("last_public_reels_call_ts", 0)
    if now - last_ts < min_interval:
        time.sleep(min_interval - (now - last_ts))

    for i, wait_s in enumerate([0.0, 1.0, 2.0]):
        if wait_s:
            time.sleep(wait_s)
        resp = requests.post("https://www.instagram.com/api/v1/clips/user/", headers=headers, data=data, timeout=20)
        if resp.status_code != 429 or i == 2:
            break

    st.session_state["last_public_reels_call_ts"] = time.time()
    
    # Debug logging for troubleshooting
    if resp.status_code != 200:
        import json as json_module
        try:
            error_body = resp.json()
        except:
            error_body = resp.text[:500]
    
    if resp.status_code == 403:
        error_msg = resp.text[:500]
        if "CSRF" in error_msg or "csrf" in error_msg.lower():
            raise PermissionError(f"CSRF token issue (403). Failed to fetch valid CSRF token. CSRF token used: {csrf_token[:20] if csrf_token else 'None'}... Response: {error_msg}")
        raise PermissionError(f"Access denied (403). Profile may be private or request was blocked. Response: {error_msg}")
    if resp.status_code == 429:
        raise ConnectionError("Rate limited (429)")
    if not resp.ok:
        error_msg = resp.text[:500]
        raise PermissionError(f"Request failed with status {resp.status_code}. Response: {error_msg}")
    resp.raise_for_status()
    return resp.json()

# ----------------------------
# Caption by media pk via comments endpoint
# ----------------------------
def fetch_caption_by_media_pk(
    media_pk: str,
    cookie_header: str,
    referer_url: Optional[str] = None,
) -> Optional[str]:
    def _extract_cookie_value(cookie_str: str, key: str) -> Optional[str]:
        try:
            parts = [p.strip() for p in cookie_str.split(';')]
            for p in parts:
                if p.startswith(key + "="):
                    return p.split('=', 1)[1]
        except Exception:
            return None
        return None

    csrf = _extract_cookie_value(cookie_header, "csrftoken")
    url = f"https://www.instagram.com/api/v1/media/{media_pk}/comments/?can_support_threading=true&permalink_enabled=false"
    headers = {
        "accept": "*/*",
        "user-agent": "Mozilla/5.0",
        "x-ig-app-id": "936619743392459",
        "x-requested-with": "XMLHttpRequest",
        "cookie": cookie_header,
        "referer": referer_url or "https://www.instagram.com/",
    }
    if csrf:
        headers["x-csrftoken"] = csrf

    # Throttle and backoff similar to others
    min_interval = 5
    now = time.time()
    last_ts = st.session_state.get("last_comments_call_ts", 0)
    if now - last_ts < min_interval:
        time.sleep(min_interval - (now - last_ts))

    backoffs = [1.0, 2.0, 4.0]
    for i, wait_s in enumerate([0.0] + backoffs):
        if wait_s:
            time.sleep(wait_s)
        resp = get_shared_session().get(url, headers=headers, timeout=20)
        if resp.status_code == 429 and i < len(backoffs):
            continue
        break

    st.session_state["last_comments_call_ts"] = time.time()

    if resp.status_code in (401, 403):
        raise PermissionError("Unauthorized or cookies expired")
    if resp.status_code == 429:
        raise ConnectionError("Rate limited (429)")
    resp.raise_for_status()
    data = resp.json()
    cap = (data or {}).get("caption") or {}
    return cap.get("text")

# ----------------------------
# Media stats (play_count, like_count, comment_count) by media pk
# ----------------------------
def fetch_media_stats_by_pk(
    media_pk: str,
    cookie_header: str,
    referer_url: Optional[str] = None,
) -> Dict[str, Any]:
    def _extract_cookie_value(cookie_str: str, key: str) -> Optional[str]:
        try:
            parts = [p.strip() for p in cookie_str.split(';')]
            for p in parts:
                if p.startswith(key + "="):
                    return p.split('=', 1)[1]
        except Exception:
            return None
        return None

    csrf = _extract_cookie_value(cookie_header, "csrftoken")
    url = f"https://www.instagram.com/api/v1/media/{media_pk}/info/"
    headers = {
        "accept": "*/*",
        "user-agent": "Mozilla/5.0",
        "x-ig-app-id": "936619743392459",
        "x-requested-with": "XMLHttpRequest",
        "cookie": cookie_header,
        "referer": referer_url or "https://www.instagram.com/",
    }
    if csrf:
        headers["x-csrftoken"] = csrf

    # Simple backoff for 429s
    for i, wait_s in enumerate([0.0, 1.5, 3.0]):
        if wait_s:
            time.sleep(wait_s)
        resp = requests.get(url, headers=headers, timeout=20)
        if resp.status_code != 429 or i == 2:
            break

    if resp.status_code in (401, 403):
        raise PermissionError("Unauthorized or cookies expired")
    if resp.status_code == 429:
        raise ConnectionError("Rate limited (429)")
    resp.raise_for_status()
    data = resp.json()
    item = (data.get("items") or [None])[0] or data
    ts = item.get("taken_at_timestamp") or item.get("taken_at")
    posted_on = None
    try:
        if ts:
            posted_on = datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        posted_on = None
    return {
        "play_count": item.get("play_count") or item.get("video_play_count") or item.get("view_count"),
        "like_count": item.get("like_count") or (item.get("edge_liked_by") or {}).get("count"),
        "comment_count": item.get("comment_count") or (item.get("edge_media_to_comment") or {}).get("count"),
        "shortcode": item.get("code") or item.get("shortcode"),
        "posted_on": posted_on,
        "product_type": item.get("product_type"),
        "media_type": item.get("media_type"),
    }

# ----------------------------
# Media owner info (username, full_name) by media pk
# ----------------------------
def fetch_media_owner_by_pk(
    media_pk: str,
    cookie_header: str,
    referer_url: Optional[str] = None,
) -> Dict[str, Any]:
    def _extract_cookie_value(cookie_str: str, key: str) -> Optional[str]:
        try:
            parts = [p.strip() for p in cookie_str.split(';')]
            for p in parts:
                if p.startswith(key + "="):
                    return p.split('=', 1)[1]
        except Exception:
            return None
        return None

    csrf = _extract_cookie_value(cookie_header, "csrftoken")
    url = f"https://www.instagram.com/api/v1/media/{media_pk}/info/"
    headers = {
        "accept": "*/*",
        "user-agent": "Mozilla/5.0",
        "x-ig-app-id": "936619743392459",
        "x-requested-with": "XMLHttpRequest",
        "cookie": cookie_header,
        "referer": referer_url or "https://www.instagram.com/",
    }
    if csrf:
        headers["x-csrftoken"] = csrf

    resp = requests.get(url, headers=headers, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    item = (data.get("items") or [None])[0] or data
    user = item.get("user") or {}
    return {
        "user_id": user.get("pk") or user.get("id"),
        "username": user.get("username"),
        "full_name": user.get("full_name"),
        "is_private": user.get("is_private"),
        "is_verified": user.get("is_verified"),
        "profile_pic_url": user.get("profile_pic_url"),
    }

# ----------------------------
# Resolve media by shortcode → returns item (contains pk/code/counts)
# ----------------------------
def resolve_media_by_shortcode(
    shortcode: str,
    cookie_header: str,
    referer_url: Optional[str] = None,
) -> Dict[str, Any]:
    def _extract_cookie_value(cookie_str: str, key: str) -> Optional[str]:
        try:
            parts = [p.strip() for p in cookie_str.split(';')]
            for p in parts:
                if p.startswith(key + "="):
                    return p.split('=', 1)[1]
        except Exception:
            return None
        return None

    csrf = _extract_cookie_value(cookie_header, "csrftoken")
    url = f"https://www.instagram.com/api/v1/media/shortcode/{shortcode}/info/"
    headers = {
        "accept": "*/*",
        "user-agent": "Mozilla/5.0",
        "x-ig-app-id": "936619743392459",
        "x-requested-with": "XMLHttpRequest",
        "cookie": cookie_header,
        "referer": referer_url or f"https://www.instagram.com/p/{shortcode}/",
    }
    if csrf:
        headers["x-csrftoken"] = csrf

    # Prefer /reel/ referer first, then /p/ fallback
    headers["referer"] = f"https://www.instagram.com/reel/{shortcode}/"
    resp = requests.get(url, headers=headers, timeout=20)
    if resp.status_code == 404:
        headers["referer"] = f"https://www.instagram.com/p/{shortcode}/"
        resp = requests.get(url, headers=headers, timeout=20)

    # If still failing, try bulk-route-definitions resolver to get media_id
    if resp.status_code in (404, 500):
        try:
            bulk_headers = {
                "accept": "*/*",
                "content-type": "application/x-www-form-urlencoded",
                "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
                "cookie": cookie_header,
                "origin": "https://www.instagram.com",
                "referer": f"https://www.instagram.com/reel/{shortcode}/",
            }
            bulk_headers["x-ig-d"] = "www"
            data = {
                "route_urls[0]": f"/reel/{shortcode}/",
                "routing_namespace": "igx_www$a$87a091182d5bd65bcb043a2888004e09",
                "__d": "www",
                "__a": "1",
                "dpr": "2",
            }
            bulk = requests.post(
                "https://www.instagram.com/ajax/bulk-route-definitions/",
                headers=bulk_headers,
                data=data,
                timeout=20,
            )
            if bulk.ok:
                j = bulk.json()
                # Heuristic: find a media_id in the payload
                import re
                m = re.search(r"(\d{10,})_\d+", json.dumps(j))
                media_id = None
                if m:
                    # Use the first capture group as id
                    media_id = m.group(1)
                if not media_id:
                    m2 = re.search(r"\"media_id\"\s*:\s*\"(\d+)\"", json.dumps(j))
                    if m2:
                        media_id = m2.group(1)
                if media_id:
                    info = requests.get(
                        f"https://www.instagram.com/api/v1/media/{media_id}/info/",
                        headers=headers,
                        timeout=20,
                    )
                    if info.ok:
                        data = info.json()
                        return (data.get("items") or [None])[0] or data
        except Exception:
            pass

    if resp.status_code in (401, 403):
        raise PermissionError("Unauthorized or cookies expired")
    if resp.status_code == 429:
        raise ConnectionError("Rate limited (429)")
    resp.raise_for_status()
    data = resp.json()
    return (data.get("items") or [None])[0] or data

# ----------------------------
# Fetch media stats via GraphQL for unauthenticated requests
# Uses bulk-route-definitions to get media_id and owner_id, then GraphQL to get video_view_count
# ----------------------------
def fetch_reel_stats_via_graphql(
    shortcode: str,
    cookie_header: str = "",
    debug: bool = False,
) -> Dict[str, Any]:
    """Fetch reel stats (play_count, likes, comments) for unauthenticated requests.
    
    Flow:
    1. Call bulk-route-definitions to get media_id and owner_id
    2. Call graphql/query with owner_id to get user's reels
    3. Match media_id in GraphQL response to get video_view_count
    
    Returns dict with play_count, like_count, comment_count, shortcode, posted_on, etc.
    If debug=True, also includes '_debug' key with diagnostic info.
    """
    debug_info = []
    
    def debug_log(msg: str):
        if debug:
            debug_info.append(msg)
            print(msg)  # Also print for terminal
    
    try:
        # Step 1: Get media_id and owner_id from bulk-route-definitions
        # For unauthenticated requests, we need more complete headers to mimic a real browser
        headers_bulk = {
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9",
            "content-type": "application/x-www-form-urlencoded",
            "origin": "https://www.instagram.com",
            "referer": f"https://www.instagram.com/reel/{shortcode}/",
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
            "x-ig-d": "www",
            "x-ig-app-id": "936619743392459",
            "x-requested-with": "XMLHttpRequest",
            "sec-ch-ua": '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        }
        # Get basic cookies if not provided (Instagram requires at least csrftoken, datr, ig_did even for public content)
        cookie_string = cookie_header
        lsd_token = None
        if not cookie_string:
            # Fetch basic cookies from Instagram homepage - use a fresh session to avoid stale cookies
            try:
                # Create a fresh session for the homepage request to ensure we get fresh cookies
                fresh_session = requests.Session()
                homepage_resp = fresh_session.get(
                    "https://www.instagram.com/",
                    headers={
                        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "accept-language": "en-US,en;q=0.9",
                        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
                    },
                    timeout=10,
                )
                if homepage_resp.ok:
                    cookies_dict = {}
                    for cookie in homepage_resp.cookies:
                        cookies_dict[cookie.name] = cookie.value
                    debug_log(f"Homepage response - total cookies received: {len(cookies_dict)}, cookie names: {list(cookies_dict.keys())}")
                    # Build cookie string from basic cookies Instagram sets
                    cookie_parts = []
                    for key in ["csrftoken", "datr", "ig_did", "ig_nrcb", "mid"]:
                        if key in cookies_dict:
                            cookie_parts.append(f"{key}={cookies_dict[key]}")
                    if cookie_parts:
                        cookie_string = "; ".join(cookie_parts)
                        debug_log(f"Fetched basic cookies: {', '.join([key for key in cookies_dict.keys() if key in ['csrftoken', 'datr', 'ig_did', 'ig_nrcb', 'mid']])}")
                        # Log actual cookie values for debugging (truncated)
                        for key in ["csrftoken", "datr", "ig_did", "ig_nrcb", "mid"]:
                            if key in cookies_dict:
                                debug_log(f"Cookie {key}: {cookies_dict[key][:10]}...")
                    else:
                        debug_log(f"⚠️ No expected cookies found! All cookies from homepage: {list(cookies_dict.keys())}")
                    
                    # Extract lsd token and other tokens from HTML (needed for x-fb-lsd header)
                    import re
                    html_text = homepage_resp.text
                    # Pattern: "LSD",[],{"token":"..."}
                    lsd_match = re.search(r'"LSD",\[\],\{"token":"([^"]+)"', html_text)
                    if not lsd_match:
                        # Try alternative pattern
                        lsd_match = re.search(r'"lsd":"([^"]+)"', html_text)
                    if lsd_match:
                        lsd_token = lsd_match.group(1)
                        debug_log(f"Extracted lsd token: {lsd_token[:20]}...")
                    
                    # Also try to extract csrftoken from HTML since we're not getting cookies
                    # Pattern: "csrf_token":"..." or "X-CSRFToken":"..."
                    csrf_html_match = re.search(r'["\']csrf_token["\']\s*:\s*["\']([^"\']+)["\']', html_text)
                    if csrf_html_match:
                        csrf_from_html = csrf_html_match.group(1)
                        if not cookie_string:
                            cookie_string = f"csrftoken={csrf_from_html}"
                            debug_log(f"Extracted csrftoken from HTML: {csrf_from_html[:20]}...")
                        elif "csrftoken" not in cookie_string:
                            cookie_string += f"; csrftoken={csrf_from_html}"
                            debug_log(f"Added csrftoken from HTML to cookie string")
            except Exception as e:
                debug_log(f"Failed to fetch basic cookies: {e}")
        
        if cookie_string:
            headers_bulk["cookie"] = cookie_string
            # Add lsd token to headers if we have it
            if lsd_token:
                headers_bulk["x-fb-lsd"] = lsd_token
            # Extract CSRF token from cookies for x-csrftoken header
            def _extract_cookie_value(cookie_str: str, key: str) -> Optional[str]:
                try:
                    parts = [p.strip() for p in cookie_str.split(';')]
                    for p in parts:
                        if p.startswith(key + "="):
                            return p.split('=', 1)[1]
                except Exception:
                    return None
                return None
            csrf_from_cookie = _extract_cookie_value(cookie_string, "csrftoken")
            if csrf_from_cookie:
                headers_bulk["x-csrftoken"] = csrf_from_cookie
        
        # Build minimal payload (Instagram accepts minimal fields for unauthenticated requests)
        import urllib.parse
        # For unauthenticated requests, try the full path format that matches the response
        # The request can be /reel/{shortcode}/ but response key might be /{username}/reel/{shortcode}/
        route_path = f"/reel/{shortcode}/"
        
        data_bulk = {
            "route_urls[0]": route_path,
            "routing_namespace": "igx_www$a$87a091182d5bd65bcb043a2888004e09",
            "__d": "www",
            "__user": "0",
            "__a": "1",
            "__req": "8",
            "dpr": "2",
        }
        
        # Add lsd to data payload if we have it
        if lsd_token:
            data_bulk["lsd"] = lsd_token
            debug_log(f"Added lsd to data payload")
        
        # Try bulk route with timeout and retry
        resp_bulk = None
        for attempt in range(2):
            try:
                resp_bulk = get_shared_session().post(
                    "https://www.instagram.com/ajax/bulk-route-definitions/",
                    headers=headers_bulk,
                    data=data_bulk,
                    timeout=30 if attempt == 0 else 60,
                )
                break
            except requests.exceptions.Timeout:
                if attempt == 0:
                    debug_log(f"⚠️ Timeout on attempt {attempt + 1}, retrying...")
                    continue
                else:
                    debug_log(f"❌ Timeout on attempt {attempt + 1}, giving up")
                    raise
        
        if not resp_bulk:
            error_msg = "Failed to get response from bulk-route (timeout/connection error)"
            debug_log(error_msg)
            result = {}
            if debug:
                result["_debug"] = debug_info
                result["_error"] = error_msg
            return result
        
        if not resp_bulk.ok:
            error_msg = f"Bulk route failed: {resp_bulk.status_code} - {resp_bulk.text[:200]}"
            debug_log(error_msg)
            result = {}
            if debug:
                result["_debug"] = debug_info
                result["_error"] = error_msg
            return result
        
        text_bulk = resp_bulk.text
        
        # Check if response is HTML (Instagram returned a login page or error)
        if text_bulk.strip().startswith("<!DOCTYPE") or text_bulk.strip().startswith("<html"):
            error_msg = f"Bulk route returned HTML instead of JSON (status {resp_bulk.status_code}). Instagram may be blocking the request."
            debug_log(error_msg)
            debug_log(f"Response headers: {dict(resp_bulk.headers)}")
            # Try to extract error message from HTML
            import re
            html_error_match = re.search(r'<title>([^<]+)</title>', text_bulk)
            if html_error_match:
                error_msg += f" HTML Title: {html_error_match.group(1)}"
            # Check if it's a login redirect
            if "Please log in" in text_bulk or "login" in text_bulk.lower():
                error_msg += " - Appears to be a login redirect."
            debug_log(f"Full HTML preview (first 1000 chars): {text_bulk[:1000]}")
            result = {}
            if debug:
                result["_debug"] = debug_info
                result["_error"] = error_msg
            return result
        
        if text_bulk.startswith("for (;;);"):
            text_bulk = text_bulk[len("for (;;);"):]
        
        try:
            j_bulk = json.loads(text_bulk)
        except json.JSONDecodeError as e:
            error_msg = f"JSON decode error: {e}, text: {text_bulk[:500]}"
            debug_log(error_msg)
            # Check if it's still HTML
            if text_bulk.strip().startswith("<!DOCTYPE") or text_bulk.strip().startswith("<html"):
                error_msg = f"Response is HTML, not JSON. Instagram may require authentication. Status: {resp_bulk.status_code}"
            result = {}
            if debug:
                result["_debug"] = debug_info
                result["_error"] = error_msg
            return result
        
        # Parse the response structure: payload.payloads[route_key].result.exports.rootView.props
        # The route_key might be /reel/{shortcode}/ or /{username}/reel/{shortcode}/
        payload = j_bulk.get("payload") or {}
        payloads = payload.get("payloads") or {}
        
        debug_log(f"📋 Full response payload keys: {list(payload.keys())}")
        debug_log(f"📋 Payloads keys: {list(payloads.keys())}")
        
        # Try exact match first
        route_obj = payloads.get(route_path) or {}
        
        # If not found, try any key that contains the shortcode (in case username was added)
        found_route_key = route_path
        if not route_obj:
            for key in payloads.keys():
                if shortcode in key and ("reel" in key or "post" in key):
                    route_obj = payloads.get(key) or {}
                    found_route_key = key
                    debug_log(f"Found route key: {key} (was looking for: {route_path})")
                    break
        else:
            debug_log(f"Using exact route key match: {route_path}")
        
        # Check for errors in the response first
        if route_obj.get("error"):
            error_value = route_obj.get("error")
            error_msg = f"Bulk route returned error: {error_value}"
            debug_log(error_msg)
            # Also log the full route_obj to see what we're getting
            debug_log(f"Full route_obj: {route_obj}")
            result = {}
            if debug:
                result["_debug"] = debug_info
                result["_error"] = error_msg
            return result
        
        # Handle both possible structures - try multiple paths
        result = route_obj.get("result") or {}
        
        # Path 0: Try route_obj directly (data might be at top level)
        media_id = route_obj.get("media_id")
        owner_id = route_obj.get("owner_id")
        
        # Path 1: result.exports.rootView.props
        exports = result.get("exports") or {}
        root_view = exports.get("rootView") or {}
        props = root_view.get("props") or {}
        
        if not media_id:
            media_id = props.get("media_id")
        if not owner_id:
            owner_id = props.get("owner_id")
        
        # Path 2: Try direct result.props if Path 1 didn't work
        if not media_id or not owner_id:
            props_direct = result.get("props") or {}
            if not media_id:
                media_id = props_direct.get("media_id")
            if not owner_id:
                owner_id = props_direct.get("owner_id")
        
        # Path 3: Try result.rootView.props (without exports)
        if not media_id or not owner_id:
            root_view_direct = result.get("rootView") or {}
            props_root = root_view_direct.get("props") or {}
            if not media_id:
                media_id = props_root.get("media_id")
            if not owner_id:
                owner_id = props_root.get("owner_id")
        
        debug_log(f"Bulk route response - media_id: {media_id}, owner_id: {owner_id}")
        debug_log(f"Route path used: {route_path}")
        debug_log(f"Found route key: {found_route_key}")
        debug_log(f"Available payload keys: {list(payloads.keys())}")
        debug_log(f"Route_obj keys: {list(route_obj.keys())}")
        # Log the actual error value if it exists
        if "error" in route_obj:
            debug_log(f"⚠️ Route_obj error field value: {repr(route_obj.get('error'))}")
            debug_log(f"⚠️ Full route_obj structure: {json.dumps(route_obj, indent=2)[:1000]}")
        debug_log(f"Result keys: {list(result.keys())}")
        if exports:
            debug_log(f"Exports keys: {list(exports.keys())}")
        if root_view:
            debug_log(f"RootView keys: {list(root_view.keys())}")
        if props:
            debug_log(f"Props keys: {list(props.keys())}")
        
        if not media_id or not owner_id:
            # Try alternative parsing paths - regex fallback
            import re
            text_for_regex = text_bulk
            # Try multiple regex patterns
            patterns_media = [
                r'"media_id"\s*:\s*"?(\d+)"?',
                r'"media_id"\s*:\s*(\d+)',
                r'media_id["\']?\s*[:=]\s*["\']?(\d+)',
                r'(\d{15,})',  # media_ids are typically long numbers
            ]
            patterns_owner = [
                r'"owner_id"\s*:\s*"?(\d+)"?',
                r'"owner_id"\s*:\s*(\d+)',
                r'owner_id["\']?\s*[:=]\s*["\']?(\d+)',
            ]
            
            for pattern in patterns_media:
                m_media = re.search(pattern, text_for_regex)
                if m_media:
                    candidate = m_media.group(1)
                    # Validate it's a reasonable length (media_ids are usually 10-20 digits)
                    if len(candidate) >= 10 and len(candidate) <= 20:
                        media_id = candidate
                        debug_log(f"Found media_id via regex pattern '{pattern}': {media_id}")
                        break
            
            for pattern in patterns_owner:
                m_owner = re.search(pattern, text_for_regex)
                if m_owner:
                    candidate = m_owner.group(1)
                    if len(candidate) >= 8 and len(candidate) <= 15:
                        owner_id = candidate
                        debug_log(f"Found owner_id via regex pattern '{pattern}': {owner_id}")
                        break
            
            debug_log(f"After regex fallback - media_id: {media_id}, owner_id: {owner_id}")
            
            # If still no media_id after regex, try oEmbed as last fallback
            if not media_id:
                debug_log("Trying oEmbed as fallback to get media_id")
                media_id_oembed = fetch_media_id_via_oembed(shortcode, cookie_header if cookie_header else "")
                if media_id_oembed:
                    media_id = media_id_oembed
                    debug_log(f"Found media_id via oEmbed: {media_id}")
            
            if not media_id or not owner_id:
                error_msg = f"Failed to extract media_id or owner_id from bulk route response. Route key found: {found_route_key}, Route obj empty: {not route_obj}"
                debug_log(error_msg)
                # Still return media_id if we found it, even without owner_id (though GraphQL won't work)
                result = {}
                if media_id:
                    result["media_id"] = str(media_id)
                if debug:
                    result["_debug"] = debug_info
                    result["_error"] = error_msg
                return result
        
        media_id_str = str(media_id)
        owner_id = str(owner_id)
        
        debug_log(f"Extracted - media_id: {media_id_str}, owner_id: {owner_id}")
        
        # Step 2: Call GraphQL endpoint to get user's reels
        # Fetch CSRF token if needed
        csrf_token = None
        if cookie_header:
            def _extract_cookie_value(cookie_str: str, key: str) -> Optional[str]:
                try:
                    parts = [p.strip() for p in cookie_str.split(';')]
                    for p in parts:
                        if p.startswith(key + "="):
                            return p.split('=', 1)[1]
                except Exception:
                    return None
                return None
            csrf_token = _extract_cookie_value(cookie_header, "csrftoken")
        
        if not csrf_token:
            csrf_token = fetch_csrf_token_from_homepage()
        
        headers_graphql = {
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9",
            "priority": "u=1, i",
            "referer": f"https://www.instagram.com/reel/{shortcode}/",
            "sec-ch-prefers-color-scheme": "dark",
            "sec-ch-ua": '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
            "x-asbd-id": "359341",
            "x-ig-app-id": "936619743392459",
            "x-ig-www-claim": "0",
            "x-requested-with": "XMLHttpRequest",
        }
        
        if cookie_header:
            headers_graphql["cookie"] = cookie_header
        
        if csrf_token:
            headers_graphql["x-csrftoken"] = csrf_token
        
        # GraphQL query - doc_id 7950326061742207 for user timeline media
        graphql_vars = {
            "id": owner_id,
            "include_clips_attribution_info": False,
            "first": 50,  # Fetch first 50 reels to increase chances of finding the target
        }
        
        debug_log(f"GraphQL query vars: {graphql_vars}")
        
        graphql_url = f"https://www.instagram.com/graphql/query/?doc_id=7950326061742207&variables={urllib.parse.quote(json.dumps(graphql_vars))}"
        
        resp_graphql = get_shared_session().get(
            graphql_url,
            headers=headers_graphql,
            timeout=20,
        )
        
        if not resp_graphql.ok:
            error_msg = f"GraphQL request failed: {resp_graphql.status_code} - {resp_graphql.text[:200]}"
            debug_log(error_msg)
            result = {}
            if debug:
                result["_debug"] = debug_info
                result["_error"] = error_msg
            return result
        
        try:
            j_graphql = resp_graphql.json()
        except json.JSONDecodeError as e:
            error_msg = f"GraphQL JSON decode error: {e}, text: {resp_graphql.text[:500]}"
            debug_log(error_msg)
            result = {}
            if debug:
                result["_debug"] = debug_info
                result["_error"] = error_msg
            return result
        
        # Check for GraphQL errors
        if j_graphql.get("errors"):
            error_msg = f"GraphQL errors: {j_graphql.get('errors')}"
            debug_log(error_msg)
            result = {}
            if debug:
                result["_debug"] = debug_info
                result["_error"] = error_msg
            return result
        
        # Step 3: Match media_id in GraphQL response
        user_data = (j_graphql.get("data") or {}).get("user") or {}
        
        if not user_data:
            error_msg = "GraphQL response missing user data"
            debug_log(error_msg)
            debug_log(f"GraphQL response keys: {list(j_graphql.keys())}")
            result = {}
            if debug:
                result["_debug"] = debug_info
                result["_error"] = error_msg
            return result
        edges = (((user_data.get("edge_owner_to_timeline_media") or {}).get("edges") or []))
        
        debug_log(f"GraphQL response - found {len(edges)} edges")
        if edges:
            debug_log(f"First edge node id: {edges[0].get('node', {}).get('id')}")
        debug_log(f"Looking for media_id: {media_id_str}")
        
        for edge in edges:
            node = edge.get("node") or {}
            node_id = str(node.get("id") or "")
            # Match by media_id (exact match)
            if node_id == media_id_str:
                debug_log(f"Matched node! video_view_count: {node.get('video_view_count')}")
                # Extract stats from GraphQL for likes/comments
                like_count = ((node.get("edge_media_preview_like") or {}).get("count") or 0)
                comment_count = ((node.get("edge_media_to_comment") or {}).get("count") or 0)
                taken_at = node.get("taken_at_timestamp")
                shortcode_found = node.get("shortcode")
                caption_edge = (node.get("edge_media_to_caption") or {}).get("edges") or []
                caption_text = ""
                if caption_edge:
                    caption_text = (caption_edge[0].get("node") or {}).get("text") or ""
                
                posted_on = None
                try:
                    if taken_at:
                        posted_on = datetime.fromtimestamp(int(taken_at), timezone.utc).strftime("%Y-%m-%d")
                except Exception:
                    pass
                
                # Fetch view_count from media API instead of GraphQL
                video_view_count = None
                try:
                    if cookie_header:
                        # Use media API to fetch view count
                        media_url = f"https://www.instagram.com/api/v1/media/{media_id_str}/info/"
                        def _extract_cookie_value(cookie_str: str, key: str) -> Optional[str]:
                            try:
                                parts = [p.strip() for p in cookie_str.split(';')]
                                for p in parts:
                                    if p.startswith(key + "="):
                                        return p.split('=', 1)[1]
                            except Exception:
                                return None
                            return None
                        
                        csrf = _extract_cookie_value(cookie_header, "csrftoken")
                        media_headers = {
                            "accept": "*/*",
                            "user-agent": "Mozilla/5.0",
                            "x-ig-app-id": "936619743392459",
                            "x-requested-with": "XMLHttpRequest",
                            "cookie": cookie_header,
                            "referer": f"https://www.instagram.com/reel/{shortcode_found or shortcode}/",
                        }
                        if csrf:
                            media_headers["x-csrftoken"] = csrf
                        
                        resp_media = requests.get(media_url, headers=media_headers, timeout=20)
                        if resp_media.ok:
                            media_data = resp_media.json()
                            media_item = (media_data.get("items") or [None])[0] or media_data
                            video_view_count = (
                                media_item.get("play_count") 
                                or media_item.get("video_play_count") 
                                or media_item.get("view_count") 
                                or media_item.get("video_view_count")
                            )
                            debug_log(f"Fetched video_view_count from media API: {video_view_count}")
                except Exception as e:
                    debug_log(f"Failed to fetch view_count from media API: {type(e).__name__}: {e}")
                    # Fall back to GraphQL value if media API fails
                    video_view_count = node.get("video_view_count")
                
                result = {
                    "play_count": video_view_count,
                    "video_view_count": video_view_count,
                    "like_count": like_count,
                    "comment_count": comment_count,
                    "shortcode": shortcode_found or shortcode,
                    "posted_on": posted_on,
                    "caption": caption_text,
                    "product_type": node.get("product_type"),
                    "media_type": "GraphVideo" if node.get("__typename") == "GraphVideo" else "unknown",
                    "media_id": media_id_str,  # Include media_id in result
                }
                if debug:
                    result["_debug"] = debug_info
                return result
        
        # Not found in first page - media_id exists but not in first 50 results
        # Could implement pagination here if needed
        error_msg = f"Media ID {media_id_str} not found in GraphQL response (checked {len(edges)} edges)"
        debug_log(error_msg)
        # Show first few node IDs for debugging
        for i, edge in enumerate(edges[:5]):
            debug_log(f"  Edge {i}: node id = {edge.get('node', {}).get('id')}")
        
        result = {"media_id": media_id_str}  # Still return media_id even if not found in GraphQL
        if debug:
            result["_debug"] = debug_info
            result["_error"] = error_msg
        return result
        
    except Exception as e:
        # Log error if debug is enabled
        import traceback
        error_msg = f"Exception in fetch_reel_stats_via_graphql: {type(e).__name__}: {e}"
        debug_log(error_msg)
        if debug:
            debug_log(traceback.format_exc())
        result = {}
        if debug:
            result["_debug"] = debug_info
            result["_error"] = error_msg
        return result

# ----------------------------
# Bulk-route: get media_id for a shortcode only
# ----------------------------
def fetch_media_id_via_bulk_route(
    shortcode: str,
    cookie_header: str,
) -> Optional[str]:
    headers = {
        "accept": "*/*",
        "content-type": "application/x-www-form-urlencoded",
        "origin": "https://www.instagram.com",
        "referer": f"https://www.instagram.com/reel/{shortcode}/",
        "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
        "x-ig-d": "www",
        "cookie": cookie_header,
    }

    data = {
        "route_urls[0]": f"/reel/{shortcode}/",
        "routing_namespace": "igx_www$a$87a091182d5bd65bcb043a2888004e09",
        "__d": "www",
        "__user": "0",
        "__a": "1",
        "__req": "5",
        "__hs": "20389.HYP:instagram_web_pkg.2.1...0",
        "dpr": "2",
        "__ccg": "EXCELLENT",
        "__rev": "1029033903",
        "__s": "ezt6se:a7g158:kwenji",
        "__hsi": "7566283129723658537",
        "__dyn": "7xeUjG1mxu1syUbFp41twpUnwgU7SbzEdF8aUco2qwJxS0k24o0B-q1ew6ywaq0yE462mcw5Mx62G5UswoEcE7O2l0Fwqo31w9O1lwxwQzXwae4UaEW2G0AEco5G0zK5o4q3y1Sw62wLyES1TwTU9UaQ0Lo6-3u2WE5B08-269wr86C1mgcEed6goK10xKi2qi7E5y4UrwHwrE5SbBK4o11o5O3a13AwhES5E",
        "__csr": "gB0Bgz3fMKzEBdb9R8JqkB8DQHbAlliaj8QmqVtmAKl9eXDBy9GK8hohAGrzF-pkBhVAA9Gl6Byena8FnJ4Kp6KaByUGr_nV9ki2-9WCypfBxJ1bK9BAUPypEix6pzoZaaz9WBz-5WCWG58GAaDUGLyH-4UK9GqtqAy9QiFay8OGz8y7C544VAvDyoWaz8Cm00miGlQ26U2PwyyEpxC0deyC0Pz2Fp4hw7xwfS1Hg6q0tC0lu0qe0Pe0eJU1SEKp0bO9yUmypRe2-1nDwXx2eByVA0EoaodA0pxo0BcM1t183Yw8ZBy4bCwtC0fpaEji8m82OwaO0JHw0op80lDwadw1u-6U095o-",
        "__hsdp": "kwes4ImAMhN54mgwakA2eiKLAjigb6ex15Wcc8tojK0jxwiVHxq11KkwaA0xpBgC32E4Jjw5fwu8y0Loowk8cEbAq4k8KEqw-wMxamaxeeyo5p0OAw53g1PU3tAwXw4iw6Awe-9wj86Pw5Qwa61Yw59wbV0b6awdNK48108iw",
        "__hblp": "0v83fwsUiw67xmaCwioswIobHx2689oGui2u8G1pwJwHxW1eU9888eFU5u68y0KGzoG8wGxO3aEC256y8x2bG6EfEc8iByEjGbw9ii9gkw4zgeo3swEBwn8b88o4u1PAwXw4iwtE3Rxi2a1hwuE8ECm3CcwmUgU1t82xwv81e8gg2Zg4e7o4-9g3lCrCyoC3m4k1_xq5EiwDwb2dwTw",
        "__sjsp": "kwes4ImX5gN4khp20Fig8VaWKhd90IoW44nEMMwzxeU1G8",
        "__comet_req": "7",
        "fb_dtsg": "NAfuNym12kUVPqfvEVxR2-bQyfeL7ClRbXzC9knthJ9kZh4Y1QyfJ_g:17864970403026470:1755093855",
        "jazoest": "26398",
        "lsd": "deB8mbiuiMC0WXGahZkLEm",
        "__spin_r": "1029033903",
        "__spin_b": "trunk",
        "__spin_t": "1761662571",
        "__crn": "comet.igweb.PolarisPostRouteNext",
    }

    resp = get_shared_session().post(
        "https://www.instagram.com/ajax/bulk-route-definitions/",
        headers=headers,
        data=data,
        timeout=20,
    )
    resp.raise_for_status()
    text = resp.text
    # Strip for(;;); prefix if present
    if text.startswith("for (;;);"):
        text = text[len("for (;;);"):]
    j = json.loads(text)
    # Attempt to locate media_id in payload for the given route
    route_key = f"/reel/{shortcode}/"
    payloads = (((j or {}).get("payload") or {}).get("payloads") or {})
    route_obj = (payloads.get(route_key) or {}).get("result") or {}
    # Fast path
    media_id = (((route_obj.get("exports") or {}).get("rootView") or {}).get("props") or {}).get("media_id")
    if media_id:
        return str(media_id)
    # Fallback: regex scan
    import re
    m = re.search(r"\"media_id\"\s*:\s*\"(\d+)\"", text)
    return m.group(1) if m else None

# ----------------------------
# Data Fetching (cached) via Instagram Web API
# ----------------------------
@st.cache_data(ttl=600, show_spinner=False)
def fetch_user_id_public(username: str) -> Optional[str]:
    url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
    headers = {
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        "x-ig-app-id": "936619743392459",
        "x-ig-www-claim": "0",
        "x-requested-with": "XMLHttpRequest",
        "referer": f"https://www.instagram.com/{username}/",
        "origin": "https://www.instagram.com",
    }
    resp = get_shared_session().get(url, headers=headers, timeout=20)
    if not resp.ok:
        return None
    try:
        data = resp.json()
        user_id = (((data or {}).get("data") or {}).get("user") or {}).get("id")
        return user_id
    except Exception:
        return None

@st.cache_data(ttl=600, show_spinner=False)
def fetch_profile_details(username: str) -> Dict[str, Any]:
    """Fetch full profile details including picture, followers, following, and bio."""
    url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
    headers = {
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        "x-ig-app-id": "936619743392459",
        "x-ig-www-claim": "0",
        "x-requested-with": "XMLHttpRequest",
        "referer": f"https://www.instagram.com/{username}/",
        "origin": "https://www.instagram.com",
    }
    resp = get_shared_session().get(url, headers=headers, timeout=20)
    if not resp.ok:
        return {}
    try:
        data = resp.json()
        user_data = (((data or {}).get("data") or {}).get("user") or {})
        # Try multiple possible field names for profile picture
        pic_url = (user_data.get("profile_pic_url_hd") 
                  or user_data.get("profile_pic_url") 
                  or user_data.get("profile_pic_url_hd_2") 
                  or user_data.get("profile_pic_url_hd_url"))
        return {
            "profile_pic_url": pic_url,
            "followers": user_data.get("edge_followed_by", {}).get("count", 0),
            "following": user_data.get("edge_follow", {}).get("count", 0),
            "bio": user_data.get("biography", ""),
            "full_name": user_data.get("full_name", ""),
        }
    except Exception:
        return {}

@st.cache_data(ttl=300, show_spinner=False)
def fetch_profile_media_count(username: str) -> Optional[int]:
    """Get total media count from web_profile_info (overall posts)."""
    url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
    headers = {
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        "x-ig-app-id": "936619743392459",
        "x-ig-www-claim": "0",
        "x-requested-with": "XMLHttpRequest",
        "referer": f"https://www.instagram.com/{username}/",
        "origin": "https://www.instagram.com",
    }
    # Use a fresh session to avoid stale state
    fresh_session = requests.Session()
    resp = fresh_session.get(url, headers=headers, timeout=20)
    if not resp.ok:
        return None
    try:
        data = resp.json()
        return ((((data or {}).get("data") or {}).get("user") or {}).get("edge_owner_to_timeline_media") or {}).get("count")
    except Exception:
        return None

def reels_to_dataframe(items: List[Dict[str, Any]]) -> pd.DataFrame:
    if not items:
        return pd.DataFrame(
            columns=["Reel Link", "Posted On", "Caption", "Media Type", "Total Views", "Total Likes", "Total Comments"]
        )

    rows = []
    for it in items:
        # Create full reel link
        shortcode = it.get("shortcode", "")
        reel_link = f"https://www.instagram.com/reel/{shortcode}/" if shortcode else ""
        
        rows.append(
            {
                "Reel Link": reel_link,
                "Posted On": to_yyyymmdd(it["taken_at_timestamp"]),
                "Caption": it.get("caption", ""),
                "Media Type": it.get("product_type", "reel"),
                "Total Views": it.get("video_view_count", 0),
                "Total Likes": it["likes"],
                "Total Comments": it["comments"],
                "_sort_ts": it["taken_at_timestamp"].timestamp(),
            }
        )

    df = pd.DataFrame(rows)
    df = df.sort_values(by="_sort_ts", ascending=False).drop(columns=["_sort_ts"]).reset_index(drop=True)

    df_display = df.copy()
    df_display["Total Likes"] = df_display["Total Likes"].apply(format_count)
    df_display["Total Comments"] = df_display["Total Comments"].apply(format_count)
    # Do NOT format Total Views; show full exact number

    return df_display

# ----------------------------
# Bulk resolve many shortcodes → media_id map
# ----------------------------
def bulk_fetch_media_ids(shortcodes: List[str], cookie_header: str, batch_size: int = 20) -> Dict[str, Optional[str]]:
    result: Dict[str, Optional[str]] = {sc: None for sc in shortcodes}
    if not shortcodes:
        return result
    sess = get_shared_session()
    for i in range(0, len(shortcodes), batch_size):
        chunk = shortcodes[i : i + batch_size]
        headers = {
            "accept": "*/*",
            "content-type": "application/x-www-form-urlencoded",
            "origin": "https://www.instagram.com",
            "referer": f"https://www.instagram.com/reel/{chunk[0]}/",
            "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
            "x-ig-d": "www",
            "cookie": cookie_header,
        }
        data = {
            "routing_namespace": "igx_www$a$87a091182d5bd65bcb043a2888004e09",
            "__d": "www",
            "__a": "1",
            "dpr": "2",
        }
        for idx, sc in enumerate(chunk):
            # sanitize again defensively
            try:
                import re as _re
                sc = _re.sub(r"[^A-Za-z0-9_]", "", sc or "")
            except Exception:
                pass
            data[f"route_urls[{idx}]"] = f"/reel/{sc}/"
        try:
            resp = sess.post("https://www.instagram.com/ajax/bulk-route-definitions/", headers=headers, data=data, timeout=20)
            if not resp.ok:
                continue
            text = resp.text
            if text.startswith("for (;;);"):
                text = text[len("for (;;);"):]
            j = json.loads(text)
            payloads = (((j or {}).get("payload") or {}).get("payloads") or {})
            for sc in chunk:
                route_key = f"/reel/{sc}/"
                route_obj = (payloads.get(route_key) or {}).get("result") or {}
                media_id = (((route_obj.get("exports") or {}).get("rootView") or {}).get("props") or {}).get("media_id")
                if not media_id:
                    import re as _re
                    m = _re.search(r"\"media_id\"\s*:\s*\"(\d+)\"", json.dumps(route_obj))
                    media_id = m.group(1) if m else None
                result[sc] = str(media_id) if media_id else None
        except Exception:
            pass
    return result

# Robust single resolver: shortcode → media_id with fallbacks
def resolve_media_id_with_fallback(shortcode: str, cookie_header: str) -> Optional[str]:
    # Try bulk-route single
    try:
        mid = fetch_media_id_via_bulk_route(shortcode, cookie_header)
        if mid:
            return mid
    except Exception:
        pass
    # Try shortcode info endpoint and parse id/pk
    try:
        item = resolve_media_by_shortcode(shortcode, cookie_header)
        if not item:
            return None
        mid = item.get("id") or item.get("pk")
        if mid:
            # item.get("id") can be of form "<pk>_<owner>"; extract pk if needed
            try:
                return str(mid).split("_")[0]
            except Exception:
                return str(mid)
    except Exception:
        pass
    # Try oEmbed
    mid = fetch_media_id_via_oembed(shortcode, cookie_header)
    if mid:
        return mid
    # Try parsing the HTML page
    mid = fetch_media_id_from_html(shortcode, cookie_header)
    if mid:
        return mid
    return None

# Extract stats from a media item payload as fallback
def parse_stats_from_item(item: Dict[str, Any]) -> Dict[str, Any]:
    if not item:
        return {}
    ts = item.get("taken_at_timestamp") or item.get("taken_at")
    try:
        posted_on = datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m-%d") if ts else None
    except Exception:
        posted_on = None
    
    # Try all possible field names for play_count
    play_count = (
        item.get("play_count")
        or item.get("video_play_count")
        or item.get("view_count")
        or item.get("video_view_count")
        or item.get("views")
    )
    
    return {
        "play_count": play_count,
        "like_count": item.get("like_count") or (item.get("edge_liked_by") or {}).get("count") or item.get("likes"),
        "comment_count": item.get("comment_count") or (item.get("edge_media_to_comment") or {}).get("count") or item.get("comments"),
        "shortcode": item.get("code") or item.get("shortcode"),
        "posted_on": posted_on,
        "product_type": item.get("product_type"),
        "media_type": item.get("media_type"),
    }

# ----------------------------
# Extra media_id fallbacks: oEmbed and HTML page parse
# ----------------------------
def fetch_media_id_via_oembed(shortcode: str, cookie_header: str) -> Optional[str]:
    try:
        url = f"https://www.instagram.com/oembed/?url=https://www.instagram.com/reel/{shortcode}/"
        headers = {
            "accept": "*/*",
            "user-agent": "Mozilla/5.0",
            "cookie": cookie_header,
        }
        resp = get_shared_session().get(url, headers=headers, timeout=20)
        if not resp.ok:
            return None
        j = resp.json()
        media_id = j.get("media_id") or j.get("id")
        if media_id:
            try:
                return str(media_id).split("_")[0]
            except Exception:
                return str(media_id)
        return None
    except Exception:
        return None

def fetch_media_id_from_html(shortcode: str, cookie_header: str) -> Optional[str]:
    try:
        url = f"https://www.instagram.com/reel/{shortcode}/"
        headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "user-agent": "Mozilla/5.0",
            "cookie": cookie_header,
            "referer": f"https://www.instagram.com/reel/{shortcode}/",
        }
        resp = get_shared_session().get(url, headers=headers, timeout=20)
        if not resp.ok:
            # try /p/ variant
            headers["referer"] = f"https://www.instagram.com/p/{shortcode}/"
            resp = get_shared_session().get(f"https://www.instagram.com/p/{shortcode}/", headers=headers, timeout=20)
            if not resp.ok:
                return None
        text = resp.text or ""
        import re as _re
        # Try media_id first
        m = _re.search(r'"media_id"\s*:\s*"(\d+)"', text)
        if m:
            return m.group(1)
        # Try id of form 1234_5678
        m2 = _re.search(r'"id"\s*:\s*"(\d+)_\d+"', text)
        if m2:
            return m2.group(1)
        return None
    except Exception:
        return None


# ----------------------------
# Shared Inputs (global across tabs)
# ----------------------------
cookie_header_global_raw = st.text_area(
    "Cookie header for Instagram web API (optional for profile; recommended for real-time data)",
    value="",
    placeholder="sessionid=...; csrftoken=...; ds_user_id=...; ...",
    help="Open DevTools → Network on instagram.com, select any XHR, and copy the full Cookie header. Note: Without cookies, Instagram returns cached data (may be hours old). With cookies, you get real-time data.",
)
cookie_header_global = cookie_header_global_raw.strip() if cookie_header_global_raw else ""


# Keep session state
if "last_username" not in st.session_state:
    st.session_state["last_username"] = ""
if "caption_cache" not in st.session_state:
    st.session_state["caption_cache"] = {}
if "show_captions" not in st.session_state:
    st.session_state["show_captions"] = False
if "profile_user_id" not in st.session_state:
    st.session_state["profile_user_id"] = None
if "profile_username_current" not in st.session_state:
    st.session_state["profile_username_current"] = None
if "profile_media_count" not in st.session_state:
    st.session_state["profile_media_count"] = None

def clear_cache_for_username(u: str):
    fetch_user_id_public.clear()

def validate_username(u: str) -> Optional[str]:
    if not u:
        return "Please enter a username."
    if u.startswith("@"):
        return "Do not include @ in the username."
    if " " in u:
        return "Username should not contain spaces."
    return None

st.markdown("<div class='card'>", unsafe_allow_html=True)

# ----------------------------
# Tabs
# ----------------------------
tab_profile, tab_reels = st.tabs(["Analyze Profile", "Analyze Reels"])

with tab_profile:
    st.subheader("Analyze Profile")
    # Hide diagnostics in production (safe even if no secrets)
    def _is_prod() -> bool:
        env_from_os = (os.getenv("ENV") or os.getenv("STREAMLIT_ENV") or "").lower()
        if env_from_os == "prod":
            return True
        try:
            env_from_secrets = str(getattr(st, "secrets", {}).get("ENV", "")).lower()
        except Exception:
            env_from_secrets = ""
        return env_from_secrets == "prod"
    IS_PROD = _is_prod()
    show_diag_profile = False  # Disabled
    fetch_captions_profile = False  # Disabled
    
    col1, col2 = st.columns([3, 1])
    with col1:
        username_input = st.text_input(
            "Enter Instagram Username or URL",
            value="",
            placeholder="natgeo or https://www.instagram.com/natgeo/",
            key="profile_username",
        ).strip()
    with col2:
        fetch_clicked = st.button("Fetch", type="primary", key="profile_fetch")
        clear_clicked = st.button("Clear", key="profile_clear")

    if clear_clicked:
        # Avoid modifying widget key post-instantiation; just rerun
        st.session_state.pop("last_username", None)
        st.session_state.pop("caption_cache", None)
        st.session_state.pop("show_captions", None)
        st.session_state["profile_user_id"] = None
        st.session_state["profile_username_current"] = None
        st.session_state["profile_media_count"] = None
        st.rerun()

    def extract_username_from_input(input_text: str) -> Optional[str]:
        """Extract username from Instagram URL or return as-is if already a username"""
        if not input_text:
            return None
        
        # If it's already a username (no slashes, no @)
        if "/" not in input_text and not input_text.startswith("@"):
            return input_text.strip()
        
        # If it starts with @, remove it
        if input_text.startswith("@"):
            return input_text[1:].strip()
        
        # Extract from Instagram URL
        import re
        patterns = [
            r"instagram\.com/([^/?]+)/?",
            r"instagram\.com/([^/?]+)\?",
            r"instagram\.com/([^/?]+)$"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, input_text)
            if match:
                username = match.group(1)
                # Remove any trailing slashes or query params
                username = username.split('/')[0].split('?')[0]
                return username
        
        # If no pattern matches, return as-is (might be a username)
        return input_text.strip()

    username_to_use = None
    if fetch_clicked:
        username_to_use = extract_username_from_input(username_input)
        # Fetch and display IP address
        try:
            ip_info_resp = requests.get("https://api.ipify.org?format=json", timeout=5)
            if ip_info_resp.ok:
                ip_data = ip_info_resp.json()
                st.info(f"🌐 Your IP: {ip_data.get('ip', 'Unknown')}")
        except:
            pass
    
    # no refresh button; cache clears automatically on Clear

    if username_to_use and fetch_clicked:
        error_msg = validate_username(username_to_use)
        if error_msg:
            st.error(error_msg)
        else:
            with st.spinner("Fetching profile info..."):
                try:
                    # If same username is already loaded, reuse user_id; else fetch (no cookies required)
                    if st.session_state.get("profile_username_current") == username_to_use and st.session_state.get("profile_user_id"):
                        user_id = st.session_state["profile_user_id"]
                    else:
                        user_id = fetch_user_id_public(username_to_use)
                        if not user_id:
                            # Check response details if available for better error messages
                            st.error(f"Profile @{username_to_use} not found, may be private, or Instagram blocked the request. Some profiles may require authentication even if they appear public.")
                            if show_diag_profile:
                                st.warning(f"Debug: user_id fetch returned None. Try checking the username or network tab.")
                        else:
                            st.session_state["profile_user_id"] = user_id
                            st.session_state["profile_username_current"] = username_to_use
                            st.session_state["profile_media_count"] = fetch_profile_media_count(username_to_use)
                            # Fetch full profile details
                            profile_details = fetch_profile_details(username_to_use)
                            st.session_state["profile_details"] = profile_details
                            st.success(f"Loaded profile @{username_to_use}")

                except PermissionError as pe:
                    st.error(str(pe))
                except ConnectionError:
                    st.error("Too many requests. Try again later.")
                except requests.HTTPError as e:
                    status = getattr(e.response, "status_code", "?")
                    body = (e.response.text[:300] + "...") if getattr(e, "response", None) and e.response.text else ""
                    st.error(f"HTTP {status}. {body}")
                except Exception as e:
                    st.error(f"An unexpected error occurred. {type(e).__name__}: {e}")

    # If a profile is loaded, show count, fetch size and Process
    if st.session_state.get("profile_user_id") and st.session_state.get("profile_username_current"):
        # Display profile info card
        profile_details = st.session_state.get("profile_details", {})
        if profile_details:
            st.markdown("### Profile Info")
            username_display = st.session_state.get("profile_username_current", "")
            full_name = profile_details.get("full_name", "")
            st.markdown(f"**{full_name if full_name else username_display}**")
            st.markdown(f"@{username_display}")
            
            stats_col1, stats_col2, stats_col3 = st.columns(3)
            with stats_col1:
                st.metric("Followers", f"{profile_details.get('followers', 0):,}")
            with stats_col2:
                st.metric("Following", f"{profile_details.get('following', 0):,}")
            with stats_col3:
                media_count = st.session_state.get("profile_media_count", 0)
                st.metric("Posts", f"{media_count:,}" if media_count else "0")
            
            bio = profile_details.get("bio", "")
            if bio:
                st.markdown(f"📝 {bio}")
        
        st.markdown("---")
        
        default_count = 5
        max_fetch = st.number_input(
            "How many media to fetch?",
            min_value=1,
            max_value=50,
            value=default_count,
            step=1,
            key="profile_fetch_count",
        )
        st.write("")
        do_process = st.button("Process", type="primary", key="profile_process")
        if do_process:
            try:
                username_proc = st.session_state["profile_username_current"]
                user_id_proc = st.session_state["profile_user_id"]
                
                # Note about data freshness
                if not cookie_header_global:
                    st.info("ℹ️ **Note:** Without cookies, Instagram returns cached data (may be up to a few hours old). For real-time data, provide your Instagram session cookie above.")
                
                # Add timestamp to prevent any caching
                import time as time_module
                cache_buster = str(time_module.time())
                
                resp = fetch_profile_reels_public(
                    target_user_id=user_id_proc,
                    page_size=int(max_fetch),
                    referer=f"https://www.instagram.com/{username_proc}/",
                    cookie_header=cookie_header_global if cookie_header_global else None,
                    _cache_buster=cache_buster,
                )

                items: List[Dict[str, Any]] = []
                # Handle response structure - could be direct items array or nested
                resp_items = resp.get("items") or []
                if not resp_items and isinstance(resp, dict):
                    # Sometimes the response structure is different
                    resp_items = resp.get("data", {}).get("items") or []
                
                # Debug removed per user request
                
                for it in resp_items[: int(max_fetch)]:
                    media = (it or {}).get("media") or it or {}
                    shortcode = media.get("code") or media.get("shortcode") or ""
                    media_pk = media.get("pk") or media.get("id") or ""
                    
                    # Try multiple possible field names for counts
                    like_count = (
                        media.get("like_count") 
                        or media.get("likes")
                        or ((media.get("edge_liked_by") or {}).get("count") or 0)
                    )
                    comment_count = (
                        media.get("comment_count")
                        or media.get("comments")
                        or ((media.get("edge_media_to_comment") or {}).get("count") or 0)
                    )
                    # Play count is the most important - check all possible fields
                    play_count = (
                        media.get("play_count")
                        or media.get("video_play_count")
                        or media.get("view_count")
                        or media.get("video_view_count")
                        or media.get("views")
                    )
                    ts = media.get("taken_at_timestamp") or media.get("taken_at")
                    taken_at = (
                        datetime.fromtimestamp(int(ts), timezone.utc) if ts else datetime.now(timezone.utc)
                    )
                    # Get caption from media - check multiple possible field structures
                    caption = ""
                    # Try edge_media_to_caption first (GraphQL structure)
                    if media.get("edge_media_to_caption"):
                        edges = media.get("edge_media_to_caption", {}).get("edges", [])
                        if edges and len(edges) > 0:
                            caption = edges[0].get("node", {}).get("text", "")
                    # If not found, try direct caption field
                    elif media.get("caption"):
                        if isinstance(media.get("caption"), str):
                            caption = media.get("caption")
                        elif isinstance(media.get("caption"), dict):
                            caption = media.get("caption", {}).get("text", "")
                    
                    items.append(
                            {
                                "shortcode": shortcode,
                                "media_pk": media_pk,
                                "owner_username": username_proc,
                            "likes": like_count or 0,
                            "comments": comment_count or 0,
                            "video_view_count": play_count or 0,
                                "taken_at_timestamp": taken_at,
                                "caption": caption,
                            }
                        )

                if not items:
                    st.warning("This profile has no Reels.")
                else:
                    st.success(f"Found {len(items)} Reels from @{username_proc}")

                    # Build table directly from public response (no cookies required)
                    rows: List[Dict[str, Any]] = []
                    table_ph = st.empty()
                    prog = st.progress(0)
                    total = len(items)
                    def _ensure_arrow_safe(df: pd.DataFrame) -> pd.DataFrame:
                        for col in ["Total Views", "Total Likes", "Total Comments"]:
                            if col in df.columns:
                                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype("int64")
                        return df

                    # Render incrementally

                    from concurrent.futures import ThreadPoolExecutor, as_completed
                    max_workers = min(8, max(2, len(items)))

                    def process_one(i: int) -> Dict[str, Any]:
                        it = items[i]
                        sc = it.get("shortcode") or ""
                        cap = it.get("caption", "")
                        return {
                            "Reel Link": f"https://www.instagram.com/reel/{sc}/" if sc else "",
                            "posted_on": it.get("taken_at_timestamp").strftime("%Y-%m-%d") if it.get("taken_at_timestamp") else "",
                            "caption": cap,
                            "media_type": "reel",
                            "Total Views": int(it.get("video_view_count") or 0),
                            "Total Likes": int(it.get("likes") or 0),
                            "Total Comments": int(it.get("comments") or 0),
                            "status": "ok",
                        }

                    completed = 0
                    rows_by_index: Dict[int, Dict[str, Any]] = {}
                    with ThreadPoolExecutor(max_workers=max_workers) as ex:
                        futures_map = {ex.submit(process_one, i): i for i in range(total)}
                        for fut in as_completed(futures_map):
                            idx = futures_map[fut]
                            try:
                                res = fut.result()
                            except Exception as e:
                                res = {
                                    "Reel Link": "",
                                    "posted_on": "",
                                    "caption": "",
                                    "media_type": "",
                                    "Total Views": 0,
                                    "Total Likes": 0,
                                    "Total Comments": 0,
                                    "status": f"error: {type(e).__name__}",
                                }
                            rows_by_index[idx] = res
                            completed += 1
                            if completed % 3 == 0 or completed == total:
                                try:
                                    ordered = [rows_by_index[i] for i in sorted(rows_by_index.keys())]
                                    df_inc = _ensure_arrow_safe(pd.DataFrame(ordered))
                                    table_ph.dataframe(df_inc, width="stretch", hide_index=True)
                                except Exception:
                                    pass
                                prog.progress(min(completed / total, 1.0))

                    if rows_by_index:
                        ordered = [rows_by_index[i] for i in sorted(rows_by_index.keys())]
                        df_final = _ensure_arrow_safe(pd.DataFrame(ordered))
                        table_ph.dataframe(df_final, width="stretch", hide_index=True)
                st.session_state["last_username"] = username_proc
            except PermissionError as pe:
                st.error(str(pe))
            except ConnectionError:
                st.error("Too many requests. Try again later.")
            except requests.HTTPError as e:
                status = getattr(e.response, "status_code", "?")
                body = (e.response.text[:300] + "...") if getattr(e, "response", None) and e.response.text else ""
                st.error(f"HTTP {status}. {body}")
            except Exception as e:
                st.error(f"An unexpected error occurred. {type(e).__name__}: {e}")

    st.markdown("<div class='small-tip'>Tip: switch tabs with Ctrl + Tab</div>", unsafe_allow_html=True)

with tab_reels:
    st.subheader("Analyze Reels")
    # Persisted results across reruns (until cleared)
    if "reels_csv_results" not in st.session_state:
        st.session_state["reels_csv_results"] = None
    if "reels_manual_results" not in st.session_state:
        st.session_state["reels_manual_results"] = None
    if "reels_csv_processing" not in st.session_state:
        st.session_state["reels_csv_processing"] = False
    if "reels_manual_processing" not in st.session_state:
        st.session_state["reels_manual_processing"] = False
    
    st.markdown("**Option 1: Bulk Upload (CSV)**")
    
    uploaded_file_bulk = st.file_uploader(
        "Choose a CSV file with reel links",
        type="csv",
        help="CSV should have a column with Instagram reel URLs (e.g., 'https://www.instagram.com/reel/ABC123/')",
        key="bulk_csv_uploader"
    )
    
    if uploaded_file_bulk is not None:
        try:
            # Read CSV
            df_uploaded_bulk = pd.read_csv(uploaded_file_bulk)
            st.success(f"✅ CSV uploaded successfully! Found {len(df_uploaded_bulk)} rows.")
            
            # Find the column with reel links
            reel_links_bulk = []
            for col in df_uploaded_bulk.columns:
                if df_uploaded_bulk[col].astype(str).str.contains('instagram.com/reel/', na=False).any():
                    reel_links_bulk = df_uploaded_bulk[col].dropna().tolist()
                    st.info(f"📊 Found reel links in column: '{col}'")
                    break
            
            if not reel_links_bulk:
                st.error("❌ No Instagram reel links found in the CSV. Please ensure your CSV contains URLs like 'https://www.instagram.com/reel/ABC123/'")
            else:
                st.write(f"🔗 Found {len(reel_links_bulk)} reel links...")
                if st.button("Process Bulk Upload", type="primary", key="bulk_upload_process"):
                    # Note about cookies
                    if not cookie_header_global:
                        st.warning("⚠️ **Note:** Cookie header is empty. Without cookies, Instagram returns cached data (may be hours old). For real-time data, provide your Instagram session cookie above.")
                    else:
                        st.info("✅ Using cookies - fetching real-time data.")
                    
                    rows_bulk: List[Dict[str, Any]] = []
                    table_ph_bulk = st.empty()
                    dl_ph_bulk = st.empty()
                    prog_bulk = st.progress(0)
                    total_bulk = len(reel_links_bulk)
                    
                    with st.spinner("Processing bulk upload..."):
                        def _ensure_arrow_safe_bulk(df: pd.DataFrame) -> pd.DataFrame:
                            for col in ["Total Views", "Total Likes", "Total Comments"]:
                                if col in df.columns:
                                    df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype("int64")
                            return df
                        
                        # Resolve IDs - try with cookies if available
                        shortcodes_bulk = [extract_shortcode(link) or link for link in reel_links_bulk]
                        id_map_bulk = {}
                        if cookie_header_global:
                            try:
                                id_map_bulk = bulk_fetch_media_ids(shortcodes_bulk, cookie_header_global)
                            except Exception:
                                id_map_bulk = {}
                        
                        from concurrent.futures import ThreadPoolExecutor, as_completed
                        max_workers = 8
                        def process_one_bulk(i: int) -> Dict[str, Any]:
                            link = reel_links_bulk[i]
                            sc = shortcodes_bulk[i]
                            media_id = id_map_bulk.get(sc)
                            
                            # Try to get media_id even without cookies
                            if not media_id:
                                if cookie_header_global:
                                    try:
                                        media_id = resolve_media_id_with_fallback(sc, cookie_header_global)
                                    except Exception:
                                        pass
                                if not media_id:
                                    try:
                                        item = resolve_media_by_shortcode(sc, cookie_header_global if cookie_header_global else "")
                                        if item:
                                            media_id = item.get("id") or item.get("pk")
                                            if media_id and isinstance(media_id, str) and "_" in media_id:
                                                media_id = media_id.split("_")[0]
                                    except Exception:
                                        pass
                            
                            ref = f"https://www.instagram.com/p/{sc}/"
                            stats = {}
                            
                            # Strategy 0: For unauthenticated requests, use NEW direct GraphQL method
                            if not cookie_header_global:
                                try:
                                    stats_graphql_result = fetch_reel_metrics_public(sc, max_retries=3)
                                    media_id_from_graphql = stats_graphql_result.get("media_id") if stats_graphql_result else None
                                    if media_id_from_graphql:
                                        media_id = media_id_from_graphql
                                    if stats_graphql_result and stats_graphql_result.get("play_count"):
                                        stats = {k: v for k, v in stats_graphql_result.items() if not k.startswith("_")}
                                    elif stats_graphql_result:
                                        stats = {k: v for k, v in stats_graphql_result.items() if not k.startswith("_")}
                                except Exception:
                                    pass
                            
                            # Strategy 0b: Fallback to OLD GraphQL method if NEW one failed
                            if (not stats or not stats.get("play_count")) and not cookie_header_global:
                                try:
                                    stats_graphql_old = fetch_reel_stats_via_graphql(sc, cookie_header="", debug=False)
                                    if stats_graphql_old and stats_graphql_old.get("play_count"):
                                        stats = {k: v for k, v in stats_graphql_old.items() if not k.startswith("_")}
                                    elif stats_graphql_old:
                                        stats_temp = {k: v for k, v in stats_graphql_old.items() if not k.startswith("_")}
                                        if not stats or len(stats_temp) > len(stats):
                                            stats = stats_temp
                                except Exception:
                                    pass
                            
                            # Strategy 1: Try fetching stats by pk
                            if media_id and cookie_header_global:
                                try:
                                    stats_new = fetch_media_stats_by_pk(media_id, cookie_header_global, referer_url=ref)
                                    if stats_new and stats_new.get("play_count"):
                                        stats = stats_new
                                except Exception:
                                    pass
                            
                            # Strategy 2: Try shortcode endpoint
                            if not stats or not stats.get("play_count"):
                                cookie_to_use = cookie_header_global if cookie_header_global else ""
                                try:
                                    item = resolve_media_by_shortcode(sc, cookie_to_use)
                                    if item:
                                        stats_from_shortcode = parse_stats_from_item(item)
                                        if stats_from_shortcode.get("play_count"):
                                            stats = stats_from_shortcode
                                except Exception:
                                    pass
                            
                            # Strategy 3: Try play_count with cookies
                            if (not stats or not stats.get("play_count")) and cookie_header_global:
                                try:
                                    play_count = fetch_play_count_with_cookies(f"https://www.instagram.com/reel/{sc}/", cookie_header_global)
                                    if play_count:
                                        stats = {"play_count": play_count, "shortcode": sc}
                                except Exception:
                                    pass
                            
                            # Strategy 4: GraphQL fallback
                            if not stats or not stats.get("play_count"):
                                try:
                                    stats_graphql = fetch_reel_stats_via_graphql(sc, cookie_header=cookie_header_global or "", debug=False)
                                    if stats_graphql and stats_graphql.get("play_count"):
                                        stats = {k: v for k, v in stats_graphql.items() if not k.startswith("_")}
                                except Exception:
                                    pass
                            
                            # Get media_id from stats or from earlier resolution
                            media_id_final = stats.get("media_id") or stats.get("id") if stats else media_id
                            
                            # Get play_count from stats
                            play_count = None
                            if stats:
                                play_count = (
                                    stats.get("play_count")
                                    or stats.get("video_play_count")
                                    or stats.get("view_count")
                                    or stats.get("video_view_count")
                                )
                            play_count = play_count if play_count is not None else 0
                            like_count = stats.get("like_count") if stats else 0
                            comment_count = stats.get("comment_count") if stats else 0
                            
                            # Status
                            if stats and play_count:
                                status = "ok"
                            else:
                                status = stats.get("_status_code", "no_data") if stats else "failed"
                            
                            return {
                                "Reel Link": link,
                                "Media ID": media_id_final if media_id_final else "",
                                "posted_on": stats.get("posted_on") if stats else "",
                                "Total Views": play_count,
                                "Total Likes": like_count,
                                "Total Comments": comment_count,
                                "status": status,
                            }
                        
                        completed_bulk = 0
                        rows_by_index_bulk: Dict[int, Dict[str, Any]] = {}
                        with ThreadPoolExecutor(max_workers=max_workers) as ex:
                            futures_map_bulk = {ex.submit(process_one_bulk, i): i for i in range(total_bulk)}
                            for fut in as_completed(futures_map_bulk):
                                idx = futures_map_bulk[fut]
                                try:
                                    res = fut.result()
                                except Exception as e:
                                    res = {
                                        "Reel Link": "",
                                        "Media ID": "",
                                        "posted_on": "",
                                        "Total Views": 0,
                                        "Total Likes": 0,
                                        "Total Comments": 0,
                                        "status": f"error: {type(e).__name__}",
                                    }
                                rows_by_index_bulk[idx] = res
                                completed_bulk += 1
                                if completed_bulk % 5 == 0 or completed_bulk == total_bulk:
                                    try:
                                        ordered = [rows_by_index_bulk[i] for i in sorted(rows_by_index_bulk.keys())]
                                        df_inc = _ensure_arrow_safe_bulk(pd.DataFrame(ordered))
                                        table_ph_bulk.dataframe(df_inc, width="stretch", hide_index=True)
                                    except Exception:
                                        pass
                                    prog_bulk.progress(min(completed_bulk / total_bulk, 1.0))
                        
                        if rows_by_index_bulk:
                            ordered = [rows_by_index_bulk[i] for i in sorted(rows_by_index_bulk.keys())]
                            df_final_bulk = _ensure_arrow_safe_bulk(pd.DataFrame(ordered))
                            table_ph_bulk.dataframe(df_final_bulk, width="stretch", hide_index=True)
                            
                            try:
                                csv_bytes = df_final_bulk.to_csv(index=False).encode("utf-8")
                                dl_ph_bulk.download_button(
                                    label="Download CSV",
                                    data=csv_bytes,
                                    file_name=f"bulk_instagram_reels_{len(ordered)}.csv",
                                    mime="text/csv",
                                    key="download_bulk_inline",
                                )
                            except Exception:
                                pass
        except Exception as e:
            st.error(f"Error reading CSV: {e}")

    st.markdown("---")
    st.markdown("**Option 2: Enter Reel Links Manually**")
    
    batch_input = st.text_area(
        "Enter Shortcode(s) or Reel URL(s) (single or multiple, comma/newline separated)",
        placeholder="DQV2iwvDOgy\nhttps://www.instagram.com/reel/DPtN66QETYj/\nhttps://www.instagram.com/reel/XXXX/",
        height=100,
        key="batch_input",
    ).strip()
    # Pre-run options (must be before clicking Fetch)
    fetch_captions_manual_opt = False  # Removed - captions not needed
    if False and not IS_PROD:  # Commented out for now - uncomment when debugging needed
        show_diag_manual_opt = st.checkbox("Show diagnostics", value=False, key="manual_show_diag")
    else:
        show_diag_manual_opt = False
    
    col_b1, col_b2 = st.columns([1,1])
    with col_b1:
        start_batch = st.button("Fetch", type="primary", key="batch_fetch")
    with col_b2:
        clear_batch = st.button("Clear", key="batch_clear")

    if clear_batch:
        if "batch_input" in st.session_state:
            del st.session_state["batch_input"]
        st.rerun()

    if start_batch:
        if not batch_input:
            st.error("Please enter at least one shortcode or Reel URL.")
        else:
            # Note about cookies for real-time data
            if not cookie_header_global:
                st.warning("⚠️ **Note:** Cookie header is empty. Without cookies, Instagram returns cached data (may be hours old). For real-time data, provide your Instagram session cookie above.")
            else:
                st.info("✅ Using cookies - fetching real-time data.")
            
            import re as _re
            tokens = [t for t in _re.split(r"[\s,]+", batch_input) if t]
            rows: List[Dict[str, Any]] = []
            table_ph = st.empty()
            dl_ph = st.empty()
            prog = st.progress(0)
            total = len(tokens)
            with st.spinner("Processing batch..."):
                st.session_state["reels_manual_processing"] = True
                def _ensure_arrow_safe(df: pd.DataFrame) -> pd.DataFrame:
                    for col in ["Total Views", "Total Likes", "Total Comments"]:
                        if col in df.columns:
                            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype("int64")
                    return df
                # Resolve IDs - try with cookies if available
                shortcodes = [extract_shortcode(token) or token for token in tokens]
                id_map = {}
                if cookie_header_global:
                    try:
                        id_map = bulk_fetch_media_ids(shortcodes, cookie_header_global)
                        if show_diag_manual_opt:
                            st.write(f"🔍 Bulk resolver found {len([k for k, v in id_map.items() if v])} media_ids out of {len(shortcodes)} shortcodes")
                    except Exception as e:
                        if show_diag_manual_opt:
                            st.warning(f"⚠️ Bulk resolver failed: {e}")
                        id_map = {}
                else:
                    if show_diag_manual_opt:
                        st.info("ℹ️ No cookies - will try shortcode endpoint directly (may work for public content)")

                from concurrent.futures import ThreadPoolExecutor, as_completed
                max_workers = 8
                def process_one(i: int) -> Dict[str, Any]:
                    token = tokens[i]
                    sc = shortcodes[i]
                    media_id = id_map.get(sc)
                    resolver_used = "bulk"
                    
                    # Debug output for first item
                    if i == 0 and show_diag_manual_opt:
                        st.write(f"🔍 Debug: Processing first reel - shortcode: {sc}, media_id from bulk: {media_id}")
                    
                    # Try to get media_id even without cookies (for public content)
                    if not media_id:
                        # Try with cookies if available
                        if cookie_header_global:
                            if i == 0 and show_diag_manual_opt:
                                st.write(f"🔄 Trying fallback resolver for shortcode: {sc}")
                            try:
                                media_id = resolve_media_id_with_fallback(sc, cookie_header_global)
                                if i == 0 and show_diag_manual_opt:
                                    st.write(f"🔍 After fallback resolver, media_id: {media_id}")
                            except Exception as e:
                                if i == 0 and show_diag_manual_opt:
                                    st.error(f"❌ Fallback resolver error: {type(e).__name__}: {e}")
                                media_id = None
                            
                            # If still no media_id, try direct shortcode endpoint as last resort
                        if not media_id:
                                if i == 0 and show_diag_manual_opt:
                                    st.write(f"🔄 Last resort: trying direct shortcode endpoint")
                                try:
                                    item = resolve_media_by_shortcode(sc, cookie_header_global)
                                    if item:
                                        media_id = item.get("id") or item.get("pk")
                                        if media_id:
                                            # Handle format like "123456_789012"
                                            if isinstance(media_id, str) and "_" in media_id:
                                                media_id = media_id.split("_")[0]
                                        if i == 0 and show_diag_manual_opt:
                                            st.write(f"🔍 Direct shortcode endpoint returned media_id: {media_id}")
                                except Exception as e:
                                    if i == 0 and show_diag_manual_opt:
                                        st.error(f"❌ Direct shortcode endpoint error: {type(e).__name__}: {e}")
                        
                        # Also try without cookies (for public content)
                        if not media_id:
                            if i == 0 and show_diag_manual_opt:
                                st.write(f"🔄 Trying shortcode endpoint without cookies (public content)")
                            try:
                                # Try shortcode endpoint without cookies
                                item = resolve_media_by_shortcode(sc, "")  # Empty cookie string
                                if item:
                                    media_id = item.get("id") or item.get("pk")
                                    if media_id and isinstance(media_id, str) and "_" in media_id:
                                        media_id = media_id.split("_")[0]
                                    if i == 0 and show_diag_manual_opt:
                                        st.write(f"🔍 Shortcode endpoint (no cookies) returned media_id: {media_id}")
                            except Exception as e:
                                if i == 0 and show_diag_manual_opt:
                                    st.warning(f"⚠️ Shortcode endpoint without cookies failed: {type(e).__name__}: {e}")
                        
                        if not media_id:
                            if i == 0 and show_diag_manual_opt:
                                st.warning(f"⚠️ Could not resolve media_id for shortcode: {sc}, but will try to get stats directly")
                    
                    # Even if media_id is missing, we can still try to get stats from shortcode endpoint
                    ref = f"https://www.instagram.com/p/{sc}/"
                    stats = {}
                    stats_graphql_result = None  # Initialize for debugging
                    
                    # Debug: Check cookie header
                    if i == 0 and show_diag_manual_opt:
                        st.write(f"🔍 Debug: cookie_header_global = '{cookie_header_global[:50] if cookie_header_global else '(empty)'}...'")
                        st.write(f"🔍 Debug: len(cookie_header_global) = {len(cookie_header_global) if cookie_header_global else 0}")
                        st.write(f"🔍 Debug: bool(cookie_header_global) = {bool(cookie_header_global)}")
                    
                    # Strategy 0: For unauthenticated requests, use NEW direct GraphQL method (doc_id=8845758582119845)
                    # This is the recommended method from the documentation
                    if not cookie_header_global:
                        if i == 0 and show_diag_manual_opt:
                            st.write(f"🔄 Strategy 0: Trying NEW direct GraphQL method (doc_id=8845758582119845) for unauthenticated request")
                        try:
                            stats_graphql_result = fetch_reel_metrics_public(sc, max_retries=3)
                            
                            # Extract media_id from GraphQL result if available, and use stats if any
                            media_id_from_graphql = stats_graphql_result.get("media_id") if stats_graphql_result else None
                            if media_id_from_graphql:
                                media_id = media_id_from_graphql  # Use media_id from GraphQL if available
                            
                            if stats_graphql_result and stats_graphql_result.get("play_count"):
                                # Remove debug info before using stats
                                stats = {k: v for k, v in stats_graphql_result.items() if not k.startswith("_")}
                                resolver_used = "graphql"  # Replace bulk with graphql since this is the primary method for unauthenticated
                            elif stats_graphql_result:
                                # Even if no play_count, use whatever stats we got (including media_id)
                                stats = {k: v for k, v in stats_graphql_result.items() if not k.startswith("_")}
                                resolver_used = resolver_used + "+graphql_partial"
                        except Exception as e:
                            if i == 0 and show_diag_manual_opt:
                                st.error(f"❌ Strategy 0 (NEW GraphQL) exception: {type(e).__name__}: {e}")
                                import traceback
                                st.code(traceback.format_exc(), language="python")
                    
                    # Strategy 0b: Fallback to OLD GraphQL method if NEW one failed
                    if (not stats or not stats.get("play_count")) and not cookie_header_global:
                        if i == 0 and show_diag_manual_opt:
                            st.write(f"🔄 Strategy 0b: Trying OLD GraphQL method (bulk-route + graphql) as fallback")
                        try:
                            stats_graphql_old = fetch_reel_stats_via_graphql(sc, cookie_header="", debug=show_diag_manual_opt)
                            if stats_graphql_old and stats_graphql_old.get("play_count"):
                                stats = {k: v for k, v in stats_graphql_old.items() if not k.startswith("_")}
                                resolver_used = resolver_used + "+old_graphql_fallback"
                                if i == 0 and show_diag_manual_opt:
                                    st.success(f"✅ Strategy 0b worked! play_count: {stats.get('play_count')}")
                            elif stats_graphql_old:
                                # Even if no play_count, use whatever we got
                                stats_temp = {k: v for k, v in stats_graphql_old.items() if not k.startswith("_")}
                                if not stats or len(stats_temp) > len(stats):
                                    stats = stats_temp
                                    resolver_used = resolver_used + "+old_graphql_partial"
                        except Exception as e:
                            if i == 0 and show_diag_manual_opt:
                                st.warning(f"⚠️ Strategy 0b failed: {type(e).__name__}: {e}")
                    
                    # Strategy 1: If we have media_id, try fetching stats by pk
                    if media_id and cookie_header_global:
                        if i == 0 and show_diag_manual_opt:
                            st.write(f"🔍 Strategy 1: Fetching stats for media_id: {media_id} via GET /api/v1/media/{media_id}/info/")
                        try:
                            stats_new = fetch_media_stats_by_pk(
                                media_id,
                                cookie_header_global,
                                referer_url=ref,
                            )
                            # Debug: show what we got (first item only)
                            if i == 0 and show_diag_manual_opt:
                                st.json({"fetch_media_stats_by_pk_response": stats_new})
                                if stats_new and stats_new.get("play_count"):
                                    st.success(f"✅ Strategy 1 worked! play_count: {stats_new.get('play_count')}")
                                elif stats_new:
                                    st.warning(f"⚠️ Strategy 1 returned stats but no play_count. Keys: {list(stats_new.keys())}")
                                else:
                                    st.warning("⚠️ Strategy 1 returned empty stats")
                            # Only overwrite stats if we got something useful
                            if stats_new and stats_new.get("play_count"):
                                stats = stats_new
                        except Exception as e:
                            if i == 0 and show_diag_manual_opt:
                                st.error(f"❌ Strategy 1 failed: {type(e).__name__}: {e}")
                    
                    # Strategy 2: Try fetching directly from shortcode endpoint (PRIMARY METHOD)
                    # API: GET https://www.instagram.com/api/v1/media/shortcode/{shortcode}/info/
                    # This can work with or without cookies (for public content)
                    if not stats or not stats.get("play_count"):
                        cookie_to_use = cookie_header_global if cookie_header_global else ""
                        if i == 0 and show_diag_manual_opt:
                            st.write(f"🔄 Strategy 2: Trying shortcode endpoint {'with' if cookie_to_use else 'without'} cookies")
                            st.write(f"🔄 Strategy 2: API endpoint: GET /api/v1/media/shortcode/{sc}/info/")
                        try:
                            if i == 0 and show_diag_manual_opt:
                                st.write(f"🔍 Calling resolve_media_by_shortcode with cookie: {'yes' if cookie_to_use else 'no'}")
                            item = resolve_media_by_shortcode(sc, cookie_to_use)
                            if item:
                                if i == 0 and show_diag_manual_opt:
                                    st.write(f"✅ Shortcode endpoint returned data with keys: {list(item.keys())[:10]}")
                                stats_from_shortcode = parse_stats_from_item(item)
                                # Only use if it has play_count
                                if stats_from_shortcode.get("play_count"):
                                    stats = stats_from_shortcode
                                    resolver_used = resolver_used + "+shortcode_api"
                                    if i == 0 and show_diag_manual_opt:
                                        st.success(f"✅ Got stats from shortcode API! play_count: {stats.get('play_count')}")
                                        st.json({"resolve_media_by_shortcode_response": stats})
                                elif i == 0 and show_diag_manual_opt:
                                    st.warning(f"⚠️ Shortcode API returned item but no play_count. Available keys: {list(item.keys())[:10]}")
                                    # Show what fields ARE available - especially look for any count fields
                                    preview_dict = {}
                                    for key in list(item.keys())[:15]:
                                        val = item.get(key)
                                        if isinstance(val, (int, str)) or val is None:
                                            preview_dict[key] = val
                                    st.json({"sample_item_preview": preview_dict})
                                    # Also check nested structures
                                    if item.get("video_view_count"):
                                        st.info(f"Found video_view_count: {item.get('video_view_count')}")
                                    if item.get("view_count"):
                                        st.info(f"Found view_count: {item.get('view_count')}")
                        except Exception as e:
                            if i == 0 and show_diag_manual_opt:
                                st.error(f"❌ Strategy 2 failed: {type(e).__name__}: {e}")
                                import traceback
                                st.code(traceback.format_exc(), language="python")
                    
                    # Strategy 3: Try using fetch_play_count_with_cookies directly
                    if (not stats or not stats.get("play_count")) and cookie_header_global:
                        if i == 0 and show_diag_manual_opt:
                            st.write("🔄 Trying direct play_count endpoint")
                        try:
                            play_count = fetch_play_count_with_cookies(f"https://www.instagram.com/reel/{sc}/", cookie_header_global)
                            if play_count:
                                stats = {"play_count": play_count, "shortcode": sc}
                                resolver_used = resolver_used + "+play_count_direct"
                                if i == 0 and show_diag_manual_opt:
                                    st.write(f"✅ Got play_count directly: {play_count}")
                        except Exception as e:
                            if i == 0 and show_diag_manual_opt:
                                st.error(f"❌ Error fetching play_count directly: {type(e).__name__}: {e}")
                    
                    # Strategy 4: Also try GraphQL method even with cookies (as fallback)
                    if (not stats or not stats.get("play_count")):
                        if i == 0 and show_diag_manual_opt:
                            st.write(f"🔄 Strategy 4: Trying GraphQL method as fallback")
                        try:
                            stats_graphql = fetch_reel_stats_via_graphql(sc, cookie_header=cookie_header_global or "", debug=show_diag_manual_opt)
                            if stats_graphql and stats_graphql.get("play_count"):
                                stats = {k: v for k, v in stats_graphql.items() if not k.startswith("_")}
                                resolver_used = resolver_used + "+graphql_fallback"
                                if i == 0 and show_diag_manual_opt:
                                    st.success(f"✅ Strategy 4 (GraphQL fallback) worked! play_count: {stats.get('play_count')}")
                        except Exception as e:
                            if i == 0 and show_diag_manual_opt:
                                st.warning(f"⚠️ Strategy 4 (GraphQL fallback) failed: {type(e).__name__}: {e}")
                    
                    # Final check: if we still have no stats and no media_id, mark as failed
                    if not stats and not media_id:
                        if i == 0 and show_diag_manual_opt:
                            st.error(f"❌ All methods failed - no stats and no media_id for shortcode: {sc}")
                    
                    cap = ""
                    if fetch_captions_manual_opt and media_id and cookie_header_global:
                        try:
                            cap = fetch_caption_by_media_pk(
                                media_id,
                                cookie_header_global,
                                referer_url=ref,
                            ) or ""
                        except Exception:
                            cap = ""
                    shortcode = (stats.get("shortcode") if stats else None) or sc
                    # Get media_id from stats or from earlier resolution
                    media_id_final = stats.get("media_id") or stats.get("id") if stats else media_id
                    
                    # Get play_count from stats, checking multiple possible field names
                    play_count = None
                    if stats:
                        play_count = (
                            stats.get("play_count")
                            or stats.get("video_play_count")
                            or stats.get("view_count")
                            or stats.get("video_view_count")
                        )
                    play_count = play_count if play_count is not None else 0
                    like_count = stats.get("like_count") if stats else 0
                    comment_count = stats.get("comment_count") if stats else 0
                    
                    # Status: "ok" if we have play_count, otherwise show the status code
                    if stats and play_count:
                        status = "ok"
                    else:
                        # Get status code from stats if available
                        status = stats.get("_status_code", "failed") if stats else "no_data"
                    
                    result_dict = {
                        "Reel Link": f"https://www.instagram.com/reel/{shortcode}/" if shortcode else "",
                        "Media ID": media_id_final if media_id_final else "",
                        "posted_on": stats.get("posted_on") if stats else "",
                        "Total Views": play_count,
                        "Total Likes": like_count,
                        "Total Comments": comment_count,
                        "status": status,
                    }
                    
                    # Store debug info from Strategy 0 for display after thread completes
                    if show_diag_manual_opt and i == 0 and stats_graphql_result:
                        if stats_graphql_result.get("_debug"):
                            result_dict["_debug_info"] = stats_graphql_result.get("_debug")
                            result_dict["_debug_error"] = stats_graphql_result.get("_error")
                            result_dict["_debug_response"] = {k: v for k, v in stats_graphql_result.items() if not k.startswith("_")}
                    
                    return result_dict

                completed = 0
                rows_by_index: Dict[int, Dict[str, Any]] = {}
                debug_info_collected = None
                with ThreadPoolExecutor(max_workers=max_workers) as ex:
                    futures_map = {ex.submit(process_one, i): i for i in range(total)}
                    for fut in as_completed(futures_map):
                        idx = futures_map[fut]
                        try:
                            res = fut.result()
                            # Collect debug info from first item if available
                            if idx == 0 and res.get("_debug_info"):
                                debug_info_collected = {
                                    "debug_messages": res.get("_debug_info", []),
                                    "error": res.get("_debug_error"),
                                    "response": res.get("_debug_response"),
                                }
                                # Remove debug fields from result dict before adding to dataframe
                                for key in ["_debug_info", "_debug_error", "_debug_response"]:
                                    res.pop(key, None)
                        except Exception as e:
                            res = {
                                "Reel Link": "",
                                "Media ID": "",
                                "posted_on": "",
                                "caption": "",
                                "media_type": "",
                                "Total Views": 0,
                                "Total Likes": 0,
                                "Total Comments": 0,
                                "status": f"error: {type(e).__name__}",
                            }
                        rows_by_index[idx] = res
                        completed += 1
                        if completed % 50 == 0 or completed == total:
                            try:
                                ordered = [rows_by_index[i] for i in sorted(rows_by_index.keys())]
                                df_inc = _ensure_arrow_safe(pd.DataFrame(ordered))
                                table_ph.dataframe(df_inc, width="stretch", hide_index=True)
                            except Exception:
                                pass
                            prog.progress(min(completed / total, 1.0))
                
                # Display debug info AFTER all threads complete (in main Streamlit context)
                if show_diag_manual_opt and debug_info_collected:
                    st.markdown("---")
                    with st.expander("🔍 Strategy 0 Debug Info (from first reel)", expanded=True):
                        st.write("**Debug Messages:**")
                        for msg in debug_info_collected.get("debug_messages", []):
                            st.text(msg)
                        
                        if debug_info_collected.get("error"):
                            st.error(f"**Error:** {debug_info_collected.get('error')}")
                        
                        if debug_info_collected.get("response"):
                            st.write("**Response Data:**")
                            st.json(debug_info_collected.get("response"))
                            
            if rows_by_index:
                ordered = [rows_by_index[i] for i in sorted(rows_by_index.keys())]
                df_batch = _ensure_arrow_safe(pd.DataFrame(ordered))
                table_ph.dataframe(df_batch, width="stretch", hide_index=True)
                # Persist manual results
                st.session_state["reels_manual_results"] = {
                    "df": df_batch,
                    "count": len(ordered),
                }
                st.session_state["reels_manual_processing"] = False
                try:
                    csv_bytes = df_batch.to_csv(index=False).encode("utf-8")
                    dl_ph.download_button(
                        label="Download CSV",
                        data=csv_bytes,
                        file_name=f"instagram_reels_{len(ordered)}.csv",
                        mime="text/csv",
                        key="download_manual_inline",
                    )
                except Exception as e:
                    st.warning(f"CSV download unavailable: {type(e).__name__}: {e}")

    # Show persistent Manual results (if any) and not processing
    if st.session_state.get("reels_manual_results") is not None and not st.session_state.get("reels_manual_processing"):
        res = st.session_state["reels_manual_results"]
        st.markdown("### Manual Results")
        try:
            csv_bytes = res["df"].to_csv(index=False).encode("utf-8")
            st.download_button(
                label="Download CSV",
                data=csv_bytes,
                file_name=f"instagram_reels_{res['count']}.csv",
                mime="text/csv",
                key="download_manual_persist",
            )
        except Exception:
            pass
        if st.button("Clear Manual Results", key="clear_manual_results"):
            st.session_state["reels_manual_results"] = None
            st.rerun()

    st.markdown("<div class='small-tip'>Tip: switch tabs with Ctrl + Tab</div>", unsafe_allow_html=True)

st.markdown("<div class='footer-note'>Made with Streamlit • Data from Instagram (public only)</div>", unsafe_allow_html=True)
st.markdown("</div>", unsafe_allow_html=True)
