# Run: pip install streamlit pandas requests

import streamlit as st
import pandas as pd
from datetime import datetime
from typing import List, Dict, Any, Optional

import time
import requests
import json
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
def extract_shortcode(reel_url: str) -> Optional[str]:
    try:
        # Accept forms like https://www.instagram.com/reel/<shortcode>/
        # or https://www.instagram.com/p/<shortcode>/ with optional trailing parts
        import re
        m = re.search(r"/(?:reel|p)/([A-Za-z0-9_-]+)/?", reel_url)
        return m.group(1) if m else None
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

    csrf = _extract_cookie_value(cookie_header, "csrftoken")

    headers = {
        "x-ig-app-id": "936619743392459",
        "x-requested-with": "XMLHttpRequest",
        "user-agent": "Mozilla/5.0",
        "referer": f"https://www.instagram.com/reel/{shortcode}/",
        "cookie": cookie_header,
        "accept": "*/*",
    }
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
        resp = requests.get(url, headers=headers, timeout=20)
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
# GraphQL: Profile Reels tab (per your cURL)
# ----------------------------
def fetch_profile_reels_graphql(
    cookie_header: str,
    target_user_id: str,
    page_size: int = 12,
    doc_id: str = "24127588873492897",
    lsd: str = "76QeIqTETcgEMdD0A-57NO",
    referer: str = "https://www.instagram.com/",
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

    variables = {
        "data": {
            "include_feed_video": True,
            "page_size": int(page_size),
            "target_user_id": str(target_user_id),
        }
    }

    headers = {
        "accept": "*/*",
        "content-type": "application/x-www-form-urlencoded",
        "user-agent": "Mozilla/5.0",
        "x-ig-app-id": "936619743392459",
        "x-fb-lsd": lsd,
        "origin": "https://www.instagram.com",
        "referer": referer,
        "cookie": cookie_header,
    }
    if csrf:
        headers["x-csrftoken"] = csrf

    data = {
        "doc_id": doc_id,
        "variables": json.dumps(variables, separators=(",", ":")),
    }

    # Throttle: ensure at least 20s between GraphQL calls
    min_interval = 20
    now = time.time()
    last_ts = st.session_state.get("last_graphql_call_ts", 0)
    if now - last_ts < min_interval:
        time.sleep(min_interval - (now - last_ts))

    # Exponential backoff on 429
    backoffs = [1.5, 3.0, 6.0]
    for i, wait_s in enumerate([0.0] + backoffs):
        if wait_s:
            time.sleep(wait_s)
        resp = requests.post("https://www.instagram.com/graphql/query", headers=headers, data=data, timeout=20)
        if resp.status_code == 429 and i < len(backoffs):
            continue
        break

    st.session_state["last_graphql_call_ts"] = time.time()

    if resp.status_code in (401, 403):
        raise PermissionError("Unauthorized or cookies expired")
    if resp.status_code == 429:
        raise ConnectionError("Rate limited (429)")
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
        resp = requests.get(url, headers=headers, timeout=20)
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
            posted_on = datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%d")
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

    # Try with provided referer (or /p/), then fallback to /reel/ if 404
    resp = requests.get(url, headers=headers, timeout=20)
    if resp.status_code == 404:
        headers["referer"] = f"https://www.instagram.com/reel/{shortcode}/"
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

    resp = requests.post(
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
def fetch_user_id_with_cookies(username: str, cookie_header: str) -> Optional[str]:
    url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
    headers = {
        "x-ig-app-id": "936619743392459",
        "x-requested-with": "XMLHttpRequest",
        "user-agent": "Mozilla/5.0",
        "cookie": cookie_header,
        "accept": "*/*",
    }
    resp = requests.get(url, headers=headers, timeout=20)
    if resp.status_code in (401, 403):
        raise PermissionError("Unauthorized or cookies expired")
    if resp.status_code == 429:
        raise ConnectionError("Rate limited (429)")
    resp.raise_for_status()
    data = resp.json()
    return (((data or {}).get("data") or {}).get("user") or {}).get("id")

def reels_to_dataframe(items: List[Dict[str, Any]]) -> pd.DataFrame:
    if not items:
        return pd.DataFrame(
            columns=["Reel Link", "Posted On", "Caption", "Media Type", "Plays", "Likes", "Comments"]
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
                "Plays": it.get("video_view_count", 0),
                "Likes": it["likes"],
                "Comments": it["comments"],
                "_sort_ts": it["taken_at_timestamp"].timestamp(),
            }
        )

    df = pd.DataFrame(rows)
    df = df.sort_values(by="_sort_ts", ascending=False).drop(columns=["_sort_ts"]).reset_index(drop=True)

    df_display = df.copy()
    df_display["Likes"] = df_display["Likes"].apply(format_count)
    df_display["Comments"] = df_display["Comments"].apply(format_count)
    # Do NOT format Plays; show full exact number

    return df_display


# ----------------------------
# Shared Inputs (global across tabs)
# ----------------------------
cookie_header_global = st.text_area(
    "Cookie header for Instagram web API",
    value="",
    placeholder="sessionid=...; csrftoken=...; ds_user_id=...; ...",
    help="Open DevTools → Network on instagram.com, select any XHR, and copy the full Cookie header.",
)


# Keep session state
if "last_username" not in st.session_state:
    st.session_state["last_username"] = ""
if "caption_cache" not in st.session_state:
    st.session_state["caption_cache"] = {}
if "show_captions" not in st.session_state:
    st.session_state["show_captions"] = False

def clear_cache_for_username(u: str):
    fetch_user_id_with_cookies.clear()

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
    
    # CSV Upload Section
    st.markdown("**Option 1: Upload CSV of Reel Links**")
    uploaded_file = st.file_uploader(
        "Choose a CSV file with reel links",
        type="csv",
        help="CSV should have a column with Instagram reel URLs (e.g., 'https://www.instagram.com/reel/ABC123/')",
        key="csv_uploader"
    )
    
    if uploaded_file is not None:
        try:
            # Read CSV
            df_uploaded = pd.read_csv(uploaded_file)
            st.success(f"✅ CSV uploaded successfully! Found {len(df_uploaded)} rows.")
            
            # Find the column with reel links
            reel_links = []
            for col in df_uploaded.columns:
                if df_uploaded[col].astype(str).str.contains('instagram.com/reel/', na=False).any():
                    reel_links = df_uploaded[col].dropna().tolist()
                    st.info(f"📊 Found reel links in column: '{col}'")
                    break
            
            if not reel_links:
                st.error("❌ No Instagram reel links found in the CSV. Please ensure your CSV contains URLs like 'https://www.instagram.com/reel/ABC123/'")
            else:
                st.write(f"🔗 Processing {len(reel_links)} reel links...")
                
                # Process the reel links
                if st.button("Process CSV Reel Links", type="primary", key="process_csv"):
                    if not cookie_header_global:
                        st.error("Cookie header is required. Paste your Instagram Cookie header above.")
                    else:
                        with st.spinner("Processing CSV reel links..."):
                            rows = []
                            total = len(reel_links)
                            prog = st.progress(0)
                            table_ph = st.empty()
                            
                            for idx, link in enumerate(reel_links):
                                try:
                                    sc = extract_shortcode(link) or link
                                    media_id = fetch_media_id_via_bulk_route(sc, cookie_header_global)
                                    if not media_id:
                                        rows.append({
                                            "Reel Link": link,
                                            "posted_on": "",
                                            "caption": "",
                                            "media_type": "",
                                            "play_count": "",
                                            "like_count": "",
                                            "comment_count": "",
                                            "status": "not found",
                                        })
                                        prog.progress(min((idx + 1) / total, 1.0))
                                        continue
                                    
                                    ref = f"https://www.instagram.com/p/{sc}/"
                                    try:
                                        stats = fetch_media_stats_by_pk(media_id, cookie_header_global, referer_url=ref)
                                    except Exception:
                                        stats = {}
                                    try:
                                        cap = fetch_caption_by_media_pk(media_id, cookie_header_global, referer_url=ref) or ""
                                    except Exception:
                                        cap = ""
                                    
                                    rows.append({
                                        "Reel Link": link,
                                        "posted_on": stats.get("posted_on"),
                                        "caption": cap,
                                        "media_type": stats.get("product_type") or stats.get("media_type"),
                                        "play_count": stats.get("play_count"),
                                        "like_count": stats.get("like_count"),
                                        "comment_count": stats.get("comment_count"),
                                        "status": "ok",
                                    })
                                except Exception as e:
                                    rows.append({
                                        "Reel Link": link,
                                        "posted_on": "",
                                        "caption": "",
                                        "media_type": "",
                                        "play_count": "",
                                        "like_count": "",
                                        "comment_count": "",
                                        "status": f"error: {type(e).__name__}",
                                    })
                                
                                # Incremental render
                                try:
                                    df_inc = pd.DataFrame(rows)
                                    table_ph.dataframe(df_inc, use_container_width=True, hide_index=True)
                                except Exception:
                                    table_ph.write(rows[-1])
                                prog.progress(min((idx + 1) / total, 1.0))
                            
                            # Final render
                            if rows:
                                df_final = pd.DataFrame(rows)
                                table_ph.dataframe(df_final, use_container_width=True, hide_index=True)
                                
                                # Download CSV
                                csv_bytes = df_final.to_csv(index=False).encode("utf-8")
                                st.download_button(
                                    label="Download Results CSV",
                                    data=csv_bytes,
                                    file_name=f"instagram_reels_analysis_{len(rows)}.csv",
                                    mime="text/csv"
                                )
        except Exception as e:
            st.error(f"Error reading CSV: {e}")
    
    st.markdown("---")
    st.markdown("**Option 2: Analyze by Username**")
    
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
        st.session_state["profile_username"] = ""
        st.session_state["last_username"] = ""
        st.session_state["caption_cache"] = {}
        st.session_state["show_captions"] = False
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
    # no refresh button; cache clears automatically on Clear

    if username_to_use:
        error_msg = validate_username(username_to_use)
        if error_msg:
            st.error(error_msg)
        else:
            with st.spinner("Fetching Reels..."):
                try:
                    if not cookie_header_global:
                        st.error("Cookie header is required. Paste your Instagram Cookie header above.")
                    else:
                        user_id = fetch_user_id_with_cookies(username_to_use, cookie_header_global)
                        if not user_id:
                            st.error("Profile not found or private.")
                        else:
                            gql = fetch_profile_reels_graphql(
                                cookie_header=cookie_header_global,
                                target_user_id=user_id,
                                page_size=5,
                                referer=f"https://www.instagram.com/{username_to_use}/",
                            )

                            edges = None
                            for path in [
                                ("data", "xdt_api__v1__clips__user__connection_v2", "edges"),
                                ("data", "user", "edge_clips_tab", "edges"),
                                ("data", "user", "edge_owner_to_timeline_media", "edges"),
                            ]:
                                cur = gql
                                ok = True
                                for p in path:
                                    cur = cur.get(p)
                                    if cur is None:
                                        ok = False
                                        break
                                if ok:
                                    edges = cur
                                    break

                            items: List[Dict[str, Any]] = []
                            if isinstance(edges, list):
                                for e in edges[:5]:
                                    node = (e or {}).get("node") or {}
                                    media = node.get("media") or node
                                    shortcode = media.get("code") or media.get("shortcode") or ""
                                    media_pk = media.get("pk") or ""
                                    like_count = (
                                        (media.get("edge_liked_by") or {}).get("count")
                                        or media.get("like_count")
                                        or 0
                                    )
                                    comment_count = (
                                        (media.get("edge_media_to_comment") or {}).get("count")
                                        or media.get("comment_count")
                                        or 0
                                    )
                                    play_count = (
                                        media.get("play_count")
                                        or media.get("video_play_count")
                                        or media.get("view_count")
                                    )
                                    ts = media.get("taken_at_timestamp") or media.get("taken_at")
                                    taken_at = (
                                        datetime.utcfromtimestamp(ts) if ts else datetime.utcnow()
                                    )
                                    items.append(
                                        {
                                            "shortcode": shortcode,
                                            "media_pk": media_pk,
                                            "owner_username": username_to_use,
                                            "likes": like_count,
                                            "comments": comment_count,
                                            "video_view_count": play_count,
                                            "taken_at_timestamp": taken_at,
                                        }
                                    )

                            if not items:
                                st.warning("This profile has no Reels.")
                            else:
                                st.success(f"Found {len(items)} Reels from @{username_to_use}")

                                # Build rows with the SAME fields as the Reels analyzer
                                rows: List[Dict[str, Any]] = []
                                table_ph = st.empty()
                                prog = st.progress(0)
                                total = len(items)
                                for idx, it in enumerate(items):
                                    try:
                                        sc = it.get("shortcode") or ""
                                        media_id = it.get("media_pk") or ""
                                        if not media_id and sc:
                                            media_id = fetch_media_id_via_bulk_route(sc, cookie_header_global) or ""
                                        if not media_id:
                                            rows.append({
                                                "Reel Link": f"https://www.instagram.com/reel/{sc}/" if sc else "",
                                                "posted_on": "",
                                                "caption": "",
                                                "media_type": "",
                                                "play_count": "",
                                                "like_count": "",
                                                "comment_count": "",
                                                "status": "not found",
                                            })
                                            prog.progress(min((idx + 1) / total, 1.0))
                                            continue

                                        ref = f"https://www.instagram.com/p/{sc}/"
                                        try:
                                            stats = fetch_media_stats_by_pk(media_id, cookie_header_global, referer_url=ref)
                                        except Exception:
                                            stats = {}
                                        try:
                                            owner = fetch_media_owner_by_pk(media_id, cookie_header_global, referer_url=ref)
                                        except Exception:
                                            owner = {}
                                        try:
                                            cap = fetch_caption_by_media_pk(media_id, cookie_header_global, referer_url=ref) or ""
                                        except Exception:
                                            cap = ""

                                        shortcode = stats.get("shortcode") or sc
                                        rows.append({
                                            "Reel Link": f"https://www.instagram.com/reel/{shortcode}/" if shortcode else "",
                                            "posted_on": stats.get("posted_on"),
                                            "caption": cap,
                                            "media_type": stats.get("product_type") or stats.get("media_type"),
                                            "play_count": stats.get("play_count"),
                                            "like_count": stats.get("like_count"),
                                            "comment_count": stats.get("comment_count"),
                                            "status": "ok",
                                        })
                                    except Exception as e:
                                        sc = it.get("shortcode") or ""
                                        rows.append({
                                            "Reel Link": f"https://www.instagram.com/reel/{sc}/" if sc else "",
                                            "posted_on": "",
                                            "caption": "",
                                            "media_type": "",
                                            "play_count": "",
                                            "like_count": "",
                                            "comment_count": "",
                                            "status": f"error: {type(e).__name__}",
                                        })

                                    # incremental render
                                    try:
                                        df_inc = pd.DataFrame(rows)
                                        table_ph.dataframe(df_inc, use_container_width=True, hide_index=True)
                                    except Exception:
                                        table_ph.write(rows[-1])
                                    prog.progress(min((idx + 1) / total, 1.0))

                                # final render
                                if rows:
                                    df_final = pd.DataFrame(rows)
                                    table_ph.dataframe(df_final, use_container_width=True, hide_index=True)

                                st.session_state["last_username"] = username_to_use

                except PermissionError:
                    st.error("Profile not found or private, or cookies expired.")
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
    batch_input = st.text_area(
        "Enter Shortcode(s) or Reel URL(s) (single or multiple, comma/newline separated)",
        placeholder="DQV2iwvDOgy\nhttps://www.instagram.com/reel/DPtN66QETYj/\nhttps://www.instagram.com/reel/XXXX/",
        height=100,
        key="batch_input",
    ).strip()
    col_b1, col_b2 = st.columns([1,1])
    with col_b1:
        start_batch = st.button("Fetch", type="primary", key="batch_fetch")
    with col_b2:
        clear_batch = st.button("Clear", key="batch_clear")

    if clear_batch:
        st.session_state["batch_input"] = ""
        st.rerun()

    if start_batch:
        if not batch_input:
            st.error("Please enter at least one shortcode or Reel URL.")
        elif not cookie_header_global:
            st.error("Please paste your Cookie header above.")
        else:
            import re as _re
            tokens = [t for t in _re.split(r"[\s,]+", batch_input) if t]
            rows: List[Dict[str, Any]] = []
            table_ph = st.empty()
            dl_ph = st.empty()
            prog = st.progress(0)
            total = len(tokens)
            with st.spinner("Processing batch..."):
                for idx, token in enumerate(tokens):
                    try:
                        sc = extract_shortcode(token) or token
                        media_id = fetch_media_id_via_bulk_route(sc, cookie_header_global)
                        if not media_id:
                            rows.append({
                                "Reel Link": f"https://www.instagram.com/reel/{sc}/" if sc else "",
                                "posted_on": "",
                                "caption": "",
                                "media_type": "",
                                "play_count": "",
                                "like_count": "",
                                "comment_count": "",
                                "status": "not found",
                            })
                            try:
                                df_inc = pd.DataFrame(rows)
                                table_ph.dataframe(df_inc, use_container_width=True, hide_index=True)
                            except Exception:
                                table_ph.write(rows[-1])
                            prog.progress(min((idx + 1) / total, 1.0))
                            continue
                        ref = f"https://www.instagram.com/p/{sc}/"
                        try:
                            stats = fetch_media_stats_by_pk(
                                media_id,
                                cookie_header_global,
                                referer_url=ref,
                            )
                        except Exception:
                            stats = {}
                        try:
                            owner = fetch_media_owner_by_pk(
                                media_id,
                                cookie_header_global,
                                referer_url=ref,
                            )
                        except Exception:
                            owner = {}
                        try:
                            cap = fetch_caption_by_media_pk(
                                media_id,
                                cookie_header_global,
                                referer_url=ref,
                            ) or ""
                        except Exception:
                            cap = ""
                        shortcode = stats.get("shortcode") or sc
                        rows.append({
                            "Reel Link": f"https://www.instagram.com/reel/{shortcode}/" if shortcode else "",
                            "posted_on": stats.get("posted_on"),
                            "caption": cap,
                            "media_type": stats.get("product_type") or stats.get("media_type"),
                            "play_count": stats.get("play_count"),
                            "like_count": stats.get("like_count"),
                            "comment_count": stats.get("comment_count"),
                            "status": "ok",
                        })
                    except Exception as e:
                        rows.append({
                            "Reel Link": f"https://www.instagram.com/reel/{token}/" if token else "",
                            "posted_on": "",
                            "caption": "",
                            "media_type": "",
                            "play_count": "",
                            "like_count": "",
                            "comment_count": "",
                            "status": f"error: {type(e).__name__}",
                        })
                    try:
                        df_inc = pd.DataFrame(rows)
                        table_ph.dataframe(df_inc, use_container_width=True, hide_index=True)
                    except Exception:
                        table_ph.write(rows[-1])
                    prog.progress(min((idx + 1) / total, 1.0))
            if rows:
                df_batch = pd.DataFrame(rows)
                table_ph.dataframe(df_batch, use_container_width=True, hide_index=True)
                try:
                    csv_bytes = df_batch.to_csv(index=False).encode("utf-8")
                    dl_ph.download_button(
                        label="Download CSV",
                        data=csv_bytes,
                        file_name=f"instagram_reels_{len(rows)}.csv",
                        mime="text/csv",
                    )
                except Exception as e:
                    st.warning(f"CSV download unavailable: {type(e).__name__}: {e}")

    st.markdown("<div class='small-tip'>Tip: switch tabs with Ctrl + Tab</div>", unsafe_allow_html=True)

st.markdown("<div class='footer-note'>Made with Streamlit • Data from Instagram (public only)</div>", unsafe_allow_html=True)
st.markdown("</div>", unsafe_allow_html=True)
