# Instagram Reels Analyzer

A sleek Streamlit web application for analyzing Instagram Reels data. This tool allows you to fetch detailed statistics for Instagram Reels using your own Instagram session cookies.

## Features

- **Analyze Profile**: Enter any Instagram username or profile URL to fetch the latest 5 Reels with detailed stats
- **Analyze Reels**: Batch process multiple Reel URLs/shortcodes to get comprehensive data
- **Comprehensive Data**: Get media ID, shortcode, play count, like count, comment count, owner info, captions, and more
- **Real-time Processing**: Incremental display of results as they're fetched
- **CSV Export**: Download results as CSV files
- **Modern UI**: Clean, tabbed interface with dark theme

## Data Points

For each Reel, the tool fetches:
- Media ID (PK)
- Shortcode
- Posted Date
- Media Type (Reel/Post)
- Play Count (exact number)
- Like Count
- Comment Count
- Owner Username
- Owner Full Name
- Owner User ID
- Caption Text
- Status

## Requirements

- Python 3.8+
- Streamlit
- Pandas
- Requests

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/instagram-reels-analyzer.git
cd instagram-reels-analyzer
```

2. Create a virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install streamlit pandas requests
```

## Usage

1. Run the application:
```bash
streamlit run app.py
```

2. Open your browser and go to `http://localhost:8501`

3. Get your Instagram cookies:
   - Open Instagram in your browser
   - Open DevTools (F12)
   - Go to Network tab
   - Make any request (refresh the page)
   - Copy the full Cookie header from any XHR request

4. Paste your cookies in the "Cookie header" field

5. Use either tab:
   - **Analyze Profile**: Enter username or profile URL
   - **Analyze Reels**: Enter Reel URLs or shortcodes (comma/newline separated)

## Important Notes

- This tool requires valid Instagram session cookies to work
- Cookies expire, so you may need to refresh them periodically
- The tool respects Instagram's rate limits with built-in throttling
- Only works with public Instagram accounts and Reels

## Disclaimer

This tool is for educational and research purposes only. Please respect Instagram's Terms of Service and use responsibly. The authors are not responsible for any misuse of this tool.

## License

MIT License - see LICENSE file for details

### 10-step tech flow: from pasting a Reel link to obtaining its exact play/view count

- **Scope**: Instagram Reels only, public content. Requires a valid Instagram web session (user cookies).
- **Key output**: exact play count (`play_count`/`video_view_count`/`view_count`), plus likes/comments if needed.

1) Accept input and extract the shortcode
- **Input**: Reel URL or shortcode (e.g., `https://www.instagram.com/reel/ABC123/`, `ABC123`).
- **Extract**: Use regex `/(?:reel|p)/([A-Za-z0-9_]+)/?` and sanitize to `[A-Za-z0-9_]`.

2) Require a valid Instagram Cookie header
- **How**: Browser DevTools → Network on `instagram.com`, copy full `Cookie` from any XHR.
- **Important cookies**: `sessionid`, `csrftoken`, `ds_user_id` (and the rest as copied).
- **Tip**: Also forward `x-csrftoken` header when available.

3) Prepare a shared HTTP session and base headers
- **Base headers**: `user-agent` (real browser UA), `accept: */*`.
- **Per-request headers**: `cookie: <FULL_COOKIE>`, `x-ig-app-id: 936619743392459`, optional `x-csrftoken`, and a `referer` like `https://www.instagram.com/reel/{shortcode}/`.

4) Fast path: resolve media_id via Bulk Route Definitions
- **Endpoint**: POST `https://www.instagram.com/ajax/bulk-route-definitions/`
- **Headers**: `content-type: application/x-www-form-urlencoded`, `origin: https://www.instagram.com`, `referer: https://www.instagram.com/reel/{shortcode}/`, `x-ig-d: www`, `cookie`.
- **Form params (minimal set)**:
  - `route_urls[0]=/reel/{shortcode}/`
  - `routing_namespace=igx_www$a$87a091182d5bd65bcb043a2888004e09`
  - `__d=www`, `__a=1`, `dpr=2`
- **Parse**: `payload.payloads["/reel/{shortcode}/"].result.exports.rootView.props.media_id` (fallback regex: `"media_id"\s*:\s*"(\d+)"`).

5) Fallback: resolve via shortcode info endpoint
- **Endpoint**: GET `https://www.instagram.com/api/v1/media/shortcode/{shortcode}/info/`
- **Headers**: `x-ig-app-id`, `x-requested-with: XMLHttpRequest`, `cookie`, `referer: https://www.instagram.com/reel/{shortcode}/` (fallback to `/p/{shortcode}/` on 404).
- **Parse**: First item of `items[]` or root; get `id`/`pk`. If `id` looks like `12345_6789`, split on `_` and use the first number as `media_pk`.

6) Fallback: oEmbed for media_id
- **Endpoint**: GET `https://www.instagram.com/oembed/?url=https://www.instagram.com/reel/{shortcode}/`
- **Headers**: `cookie`, realistic `user-agent`.
- **Parse**: `media_id` or `id`; split `_` if present to obtain `media_pk`.

7) Fallback: HTML page parse for media_id
- **Endpoint**: GET `https://www.instagram.com/reel/{shortcode}/` (or `/p/{shortcode}/`)
- **Headers**: `cookie`, `referer`, browser UA, `accept` for HTML.
- **Parse**: `"media_id"\s*:\s*"(\d+)"` or `"id"\s*:\s*"(\d+)_\d+"` → take the first number.

8) Fetch exact stats by media pk (recommended)
- **Endpoint**: GET `https://www.instagram.com/api/v1/media/{media_pk}/info/`
- **Headers**: `x-ig-app-id`, `x-requested-with: XMLHttpRequest`, `cookie`, `referer: https://www.instagram.com/p/{shortcode}/`.
- **Parse**: From first `items[]` element or root:
  - Views: `play_count` or `video_play_count` or `view_count` or `video_view_count`
  - Likes: `like_count` or `edge_liked_by.count`
  - Comments: `comment_count` or `edge_media_to_comment.count`
  - Shortcode: `code` or `shortcode`
  - Posted date: `taken_at_timestamp`/`taken_at` → convert to `YYYY-MM-DD` if needed

9) Rate limits, retries, and auth errors
- **Throttle**: Space cookie/GraphQL calls (≈20s) to reduce 429s; consider exponential backoff (e.g., 1.5s → 3s → 6s).
- **Errors**:
  - 401/403: invalid/expired cookies or private content
  - 404: try alternate referer (`/p/`) or other resolvers
  - 429: rate-limited; wait and retry later

10) Examples

Example output JSON:

```json
{
  "shortcode": "ABC123",
  "media_pk": "1234567890123456789",
  "posted_on": "2025-10-30",
  "media_type": "CLIPS",
  "product_type": "clips",
  "play_count": 123456,
  "like_count": 7890,
  "comment_count": 123
}
```

Resolve media_id via bulk route:

```bash
curl 'https://www.instagram.com/ajax/bulk-route-definitions/' \
  -H 'content-type: application/x-www-form-urlencoded' \
  -H 'origin: https://www.instagram.com' \
  -H 'referer: https://www.instagram.com/reel/ABC123/' \
  -H 'x-ig-d: www' \
  -H 'cookie: <FULL_COOKIE_STRING>' \
  --data-raw 'route_urls[0]=/reel/ABC123/&routing_namespace=igx_www$a$87a091182d5bd65bcb043a2888004e09&__d=www&__a=1&dpr=2'
```

Fetch stats by media pk:

```bash
curl 'https://www.instagram.com/api/v1/media/1234567890123456789/info/' \
  -H 'x-ig-app-id: 936619743392459' \
  -H 'x-requested-with: XMLHttpRequest' \
  -H 'referer: https://www.instagram.com/p/ABC123/' \
  -H 'user-agent: Mozilla/5.0' \
  -H 'cookie: <FULL_COOKIE_STRING>'
```

Shortcode info fallback:

```bash
curl 'https://www.instagram.com/api/v1/media/shortcode/ABC123/info/' \
  -H 'x-ig-app-id: 936619743392459' \
  -H 'x-requested-with: XMLHttpRequest' \
  -H 'referer: https://www.instagram.com/reel/ABC123/' \
  -H 'cookie: <FULL_COOKIE_STRING>'
```
