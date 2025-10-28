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
