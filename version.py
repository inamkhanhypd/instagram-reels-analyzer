# Version management for Instagram Reels Analyzer
VERSION = "1.2.0"
BUILD_DATE = "2025-01-28"
CHANGELOG = {
    "1.2.0": {
        "date": "2025-01-28",
        "changes": [
            "Changed shortcode display to show full reel links instead of clickable text",
            "Added CSV upload functionality to Analyze Profile section",
            "CSV upload automatically detects reel links in any column",
            "Added incremental processing with progress bar for CSV uploads",
            "Added download button for CSV analysis results",
            "Improved user experience with two options: CSV upload or username analysis"
        ]
    },
    "1.1.0": {
        "date": "2025-01-28",
        "changes": [
            "Added version display in header",
            "Removed owner fields (username, full name, user ID)",
            "Removed media_id column",
            "Reordered columns: Shortcode | Posted On | Caption | Media Type | Plays | Likes | Comments",
            "Made shortcodes clickable links to Instagram reels",
            "Streamlined UI for better user experience"
        ]
    },
    "1.0.0": {
        "date": "2025-01-28",
        "changes": [
            "Initial release with two-tab interface",
            "Analyze Profile: Fetch latest 5 reels for any username",
            "Analyze Reels: Batch process multiple reel URLs",
            "Comprehensive data: play count, likes, comments, captions",
            "CSV export functionality",
            "Modern dark theme UI"
        ]
    }
}

def get_version_info():
    """Get current version information"""
    return {
        "version": VERSION,
        "build_date": BUILD_DATE,
        "changelog": CHANGELOG[VERSION]
    }
