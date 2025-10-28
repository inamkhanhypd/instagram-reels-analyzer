# Version management for Instagram Reels Analyzer
VERSION = "1.2.3"
BUILD_DATE = "2025-01-28"
CHANGELOG = {
    "1.2.3": {
        "date": "2025-01-28",
        "changes": [
            "Added development workflow with develop branch",
            "Created DEVELOPMENT.md documentation",
            "Set up proper branch strategy: develop → main → deploy",
            "Improved development process and testing workflow"
        ]
    },
    "1.2.2": {
        "date": "2025-01-28",
        "changes": [
            "Updated column names: play_count → Total Views, like_count → Total Likes, comment_count → Total Comments",
            "Added 'Top 5 Media' text in Analyze Profile section for better clarity",
            "Consistent column naming across both Analyze Profile and Analyze Reels sections",
            "Improved user experience with clearer data labels"
        ]
    },
    "1.2.1": {
        "date": "2025-01-28",
        "changes": [
            "Moved CSV upload functionality from Analyze Profile to Analyze Reels section",
            "CSV upload now correctly placed in the reel analysis workflow",
            "Maintained two options in Analyze Reels: CSV upload or manual input",
            "Analyze Profile section now focuses solely on username-based analysis"
        ]
    },
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
