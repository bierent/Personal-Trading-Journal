STS Trading Journal
<div align="center">
Python
Flask
SQLite
License

A comprehensive, self-hosted trading journal for serious traders

Track trades, analyze performance, and improve your trading strategy

</div>
📸 Features
📊 Trade Management
Futures/Margin Trading - Full support with automatic R:R calculation
Spot Trading - Track spot positions with percentage gain tracking
Partial Close Support - Scale out of positions with accurate P&L tracking
Parent-Child Relationships - Link partial takes to parent trades
Multi-Timeframe Tagging - Categorize trades as HTF, MTF, or LTF
📈 Analytics Dashboard
Win rate & loss rate statistics
Total, average, and median R:R
Long/Short ratio analysis
Performance by trade type
Average trade duration
Interactive charts with daily/monthly views
Period filtering (Today, Week, Month, Year, All-time)
📅 Trading Journal
Daily Entries - Document your daily trading thoughts
Weekly Reviews - Summarize weekly performance
Monthly Recaps - Track long-term progress
Calendar View - Visual overview with trade activity indicators
🖼️ Gallery
Upload trade screenshots and charts
Multi-image support per entry
Search and filter functionality
Infinite scroll pagination
📚 Knowledge Base
Create articles and trading notes
Category and tag organization
Support for PDFs, videos, and images
Full-text search
📝 Additional Tools
Sticky Notes - Quick notes with color coding and pin support
Watchlist - Track tickers of interest
Todo List - Trading task management
Trading Rules - Document and reference your trading rules
🔒 Security
CSRF protection
Rate limiting on sensitive endpoints
Secure session management
Password hashing with bcrypt
Security headers (XSS, CSP, etc.)
🚀 Quick Start
Prerequisites
Python 3.8+
pip
Installation
Bash

# Clone the repository
git clone https://github.com/yourusername/sts-trading-journal.git
cd sts-trading-journal

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create config file
cp config.example.ini config.ini
# Edit config.ini and add your secret key

# Run the application
python app.py
Default Login
Email: admin@admin.com
Password: 12345678
⚠️ Important: Change these credentials immediately after first login!

📦 Dependencies
text

Flask
Flask-WTF
Flask-Bcrypt
Flask-Limiter
Werkzeug
pandas
openpyxl
Pillow
📁 Project Structure
text

sts-trading-journal/
├── app.py                 # Main application
├── config.ini             # Configuration file
├── data10.db              # SQLite database
├── static/
│   ├── uploads/           # User uploads
│   │   └── knowledge/     # Knowledge base files
│   └── css/               # Stylesheets
├── templates/             # Jinja2 templates
│   ├── index.html         # Main trades view
│   ├── spot.html          # Spot trades
│   ├── journal.html       # Calendar view
│   ├── daily_journal.html # Daily entry view
│   ├── analytics.html     # Analytics dashboard
│   ├── gallery.html       # Image gallery
│   ├── knowledge.html     # Knowledge base
│   ├── notes.html         # Sticky notes
│   ├── todo.html          # Watchlist & todos
│   ├── rules.html         # Trading rules
│   └── settings.html      # User settings
└── app.log                # Application logs
