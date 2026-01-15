# STS Trading Journal 🚀

**Lightning-fast trading journal** – Track, analyze, and master your trades like never before.

## ✨ Features

- **Trade Management**: Full CRUD, partial closes with auto-RR calculation, parent/child relationships, Excel import/export
- **Analytics**: Win rate, RR stats (avg/median/max), Long/Short ratios, HTF/MTF/LTF performance, interactive charts
- **Journaling**: Daily/Weekly/Monthly entries with calendar view and trade integration
- **Media**: Multi-image gallery, video support, knowledge base (articles + files)
- **Productivity**: Todo lists (tickers/tasks), rich notes (pinned/colors), trading rules organizer
- **Security**: Bcrypt auth, CSRF protection, CSP headers, rate limiting ready

## 🚀 Quick Start (2 minutes)

```bash
git clone https://github.com/yourusername/Personal-Trading-Journal.git
cd sts-trading-journal
pip install -r requirements.txt
cp config.ini.example config.ini
python app.py

Auto-creates:

SQLite database (data.db)
Admin: admin@admin.com / 12345678
Open: http://127.0.0.1:5000

📱 Key Features Demo
💰 Monthly RR tracking
📊 Precise win rate 
⏱️ Average trade duration
🏆 Highest RR trades
🔥 Most traded tickers
🛠️ Tech Stack
Backend: Flask + SQLite (WAL mode) + Pandas
Images: Pillow (2K auto-compress)
Security: Bcrypt + CSRF + CSP headers
Performance: 20+ indexes + LRU caching
Frontend: Vanilla HTML/CSS/JS
📁 File Structure
├── app.py              # Main app (all routes)
├── data.db            # Auto SQLite DB
├── static/uploads/    # Images/videos
├── templates/         # HTML templates
├── config.ini         # Secret key
└── requirements.txt
🔒 Admin Setup
Login: admin@admin.com / 12345678
Settings: /settings (change email/password)

🎯 Production Ready
512MB file uploads with validation
Image compression (max 2K width)
WAL SQLite (production optimized)
Security headers (XSS/CSP protection)
Pagination + infinite scroll gallery
Session security (12hr lifetime)
📊 Screenshot


🤝 Contributing
Fork + clone
pip install -r requirements.txt
Create feature branch
Test: python app.py
PR with description
