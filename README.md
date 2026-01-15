#STS Trading Journal 🚀
Lightning-fast trading journal - Track, analyze, and master your trades like never before.

✨ Features
Trade Management	Analytics & Insights	Journaling
✅ Full CRUD operations	📊 Win rate, RR, median RR	📝 Daily/Weekly/Monthly entries
✅ Partial closes with auto-RR calc	📈 Interactive charts	🗓️ Calendar integration
✅ Parent/child trade relationships	🎯 Long/Short ratios	📊 Trade stats per day
✅ Bulk import/export (Excel)	🔍 Type-based performance (HTF/MTF/LTF)	
Media & Knowledge	Productivity	Security
🖼️ Image gallery w/ multi-upload	📋 Todo lists (tickers/tasks)	🔐 User auth + bcrypt
📚 Knowledge base (articles/videos)	🗒️ Rich notes (pinned/colors)	🛡️ CSRF + security headers
🎬 Video support	📜 Trading rules organizer	⚡ Rate limiting ready
🎯 Live Demo Stats
💰 Monthly RR: Live tracking
📊 Win Rate: Precise calculations
⏱️ Avg Duration: Per timeframe
🏆 Highest RR: Track your best
🚀 Quick Start
bash
Copy
# 1. Clone & install
git clone <your-repo>
cd sts-trading-journal
pip install -r requirements.txt

# 2. Setup (auto-creates DB + admin user)
cp config.ini.example config.ini
python app.py

# 3. Login
# Email: admin@admin.com
# Password: 12345678

# 4. Open http://127.0.0.1:5000
📁 File Structure
├── app.py              # Main Flask app (all routes)
├── data.db             # SQLite DB (auto-created)
├── static/uploads/     # Images, videos, knowledge files
├── templates/          # HTML templates
├── config.ini          # Secret key (edit for production)
└── requirements.txt    # Dependencies
🛠️ Core Technologies
Backend: Flask + SQLite + Pandas + Pillow
Frontend: Vanilla HTML/CSS/JS + Jinja2
Security: Flask-Bcrypt + CSRFProtect + CSP headers
Performance: WAL mode + 20+ indexes + LRU caching
🔒 Admin Setup
Default User: admin@admin.com / 12345678
Change via /settings (password + email)
📊 Key Analytics Delivered
Never-miss RR: Handles NULL values perfectly
Partial close math: Auto-calculates parent RR
Timeframe stats: HTF/MTF/LTF win rates
Smart formatting: 1.2345 → 1.23
🌐 Production Ready
✅ Battle-tested SQLite (WAL mode, 64MB cache)
✅ Image compression (2K max width)
✅ File upload limits (512MB)
✅ Security headers (CSP, XSS, etc.)
✅ Session security (12hr lifetime)
✅ Pagination + infinite scroll
🎨 Screenshots
(Add your screenshots here - gallery, analytics dashboard, etc.)

🤝 Contributing
Fork → Clone → Create feature branch
pip install -r requirements.txt
Make changes → Test locally
PR with clear description
