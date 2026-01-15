STS Trading Journal 🚀
Lightning-fast trading journal built by a legend in 2025 – Track, analyze, and master your trades like never before.

✨ Features Overview
Trade Management	Analytics & Insights	Journaling
✅ Full CRUD operations	📊 Win rate, RR, median RR	📝 Daily/Weekly/Monthly entries
✅ Partial closes w/ auto-RR	📈 Interactive charts	🗓️ Calendar integration
✅ Parent/child relationships	🎯 Long/Short ratios	📊 Trade stats per day
✅ Bulk Excel import/export	🔍 HTF/MTF/LTF performance	
Media & Knowledge	Productivity	Security
🖼️ Multi-image gallery	📋 Todo lists (tickers/tasks)	🔐 Bcrypt + CSRF
📚 Knowledge base (videos/docs)	🗒️ Rich notes w/ pinning	🛡️ CSP headers
🎬 Full video support	📜 Trading rules organizer	⚡ Rate limiting
🚀 Quick Start (2 minutes)
bash
Copy
git clone https://github.com/yourusername/sts-trading-journal.git
cd sts-trading-journal
pip install -r requirements.txt
cp config.ini.example config.ini
python app.py
Auto-creates:

✅ SQLite database (data.db)
✅ Admin user: admin@admin.com / 12345678
Open: http://127.0.0.1:5000

📱 Live Demo Features
💰 Monthly RR: Live tracking
📊 Win Rate: Precise calculations  
⏱️ Avg Duration: Per timeframe
🏆 Highest RR: Track your best
🔥 Most traded ticker
🛠️ Tech Stack
Backend: Flask + SQLite (WAL mode) + Pandas
Images: Pillow (auto-compress 2K)
Security: Bcrypt + CSRFProtect + CSP headers
Performance: 20+ indexes + LRU cache
Frontend: Vanilla HTML/CSS/JS + Jinja2
📁 What's Included
├── app.py                 # 🔥 All routes + logic (1 file!)
├── data.db               # Auto-created SQLite
├── static/uploads/       # Images/videos/knowledge
├── templates/*.html      # Responsive UI
├── config.ini           # Edit secret_key for prod
└── requirements.txt     # pip install -r
🔒 Admin Panel
/settings - Change email/password
Default: admin@admin.com / 12345678

🎯 Key Analytics
✅ Handles NULL RR perfectly
✅ Auto-calculates partial close math
✅ Smart price formatting (1.2345 → 1.23)
✅ Timeframe stats (HTF/MTF/LTF)
✅ Median + avg + max RR
🌐 Production Ready
✅ 512MB file uploads
✅ Image compression (2K max)
✅ Session security (12hr)
✅ WAL SQLite (production)
✅ Pagination + infinite scroll
✅ Security headers (XSS/CSP)
📊 Screenshots


🤝 Contributing
git clone + pip install -r requirements.txt
Create feature branch
Test locally: python app.py
PR with description
