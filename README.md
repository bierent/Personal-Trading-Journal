# STS Trading Journal 🚀
**Lightning-fast trading journal** – Track, analyze, and master your trades like never before.
![Trading Journal Banner](https://via.placeholder.com/1200x400/1a1a2e/ffffff?text=STS+Trading+Journal)
## ✨ Features
- **Trade Management**: Full CRUD, partial closes with auto-RR calculation, parent/child relationships, Excel import/export
- **Analytics**: Win rate, RR stats (avg/median/max), Long/Short ratios, HTF/MTF/LTF performance, interactive charts
- **Journaling**: Daily/Weekly/Monthly entries with calendar view and trade integration
- **Media**: Multi-image gallery, video support, knowledge base (articles + files)
- **Productivity**: Todo lists (tickers/tasks), rich notes (pinned/colors), trading rules organizer
- **Security**: Bcrypt auth, CSRF protection, CSP headers, rate limiting ready
---
## 🚀 Quick Start (2 minutes)
```bash
pip install -r requirements.txt
cp config.ini.example config.ini
python app.py
```
**Auto-creates:**
- 📦 SQLite database (`data.db`)
- 👤 Admin: `admin@admin.com` / `12345678`
- 🌐 Open: http://127.0.0.1:5000
---
## 📱 Key Features Demo
| 💰 Monthly RR Tracking | 📊 Precise Win Rate | ⏱️ Avg Trade Duration |
|:---:|:---:|:---:|
| ![Monthly RR](https://via.placeholder.com/300x200/2d3436/ffffff?text=Monthly+RR) | ![Win Rate](https://via.placeholder.com/300x200/2d3436/ffffff?text=Win+Rate) | ![Duration](https://via.placeholder.com/300x200/2d3436/ffffff?text=Duration) |
| 🏆 Highest RR Trades | 🔥 Most Traded Tickers |
|:---:|:---:|
| ![Highest RR](https://via.placeholder.com/300x200/2d3436/ffffff?text=Highest+RR) | ![Tickers](https://via.placeholder.com/300x200/2d3436/ffffff?text=Top+Tickers) |
---
## 🛠️ Tech Stack
| Category | Technologies |
|----------|-------------|
| **Backend** | Flask + SQLite (WAL mode) + Pandas |
| **Images** | Pillow (2K auto-compress) |
| **Security** | Bcrypt + CSRF + CSP headers |
| **Performance** | 20+ indexes + LRU caching |
| **Frontend** | Vanilla HTML/CSS/JS |
---
## 📁 File Structure
```
├── app.py              # Main app (all routes)
├── data.db             # Auto SQLite DB
├── static/uploads/     # Images/videos
├── templates/          # HTML templates
├── config.ini          # Secret key
└── requirements.txt
```
---
## 🔒 Admin Setup
| Setting | Value |
|---------|-------|
| **Login** | `admin@admin.com` / `12345678` |
| **Settings** | `/settings` (change email/password) |
---
## 🎯 Production Ready
✅ 512MB file uploads with validation  
✅ Image compression (max 2K width)  
✅ WAL SQLite (production optimized)  
✅ Security headers (XSS/CSP protection)  
✅ Pagination + infinite scroll gallery  
✅ Session security (12hr lifetime)  
---
## 📊 Screenshots
<details>
<summary>Click to expand screenshots</summary>
### Dashboard
![Dashboard](https://via.placeholder.com/800x500/1a1a2e/ffffff?text=Dashboard+Screenshot)
### Trade Analytics
![Analytics](https://via.placeholder.com/800x500/1a1a2e/ffffff?text=Analytics+Screenshot)
### Journal View
![Journal](https://via.placeholder.com/800x500/1a1a2e/ffffff?text=Journal+Screenshot)
</details>
---
## 🤝 Contributing
1. Fork + clone
2. `pip install -r requirements.txt`
3. Create feature branch
4. Test: `python app.py`
5. PR with description
---
## 📄 License
MIT License - feel free to use for personal or commercial projects.
---
<p align="center">
  <b>Made with ❤️ for traders</b><br>
  ⭐ Star this repo if you find it useful!
</p>

<img width="1915" height="913" alt="image" src="https://github.com/user-attachments/assets/3b403581-7dab-4c5e-a795-e45c2d80c9d2" />
