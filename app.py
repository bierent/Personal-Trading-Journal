# STS Trading Journal - Built by a legend in 2025
# Lightning fast, faster than these other tradesystems

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify, g
import sqlite3
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from functools import wraps, lru_cache
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter
import pandas as pd
from datetime import datetime
import io
import math
from datetime import datetime, timedelta, date
import configparser
import re
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, CSRFError
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length


from PIL import Image
import io
import time


import calendar
import logging
from logging.handlers import RotatingFileHandler
import json



app = Flask(__name__)
csrf = CSRFProtect(app)

handler = RotatingFileHandler('app.log', maxBytes=10000000, backupCount=5)  # 10MB per file, keep 5 backups
handler.setLevel(logging.DEBUG)  
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
app.logger.addHandler(handler)
app.logger.setLevel(logging.DEBUG)  


logging.basicConfig(handlers=[handler], level=logging.DEBUG)

app.config['SESSION_COOKIE_SAMESITE'] = "Strict"
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True 
PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
app.config['WTF_CSRF_TIME_LIMIT'] = 86400
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=7)])
    submit = SubmitField('Login')

config = configparser.ConfigParser()
config.read('config.ini')
app.secret_key = config['flask']['secret_key']
bcrypt = Bcrypt(app)
@app.context_processor
def inject_csrf_token():
    from flask_wtf.csrf import generate_csrf
    return dict(csrf_token=generate_csrf)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest': 
        return jsonify({'success': False, 'message': 'Invalid or missing CSRF token. Please refresh and try again.'}), 400
    else:  
        flash('Invalid or missing CSRF token. Please try again.', 'error')
        return redirect(request.url), 400
    
@app.after_request
def add_security_headers(response):
    # Don't add frame restrictions for PDF files
    if request.path.startswith('/static/uploads/knowledge/') and request.path.endswith('.pdf'):
        # Allow PDFs to be embedded
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net fonts.googleapis.com fonts.gstatic.com cdnjs.cloudflare.com; "
            "img-src 'self' data: blob: https:; "
            "font-src 'self' data: fonts.gstatic.com fonts.googleapis.com cdnjs.cloudflare.com cdn.jsdelivr.net; "
            "connect-src 'self'; "
            "frame-ancestors 'self';"  # Allow embedding from same origin
        )
        return response
    
    # Regular security headers for all other routes
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net fonts.googleapis.com fonts.gstatic.com cdnjs.cloudflare.com; "
        "img-src 'self' data: blob: https:; "
        "font-src 'self' data: fonts.gstatic.com fonts.googleapis.com cdnjs.cloudflare.com cdn.jsdelivr.net;"
        "connect-src 'self';" 
    )
    return response
DATABASE = 'data.db'
app.config['UPLOAD_FOLDER']= 'static/uploads'
KNOWLEDGE_UPLOAD_FOLDER = 'static/uploads/knowledge'
os.makedirs(KNOWLEDGE_UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'mp4', 'webm', 'ogg'}
app.config["MAX_CONTENT_LENGTH"] = 512*1024*1024
app.config['PERMANENT_SESSION_LIFETIME'] = 14400



limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
@limiter.limit("5 per minute") 

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    
    if form.validate_on_submit(): 
        email = form.email.data
        password = form.password.data

        email_regex = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
        if not re.match(email_regex, email):
            flash('Please enter a valid email address.', 'error')
            return render_template('login.html', form=form)  
        
        if len(password) < 7:
            flash('Password must be at least 7 characters long.', 'error')
            return render_template('login.html', form=form)

        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        user = cursor.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['username'] = email
            print("Redirecting to:", url_for('index', _external=True))
            return redirect(url_for('index', _external=True))
        else:
            flash('Invalid credentials', 'error')
            return render_template('login.html', form=form)  
    

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function



def migrate_gallery_table():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  
    cursor = conn.cursor()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='gallery'")
    if not cursor.fetchone():
        print("Gallery table does not exist yet. Skipping migration.")
        conn.close()
        return
 
    cursor.execute("SELECT id, image_path FROM gallery")
    rows = cursor.fetchall()
    updated = False
    for row in rows:
        image_path = row['image_path']
        if image_path:  # Skip if null/empty
            try:
                json.loads(image_path)  # If it's already valid JSON, skip
            except json.JSONDecodeError:
                json_paths = json.dumps([image_path])
                cursor.execute("UPDATE gallery SET image_path = ? WHERE id = ?", (json_paths, row['id']))
                updated = True
    
    conn.commit()
    conn.close()
    if updated:
        print("Gallery table migrated to support multi-images in image_path.")
    else:
        print("Gallery table already supports multi-images.")
    
     
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    migrate_gallery_table()
    
 


    cursor.execute('''CREATE TABLE IF NOT EXISTS trades (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    symbol TEXT NOT NULL, 
                    open_time TEXT,
                    close_time TEXT,
                    type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    sort TEXT NOT NULL,
                    open_price REAL,
                    close_price REAL,
                    risk REAL,
                    SL REAL,
                    TP REAL,
                    RR REAL,
                    reason TEXT,
                    feedback TEXT,
                    reason_image TEXT,
                    feedback_image TEXT,
                    parent_id INTEGER)''')

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_parent_id ON trades(parent_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_open_time ON trades(open_time)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_status ON trades(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_symbol ON trades(symbol)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sort ON trades(sort)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_parent_id ON trades(parent_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_parent_open ON trades(parent_id, open_time DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_parent_status ON trades(parent_id, status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_close_time ON trades(close_time)")

    cursor.execute("""CREATE TABLE IF NOT EXISTS spot_trades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
                    symbol TEXT NOT NULL, 
                    open_time TEXT,
                    close_time TEXT,
                    status TEXT NOT NULL,
                    open_price REAL,
                    close_price REAL,
                    risk REAL,
                    SL REAL,
                    TP REAL,

                    reason TEXT,
                    feedback TEXT,
                    reason_image TEXT,
                    feedback_image TEXT,
                    Gain REAL,
                    parent_id INTEGER)""")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_spot_trades_symbol ON spot_trades(symbol);")
    

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS journal_entries(
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   date DATE NOT NULL,
                   entry_type TEXT NOT NULL CHECK(entry_type IN('daily', 'weekly', 'monthly')),
                   content TEXT,
                   week_start_date DATE,
                   month_start_date DATE,
                   created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                   updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='journal_entries'")
    row = cursor.fetchone()
    if row and "'monthly'" not in row[0]: 
        cursor.execute("ALTER TABLE journal_entries RENAME TO journal_entries_old")
        cursor.execute('''CREATE TABLE journal_entries(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date DATE NOT NULL,
                    entry_type TEXT NOT NULL CHECK(entry_type IN('daily', 'weekly', 'monthly')),
                    content TEXT,
                    week_start_date DATE,
                    month_start_date DATE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute("INSERT INTO journal_entries SELECT * FROM journal_entries_old") 
        cursor.execute("DROP TABLE journal_entries_old")
        print("Migrated journal_entries table: Added 'monthly' to CHECK constraint.")
    conn.commit() 

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_journal_date ON journal_entries(date)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_journal_type ON journal_entries(entry_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_journal_week ON journal_entries(week_start_date)")

    ##rules
    ##todo
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS todos1 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            list_type TEXT NOT NULL, -- 'ticker' or 'todo'
            content TEXT NOT NULL,
            completed INTEGER DEFAULT 0
        )
    ''')
    ###notes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notes1 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            content TEXT NOT NULL,
            color TEXT DEFAULT 'yellow',
            pinned INTEGER DEFAULT 0, 
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            image_url TEXT DEFAULT NULL
        )
    ''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS gallery (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT,
                    image_path TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_gallery_title ON gallery(title)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_gallery_description ON gallery(description)")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS knowledge_articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            category TEXT,
            tags TEXT,
            featured_image TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
            type TEXT
        )
    ''')
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_knowledge_title ON knowledge_articles(title)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_knowledge_category ON knowledge_articles(category)")

    cursor.executescript("""
        CREATE INDEX IF NOT EXISTS idx_trades_closed_rr ON trades(status, RR) WHERE status = 'CLOSED' AND RR IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_trades_parent_closed ON trades(parent_id, status) WHERE parent_id IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_trades_open_date ON trades(open_time);
        CREATE INDEX IF NOT EXISTS idx_trades_close_date ON trades(close_time);
        CREATE INDEX IF NOT EXISTS idx_knowledge_type ON knowledge_articles(type);
    """)

    conn.executescript("""
        -- Gallery
        CREATE INDEX IF NOT EXISTS idx_gallery_created ON gallery(created_at DESC);
        
        -- Knowledge
        CREATE INDEX IF NOT EXISTS idx_knowledge_created ON knowledge_articles(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_knowledge_type_created ON knowledge_articles(type, created_at DESC);
        
        -- Notes
        CREATE INDEX IF NOT EXISTS idx_notes_pinned_updated ON notes1(pinned DESC, updated_at DESC);
        
        -- Journal entries
        CREATE INDEX IF NOT EXISTS idx_journal_date_type ON journal_entries(date, entry_type);
        
        -- Todos
        CREATE INDEX IF NOT EXISTS idx_todos_type ON todos1(list_type);
    """)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS trading_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        category TEXT DEFAULT 'general',
        color TEXT DEFAULT 'yellow',
        pinned INTEGER DEFAULT 0,
        order_index INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_rules_category ON trading_rules(category)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_rules_pinned ON trading_rules(pinned)")
    


    user_count = cursor.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    if user_count == 0:
        default_email = 'admin@admin.com'
        default_password = '12345678'
        hashed = generate_password_hash(default_password)
        cursor.execute('INSERT INTO users (email, password) VALUES (?,?)', (default_email, hashed))

    conn.commit()
     




def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, timeout=30.0, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL;")
        g.db.execute("PRAGMA synchronous=NORMAL;")
        g.db.execute("PRAGMA cache_size=-64000;")   # 64MB cache
        g.db.execute("PRAGMA foreign_keys=ON;")
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_parent_rr_with_partials(parent, partials):
    total_realized_r = 0.0
    total_risk_closed = 0.0

    def r_multiple(sort, open_price, close_price, SL):
        if None in (open_price, close_price, SL):
            return 0.0
        try:
            if sort == 'SHORT':
                return (open_price - close_price) / (SL - open_price)
            elif sort == 'LONG':
                return (close_price - open_price) / (open_price - SL)
            else:
                return 0.0
        except ZeroDivisionError:
            return 0.0

    for partial in partials:
        if partial['status'] == 'CLOSED' and partial['close_price'] is not None and partial['risk'] is not None:
            r_mult = r_multiple(parent['sort'], partial['open_price'] or parent['open_price'], partial['close_price'], parent['SL'])
            total_realized_r += r_mult * partial['risk']
            total_risk_closed += partial['risk']

    parent_risk = parent['risk'] if parent['risk'] is not None else 0.0
    if parent['status'] == 'CLOSED' and parent['close_price'] is not None and parent_risk > 0:
        r_mult = r_multiple(parent['sort'], parent['open_price'], parent['close_price'], parent['SL'])
        total_realized_r += r_mult * parent_risk
        total_risk_closed += parent_risk

    if total_risk_closed == 0:
        return None

    return round(total_realized_r / total_risk_closed, 2)

def parse_time(s):
    if not s:
        return None
    s = s.replace('T', ' ').strip()
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None
@lru_cache(maxsize=12)
def get_trades_by_date_range_cached(start_date: str, end_date: str):
    conn = get_db()
    query = """
            SELECT *, DATE(open_time) as trade_date 
            FROM trades 
            WHERE parent_id IS NULL 
            AND open_time BETWEEN ? AND ?
            ORDER BY open_time DESC
        """
    return conn.execute(query, (start_date, end_date)).fetchall()
def compress_image(file, max_width=2000, quality=100):  #
    try:
        file.seek(0)  
        img = Image.open(file)
        file.seek(0)  
        original_format = img.format.lower() if img.format else 'jpeg'

        if original_format in ['jpg', 'jpeg'] and img.width <= max_width:
            file.seek(0)  # Return original untouched
            logging.info("Skipping compression for JPEG (no resize needed)")
            return file

        resized = False
        if img.width > max_width:
            ratio = max_width / float(img.width)
            new_height = int(float(img.height) * ratio)
            img = img.resize((max_width, new_height), Image.LANCZOS)
            resized = True
        
        output = io.BytesIO()
        
        if original_format in ['jpg', 'jpeg']:
            img.save(output, format='JPEG', quality=quality, optimize=True)
        elif original_format == 'png':
            img.save(output, format='PNG', optimize=True, compress_level=5)  
        else:

            img.save(output, format='PNG', optimize=True, compress_level=5)
        
        output.seek(0)
        return output
    except Exception as e:
        logging.error(f"Image compression failed: {e}")
        file.seek(0)  
        return file  
    

    
init_db()


@app.route('/')
@login_required
def index():
    date_filter = request.args.get('date_filter', 'last30')
    search_query = request.args.get('search', '').strip()
    
    # Pagination (highly recommended!)
    page = request.args.get('page', 1, type=int)
    per_page = 30
    offset = (page - 1) * per_page

    conn = get_db()
    params = []
    now = datetime.now()

    conditions = ["parent_id IS NULL"]
    
    # Date filters
    if date_filter == 'today':
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = now.replace(hour=23, minute=59, second=59, microsecond=999999)
        conditions.append("open_time >= ? AND open_time <= ?")
        params.extend([start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S')])
        
    elif date_filter == 'week':
        start = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=6, hours=23, minutes=59, seconds=59)
        conditions.append("open_time >= ? AND open_time <= ?")
        params.extend([start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S')])
        
    elif date_filter == 'month':
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end = (start + timedelta(days=32)).replace(day=1) - timedelta(seconds=1)
        conditions.append("open_time >= ? AND open_time <= ?")
        params.extend([start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S')])
        
    elif date_filter == 'year':
        start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        end = now.replace(month=12, day=31, hour=23, minute=59, second=59, microsecond=999999)
        conditions.append("open_time >= ? AND open_time <= ?")
        params.extend([start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S')])

    elif date_filter == 'last30':
        start = (now - timedelta(days=30)).replace(hour=0, minute=0, second=0, microsecond=0)
        conditions.append("open_time >= ?")
        params.append(start.strftime('%Y-%m-%d %H:%M:%S'))    

    # Search
    if search_query:
        search_param = f"%{search_query}%"
        search_conditions = [
            "symbol LIKE ?", "status LIKE ?", "sort LIKE ?", "type LIKE ?",
            "CAST(open_price AS TEXT) LIKE ?", "CAST(close_price AS TEXT) LIKE ?",
            "reason LIKE ?", "feedback LIKE ?"
        ]
        conditions.append(f"({' OR '.join(search_conditions)})")
        params.extend([search_param] * len(search_conditions))

    where_clause = " AND ".join(conditions)

    parent_query = f"SELECT * FROM trades WHERE {where_clause} ORDER BY id DESC"
    parents = conn.execute(parent_query, params).fetchall()[:500]

    # === Fetch partials for all parents in ONE query ===
    parent_ids = [p['id'] for p in parents]
    partials_by_parent = {}


    # 2. Fetch ALL partials in ONE query (only if needed)
    if parent_ids:
        placeholders = ','.join(['?'] * len(parent_ids))
        partials_query = "SELECT *, parent_id FROM trades WHERE parent_id IN (" + placeholders + ")"
        partial_rows = conn.execute(partials_query, parent_ids).fetchall()
        
        for row in partial_rows:
            pid = row['parent_id']
            if pid not in partials_by_parent:
                partials_by_parent[pid] = []
            partials_by_parent[pid].append(dict(row))

    # Process parents and calculate RR
    processed_parents = []
    for parent_row in parents:
        parent = dict(parent_row)
        partials = partials_by_parent.get(parent['id'], [])
        
        if partials:
            parent['calculated_RR'] = calculate_parent_rr_with_partials(parent, partials)
        else:
            parent['calculated_RR'] = parent['RR']

        if parent['status'] == 'CLOSED' and partials:
            total_closed_risk = sum(p['risk'] or 0 for p in partials if p['status'] == 'CLOSED')
            parent['risk'] = total_closed_risk or parent['risk']

        processed_parents.append(parent)



    @lru_cache(maxsize=12)
    def get_monthly_rr_cached(year_month: str):
        result = conn.execute("""
            SELECT COALESCE(SUM(RR), 0) FROM trades 
            WHERE parent_id IS NULL AND status = 'CLOSED' 
              AND strftime('%Y-%m', close_time) = ?
        """, (year_month,)).fetchone()
        return result[0]

    monthly_rr = get_monthly_rr_cached(datetime.now().strftime('%Y-%m'))
    

     

    return render_template(
        'index.html',
        trades=processed_parents,
        partials_by_parent=partials_by_parent,
        monthly_rr=monthly_rr,
        page=page,
        date_filter=date_filter,
        search=search_query or None
    )

@app.route('/spot')
@login_required
def spot():
    date_filter = request.args.get('date_filter', 'last30')
    search_query = request.args.get('search', '').strip()
    
    page = request.args.get('page', 1, type=int)
    per_page = 30
    offset = (page - 1) * per_page

    conn = get_db()
    params = []
    now = datetime.now()

    conditions = ["parent_id IS NULL"]
    
    # Date filters (same as index)
    if date_filter == 'today':
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = now.replace(hour=23, minute=59, second=59, microsecond=999999)
        conditions.append("open_time >= ? AND open_time <= ?")
        params.extend([start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S')])
        
    elif date_filter == 'week':
        start = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=6, hours=23, minutes=59, seconds=59)
        conditions.append("open_time >= ? AND open_time <= ?")
        params.extend([start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S')])
        
    elif date_filter == 'month':
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end = (start + timedelta(days=32)).replace(day=1) - timedelta(seconds=1)
        conditions.append("open_time >= ? AND open_time <= ?")
        params.extend([start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S')])
        
    elif date_filter == 'year':
        start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        end = now.replace(month=12, day=31, hour=23, minute=59, second=59, microsecond=999999)
        conditions.append("open_time >= ? AND open_time <= ?")
        params.extend([start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S')])

    elif date_filter == 'last30':
        start = (now - timedelta(days=30)).replace(hour=0, minute=0, second=0, microsecond=0)
        conditions.append("open_time >= ?")
        params.append(start.strftime('%Y-%m-%d %H:%M:%S'))    

    # Search
    if search_query:
        search_param = f"%{search_query}%"
        search_conditions = [
            "symbol LIKE ?", "status LIKE ?",
            "CAST(open_price AS TEXT) LIKE ?", "CAST(close_price AS TEXT) LIKE ?",
            "reason LIKE ?", "feedback LIKE ?"
        ]
        conditions.append(f"({' OR '.join(search_conditions)})")
        params.extend([search_param] * len(search_conditions))

    where_clause = " AND ".join(conditions)

    parent_query = f"SELECT * FROM spot_trades WHERE {where_clause} ORDER BY id DESC"
    parents = conn.execute(parent_query, params).fetchall()[:500]

    # Fetch partials for all parents in ONE query
    parent_ids = [p['id'] for p in parents]
    partials_by_parent = {}

    if parent_ids:
        placeholders = ','.join(['?'] * len(parent_ids))
        partials_query = "SELECT *, parent_id FROM spot_trades WHERE parent_id IN (" + placeholders + ")"
        partial_rows = conn.execute(partials_query, parent_ids).fetchall()
        
        for row in partial_rows:
            pid = row['parent_id']
            if pid not in partials_by_parent:
                partials_by_parent[pid] = []
            partials_by_parent[pid].append(dict(row))

    # 🚀 SPOT % GAIN CALCULATION (NEW)
    processed_parents = []
    for parent_row in parents:
        parent = dict(parent_row)
        partials = partials_by_parent.get(parent['id'], [])
        
        # SPOT % GAIN: ((close_price - open_price) / open_price) * 100
        if partials:
            # Weighted average % gain for spot with partials
            total_realized_gain_pct = 0.0
            total_risk_closed = 0.0
            
            for partial in partials:
                if partial['status'] == 'CLOSED' and partial['close_price'] is not None and partial['risk'] is not None:
                    open_p = partial['open_price'] or parent['open_price']
                    if open_p and open_p != 0:
                        pct_gain = ((partial['close_price'] - open_p) / open_p) * 100
                        total_realized_gain_pct += pct_gain * partial['risk']
                        total_risk_closed += partial['risk']
            
            parent_risk = parent['risk'] if parent['risk'] is not None else 0.0
            if parent['status'] == 'CLOSED' and parent['close_price'] is not None and parent_risk > 0:
                if parent['open_price'] and parent['open_price'] != 0:
                    pct_gain = ((parent['close_price'] - parent['open_price']) / parent['open_price']) * 100
                    total_realized_gain_pct += pct_gain * parent_risk
                    total_risk_closed += parent_risk
            
            if total_risk_closed > 0:
                parent['calculated_pct_gain'] = round(total_realized_gain_pct / total_risk_closed, 2)
            else:
                parent['calculated_pct_gain'] = None
        else:
            # Single trade % gain
            if parent['status'] == 'CLOSED' and parent['open_price'] and parent['close_price'] and parent['open_price'] != 0:
                parent['calculated_pct_gain'] = round(((parent['close_price'] - parent['open_price']) / parent['open_price']) * 100, 2)
            else:
                parent['calculated_pct_gain'] = None

        if parent['status'] == 'CLOSED' and partials:
            total_closed_risk = sum(p['risk'] or 0 for p in partials if p['status'] == 'CLOSED')
            parent['risk'] = total_closed_risk or parent['risk']

        processed_parents.append(parent)

    # 🔥 MONTHLY % GAIN (not RR anymore!)
    monthly_pct_gain_result = conn.execute("""
        SELECT COALESCE(AVG(CASE 
            WHEN open_price != 0 AND close_price IS NOT NULL THEN 
            ((close_price - open_price) / open_price) * 100 
            ELSE 0 END), 0) 
        FROM spot_trades 
        WHERE parent_id IS NULL AND status = 'CLOSED' 
          AND strftime('%Y-%m', close_time) = ?
    """, (datetime.now().strftime('%Y-%m'),)).fetchone()
    monthly_pct_gain = round(monthly_pct_gain_result[0], 2)

    return render_template(
        'spot.html',
        trades=processed_parents,
        partials_by_parent=partials_by_parent,
        monthly_pct_gain=monthly_pct_gain,  # ✅ Changed from monthly_rr
        page=page,
        date_filter=date_filter,
        search=search_query or None
    )
@app.route('/add_spot', methods=['POST'])
@login_required
def add_spot():
    symbol = request.form.get('symbol', '').upper()
    open_time = request.form.get('open_time', '').replace('T', ' ').strip()
    close_time = request.form.get('close_time', '').replace('T', ' ').strip()
    status = request.form.get('status', '').upper()
    open_price = request.form.get('open_price')
    close_price = request.form.get('close_price')
    risk = request.form.get('risk')
    SL = request.form.get('SL')
    TP = request.form.get('TP')
    reason = request.form.get('reason')
    feedback = request.form.get('feedback')

    open_dt = parse_time(open_time)
    close_dt = parse_time(close_time)
    if open_dt and close_dt and close_dt < open_dt:
        flash('Close time cannot be before open time.', 'error')
        return redirect(url_for('spot'))

    open_price = float(open_price) if open_price else None
    close_price = float(close_price) if close_price else None
    risk = float(risk) if risk else None
    SL = float(SL) if SL else None
    TP = float(TP) if TP else None

    # Spot trades use % gain, not RR
    pct_gain = None
    if close_price is not None and open_price is not None and open_price != 0:
        pct_gain = round(((close_price - open_price) / open_price) * 100, 2)

    sql = '''INSERT INTO spot_trades (symbol, open_time, close_time, status, open_price, close_price, risk, SL, TP, Gain, reason, feedback, parent_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'''

    with get_db() as conn:
        conn.execute(sql, (symbol, open_time, close_time, status, open_price, close_price, risk, SL, TP, pct_gain, reason, feedback, None))
        conn.commit()

    flash('Spot trade added!', 'success')
    return redirect(url_for('spot'))
@app.route('/edit_spot/<int:user_id>', methods=['POST'])
@login_required
def edit_spot_trade(user_id):
    try:
        conn = get_db()
        current = conn.execute('SELECT * FROM spot_trades WHERE id=?', (user_id,)).fetchone()
        if current is None:
            return jsonify({'success': False, 'message': 'Spot trade not found'})

        symbol = request.form.get('symbol', '').upper() or current['symbol']
        open_time = request.form.get('open_time', current['open_time'])
        close_time = request.form.get('close_time', current['close_time'])
        status = request.form.get('status', current['status']).upper()
        open_price = request.form.get('open_price')
        close_price = request.form.get('close_price')
        risk = request.form.get('risk')
        SL = request.form.get('SL', current['SL'])
        TP = request.form.get('TP', current['TP'])

        # Convert numeric fields
        open_price = float(open_price) if open_price else current['open_price']
        close_price = float(close_price) if close_price else current['close_price']
        risk = float(risk) if risk else current['risk']
        SL = float(SL) if SL else current['SL']
        TP = float(TP) if TP else current['TP']

        # Validate time
        open_dt = parse_time(open_time)
        close_dt = parse_time(close_time)
        if open_dt and close_dt and close_dt < open_dt:
            return jsonify({'success': False, 'message': 'Close time cannot be before open time.'})

        # Calculate % gain for spot trades
        pct_gain = None
        if close_price is not None and open_price is not None and open_price != 0:
            pct_gain = round(((close_price - open_price) / open_price) * 100, 2)

        # Update spot trade
        conn.execute('''
            UPDATE spot_trades 
            SET symbol=?, open_time=?, close_time=?, status=?, open_price=?, close_price=?, 
                risk=?, SL=?, TP=?, Gain=?
            WHERE id=?
        ''', (symbol, open_time, close_time, status, open_price, close_price, risk, SL, TP, pct_gain, user_id))
        
        conn.commit()
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    
@app.route('/delete_spot/<int:user_id>', methods=['POST'])
@login_required
def delete_spot_trade(user_id):
    try:
        with get_db() as conn:
            trade = conn.execute('SELECT * FROM spot_trades WHERE id=?', (user_id,)).fetchone()
            if not trade:
                flash('Spot trade not found.', 'error')
                return redirect(url_for('spot'))

            conn.execute('DELETE FROM spot_trades WHERE id=?', (user_id,))
            conn.commit()
        
        flash('Spot trade deleted successfully!', 'success')
        return redirect(url_for('spot'))
    except Exception as e:
        flash(f'Delete failed: {str(e)}', 'error')
        return redirect(url_for('spot'))
    

@app.route('/journal', methods=['GET', 'POST'])
@app.route('/journal/<date_str>', methods=['GET', 'POST'])
@login_required
def journal(date_str=None):

    if request.method == 'POST':
        date_str = request.form.get('date')
        entry_type = request.form.get('entry_type')
        content = request.form.get('content', '').strip()
        #print(f"Form data - date: {date_str}, type: {entry_type}, content length: {len(content)}")
        
        try:
            journal_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            if entry_type == 'weekly':
                week_start = journal_date - timedelta(days=journal_date.weekday())

            elif entry_type == 'monthly':
                month_start = journal_date.replace(day=1)
            else:
                week_start = None
                month_start = None 
        except ValueError:
            flash('Invalid date format', 'error')
            return redirect(url_for('journal'))
        
        conn = get_db()
        
        try:
            if entry_type == 'daily':
                existing = conn.execute("""
                    SELECT id FROM journal_entries 
                    WHERE date = ? AND entry_type = 'daily'
                """, (date_str,)).fetchone()
            elif entry_type == 'weekly':  
                existing = conn.execute("""
                    SELECT id FROM journal_entries 
                    WHERE week_start_date = ? AND entry_type = 'weekly'
                """, (week_start.isoformat(),)).fetchone()

            elif entry_type == 'monthly':
                existing = conn.execute("""
                    SELECT id FROM journal_entries 
                    WHERE month_start_date = ? AND entry_type = 'monthly'
                """, (month_start.isoformat(),)).fetchone()
            
            if existing:
                conn.execute("""
                    UPDATE journal_entries 
                    SET content = ?, updated_at = CURRENT_TIMESTAMP 
                    WHERE id = ?
                """, (content, existing['id']))

            else:
                if entry_type == 'daily':
                    conn.execute("""
                        INSERT INTO journal_entries (date, entry_type, content) 
                        VALUES (?, ?, ?)
                    """, (date_str, entry_type, content))
                elif entry_type == 'weekly':  
                    conn.execute("""
                        INSERT INTO journal_entries (date, entry_type, content, week_start_date) 
                        VALUES (?, ?, ?, ?)
                    """, (date_str, entry_type, content, week_start.isoformat()))
                elif entry_type == 'monthly':
                    conn.execute("""
                        INSERT INTO journal_entries (date, entry_type, content, month_start_date) 
                        VALUES (?, ?, ?, ?)
                    """, (date_str, entry_type, content, month_start.isoformat()))

            
            conn.commit()
            flash(f'{entry_type.title()} journal saved!', 'success')
        except Exception as e:
            print(f"Database error: {e}")
            flash('Error saving journal entry', 'error')

             
        
        return redirect(url_for('journal', date_str=date_str))
    
    if date_str:
        #print(f"Showing daily view for {date_str}")
        try:
            journal_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            week_start = journal_date - timedelta(days=journal_date.weekday())
            month_start = journal_date.replace(day=1)  
        except ValueError:
            flash('Invalid date format', 'error')
            return redirect(url_for('journal'))
        
 


        year_month = journal_date.strftime('%Y-%m')
        start_of_month = f"{year_month}-01"
        last_day = calendar.monthrange(journal_date.year, journal_date.month)[1]
        end_of_month = f"{year_month}-{last_day:02d}"

        # This will be cached for 32 different months → basically instant after first load
        all_month_trades = get_trades_by_date_range_cached(start_of_month + " 00:00:00", 
                                                          end_of_month + " 23:59:59")

        # Filter only today's parent trades
        trades = [t for t in all_month_trades if t['trade_date'] == date_str]

        # Keep the journal entries queries exactly as they are (they're already fast)
        conn = get_db()
        
        daily_entry = conn.execute("""
            SELECT * FROM journal_entries 
            WHERE date = ? AND entry_type = 'daily'
        """, (date_str,)).fetchone()
        
        weekly_entry = conn.execute("""
            SELECT * FROM journal_entries 
            WHERE week_start_date = ? AND entry_type = 'weekly'
        """, (week_start.isoformat(),)).fetchone()

        monthly_entry = conn.execute("""
            SELECT * FROM journal_entries 
            WHERE month_start_date = ? AND entry_type = 'monthly'
        """, (month_start.isoformat(),)).fetchone()
        
         
        
        return render_template('daily_journal.html',
                             date=journal_date,
                             date_str=date_str,
                             week_start=week_start,
                             trades=trades,
                             daily_entry=daily_entry,
                             weekly_entry=weekly_entry,
                             monthly_entry=monthly_entry)
    

    year = int(request.args.get('year', datetime.now().year))
    month = int(request.args.get('month', datetime.now().month))

    cal = calendar.monthcalendar(year, month)
    month_name = calendar.month_name[month]
    

    conn = get_db()

    trades_query = f"""
        SELECT DATE(open_time) as trade_date, COUNT(*) as trade_count,
               SUM(CASE WHEN RR > 0 THEN 1 ELSE 0 END) as wins,
               SUM(CASE WHEN RR < 0 THEN 1 ELSE 0 END) as losses
        FROM trades
        WHERE parent_id IS NULL 
        AND strftime('%Y-%m', open_time) = ?
        GROUP BY DATE(open_time)
    """
    trades_data = {}
    for row in conn.execute(trades_query, (f"{year:04d}-{month:02d}",)):
        trades_data[row['trade_date']] = {
            'count': row['trade_count'],
            'wins': row['wins'],
            'losses': row['losses']
        }

    journal_query = """
        SELECT date, entry_type, 
               CASE WHEN LENGTH(content) > 0 THEN 1 ELSE 0 END as has_content
        FROM journal_entries 
        WHERE strftime('%Y-%m', date) = ?
    """
    journal_data = {}
    for row in conn.execute(journal_query, (f"{year:04d}-{month:02d}",)):
        date_str_loop = row['date']
        if date_str_loop not in journal_data:
            journal_data[date_str_loop] = {}
        journal_data[date_str_loop][row['entry_type']] = row['has_content']
    

    prev_month = month - 1 if month > 1 else 12
    prev_year = year if month > 1 else year - 1
    next_month = month + 1 if month < 12 else 1
    next_year = year if month < 12 else year + 1
    
    return render_template('journal.html', 
                         calendar_data=cal,
                         year=year, 
                         month=month,
                         month_name=month_name,
                         trades_data=trades_data,
                         journal_data=journal_data,
                         prev_year=prev_year,
                         prev_month=prev_month,
                         next_year=next_year,
                         next_month=next_month,
                         today=date.today().isoformat())

@app.route('/analytics', methods=['GET', 'POST'])
@login_required
def analytics():
    period = request.args.get('period', 'monthly') 
    now = datetime.now()
    start_date = None
    end_date = None

    if period == 'monthly':
        start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end_date = (start_date + timedelta(days=32)).replace(day=1) - timedelta(seconds=1)
    elif period == 'last_month':
        first_of_this_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end_date = first_of_this_month - timedelta(seconds=1)
        start_date = end_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    elif period == 'yearly':
        start_date = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        end_date = now.replace(month=12, day=31, hour=23, minute=59, second=59, microsecond=999999)
    # 'all' → no filter

    filter_clause = ""
    filter_params = []
    if period != 'all':
        if start_date and end_date:
            filter_clause = "AND open_time BETWEEN ? AND ?"
            filter_params = [start_date.strftime('%Y-%m-%d %H:%M:%S'), end_date.strftime('%Y-%m-%d %H:%M:%S')]
        elif start_date:
            filter_clause = "AND open_time >= ?"
            filter_params = [start_date.strftime('%Y-%m-%d %H:%M:%S')]

    conn = get_db()

    # === TOTAL TRADES ===
    total_trades = conn.execute(f"SELECT COUNT(*) FROM trades WHERE parent_id IS NULL {filter_clause}", filter_params).fetchone()[0]

        # === CLOSED TRADES SUMMARY (NEVER SHOWS None AGAIN!) ===
    closed_raw = conn.execute(f"""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN RR > 0 THEN 1 ELSE 0 END) as wins,
            SUM(CASE WHEN RR = 0 THEN 1 ELSE 0 END) as be,
            SUM(CASE WHEN RR < 0 THEN 1 ELSE 0 END) as losses,
            SUM(RR) as sum_rr,
            AVG(RR) as avg_rr
        FROM trades 
        WHERE parent_id IS NULL AND status = 'CLOSED' AND RR IS NOT NULL {filter_clause}
    """, filter_params).fetchone()

    # Force ALL None → 0
    closed = {
        'total': closed_raw['total'] if closed_raw else 0,
        'wins': closed_raw['wins'] or 0 if closed_raw else 0,
        'be': closed_raw['be'] or 0 if closed_raw else 0,
        'losses': closed_raw['losses'] or 0 if closed_raw else 0,
        'sum_rr': closed_raw['sum_rr'] or 0 if closed_raw else 0,
        'avg_rr': closed_raw['avg_rr'] or 0 if closed_raw else 0,
    }

    closed_count = closed['total']
    win_count = closed['wins']
    loss_count = closed['losses']
    breakeven_count = closed['be']

    win_rate = round(win_count / closed_count * 100, 1) if closed_count > 0 else 0.0
    total_rr = round(closed['sum_rr'], 2)
    average_rr = round(closed['avg_rr'], 2)

        # === MEDIAN RR (100% Safe - No rowid!) ===
    median_query = f"""
        WITH ordered AS (
            SELECT RR FROM trades 
            WHERE parent_id IS NULL AND status = 'CLOSED' AND RR IS NOT NULL {filter_clause}
            ORDER BY RR
        ),
        ranked AS (
            SELECT RR,
                   ROW_NUMBER() OVER (ORDER BY RR) AS rn,
                   COUNT(*) OVER () AS cnt
            FROM ordered
        )
        SELECT AVG(RR) AS median_rr
        FROM ranked
        WHERE rn IN (FLOOR((cnt + 1)/2.0), CEIL((cnt + 1)/2.0))
    """
    median_row = conn.execute(median_query, filter_params).fetchone()
    median_rr = f"{median_row['median_rr']:.2f}" if median_row and median_row['median_rr'] else "N/A"

    # === HIGHEST RR ===
    highest_rr_row = conn.execute(f"""
        SELECT MAX(RR) FROM trades 
        WHERE parent_id IS NULL AND status = 'CLOSED' AND RR > 0 {filter_clause}
    """, filter_params).fetchone()
    highest_rr = f"{highest_rr_row[0]:.2f}" if highest_rr_row and highest_rr_row[0] else "N/A"

    # === MOST USED SYMBOL ===
    ticker = conn.execute(f"""
        SELECT symbol FROM trades 
        WHERE parent_id IS NULL AND symbol IS NOT NULL {filter_clause}
        GROUP BY symbol ORDER BY COUNT() DESC LIMIT 1
    """, filter_params).fetchone()
    most_used_ticker = ticker[0] if ticker else "N/A"

    # === LONG/SHORT ===
    ls = dict(conn.execute(f"""
        SELECT sort, COUNT(*) FROM trades 
        WHERE parent_id IS NULL AND sort IN ('LONG', 'SHORT') {filter_clause}
        GROUP BY sort
    """, filter_params).fetchall())
    long_count = ls.get('LONG', 0)
    short_count = ls.get('SHORT', 0)
    total_ls = long_count + short_count
    long_ratio = round(long_count / total_ls * 100, 1) if total_ls > 0 else 0
    short_ratio = round(short_count / total_ls * 100, 1) if total_ls > 0 else 0

    # === TYPE STATS ===
    types = ['HTF', 'MTF', 'LTF']
    trades_per_type = dict(conn.execute(f"""
        SELECT type, COUNT(*) FROM trades WHERE parent_id IS NULL {filter_clause} GROUP BY type
    """, filter_params).fetchall())
    trades_per_type_complete = {t: trades_per_type.get(t, 0) for t in types}

    type_stats = {}
    for t in types:
        row = conn.execute(f"""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN RR > 0 THEN 1 ELSE 0 END) as wins,
                SUM(RR) as rr
            FROM trades 
            WHERE parent_id IS NULL AND type = ? AND status = 'CLOSED' AND RR IS NOT NULL {filter_clause}
        """, [t] + filter_params).fetchone() or {'total':0, 'wins':0, 'rr':0}
        total = row['total']
        type_stats[t] = {
            'closed_count': total,
            'win_count': row['wins'],
            'win_rate': round(row['wins']/total*100, 1) if total > 0 else 0,
            'total_rr': round(row['rr'] or 0, 2)
        }

    long_short_per_type = {t: {'long_count': 0, 'short_count': 0} for t in types}
    for row in conn.execute(f"""
        SELECT type, sort, COUNT(*) FROM trades 
        WHERE parent_id IS NULL AND sort IN ('LONG','SHORT') {filter_clause}
        GROUP BY type, sort
    """, filter_params):
        if row['type'] in types:
            long_short_per_type[row['type']][f"{row['sort'].lower()}_count"] = row[2]

    total_rr_per_type = {t: type_stats[t]['total_rr'] for t in types}

    # === AVG DURATION ===
    duration = conn.execute(f"""
        SELECT AVG(julianday(close_time) - julianday(open_time)) * 86400 
        FROM trades WHERE parent_id IS NULL AND status = 'CLOSED' AND close_time IS NOT NULL {filter_clause}
    """, filter_params).fetchone()[0] or 0
    avg_trade_duration_days = round(duration / 86400, 1)

    # === RR CHART ===
    rr_labels = []
    rr_values = []

    if period == 'monthly':
        year, month = now.year, now.month
        days = calendar.monthrange(year, month)[1]
        rr_labels = [f"{year}-{month:02d}-{d:02d}" for d in range(1, days+1)]
        daily = dict(conn.execute("""
            SELECT DATE(close_time), SUM(RR) FROM trades 
            WHERE parent_id IS NULL AND status='CLOSED' AND strftime('%Y-%m', close_time)=?
            GROUP BY DATE(close_time)
        """, [f"{year}-{month:02d}"]))
        rr_values = [round(daily.get(d, 0) or 0, 2) for d in rr_labels]

    elif period == 'yearly':
        rr_labels = [calendar.month_abbr[i] for i in range(1,13)]
        monthly = dict(conn.execute("""
            SELECT strftime('%m', close_time), SUM(RR) FROM trades 
            WHERE parent_id IS NULL AND status='CLOSED' AND strftime('%Y', close_time)=?
            GROUP BY strftime('%m', close_time)
        """, [str(now.year)]))
        rr_values = [round(monthly.get(f"{i:02d}", 0) or 0, 2) for i in range(1,13)]

    elif period in ['last_month', 'all']:
        recent = conn.execute(f"""
            SELECT DATE(close_time), SUM(RR) FROM trades 
            WHERE parent_id IS NULL AND status='CLOSED' 
            ORDER BY close_time DESC LIMIT 30
        """).fetchall()
        for d, r in reversed(recent):
            rr_labels.append(d or "No Date")
            rr_values.append(round(r or 0, 2))

    analytics_data = {
        'total_trades': int(total_trades or 0),
        'win_count': int(win_count),
        'loss_count': int(loss_count),
        'breakeven_count': int(breakeven_count),
        'win_rate': float(win_rate),
        'total_rr': float(total_rr),
        'average_rr': float(average_rr),
        'median_rr': median_rr,
        'highest_rr': highest_rr,
        'most_used_ticker': most_used_ticker or "N/A",
        'avg_trade_duration': float(avg_trade_duration_days),
        'long_count': int(long_count),
        'short_count': int(short_count),
        'long_ratio': float(long_ratio),
        'short_ratio': float(short_ratio),
        'trades_per_type': trades_per_type_complete,
        'type_stats': type_stats,
        'long_short_per_type': long_short_per_type,
        'total_rr_per_type': total_rr_per_type,
        'rr_labels': rr_labels,
        'rr_values': rr_values,
    }

    return render_template('analytics.html', analytics_data=analytics_data, period=period)

@app.route('/rules', methods=['GET', 'POST'])
@login_required
def rules():
    return render_template('rules.html')

@app.route('/todo', methods=['GET', 'POST'])
@login_required
def todo():
    conn = get_db()

    if request.method == 'POST':
        action = request.form.get('action')
        list_type = request.form.get('list_type')
        todo_id = request.form.get('todo_id')
        content = request.form.get('content', '').strip()

        if action == 'add' and content and list_type in ['ticker', 'todo']:
            if list_type == 'ticker':
                content = content.upper()
            conn.execute('INSERT INTO todos1 (list_type, content) VALUES (?, ?)', (list_type, content))

        elif action == 'edit' and todo_id and content:
            conn.execute('UPDATE todos1 SET content=? WHERE id=?', (content, todo_id))

        elif action == 'delete' and todo_id:
            conn.execute('DELETE FROM todos1 WHERE id=?', (todo_id,))

        elif action == 'toggle' and todo_id:
            todo = conn.execute('SELECT completed FROM todos1 WHERE id=?', (todo_id,)).fetchone()
            if todo:
                new_status = 0 if todo['completed'] else 1
                conn.execute('UPDATE todos1 SET completed=? WHERE id=?', (new_status, todo_id))

        conn.commit()
        conn.close()

        # THIS IS THE KEY LINE:
        return redirect(url_for('todo'))  # Redirect after ANY POST!

    # Only runs on GET requests (initial load or after redirect)
    tickers = conn.execute('SELECT * FROM todos1 WHERE list_type="ticker" ORDER BY id').fetchall()
    todos = conn.execute('SELECT * FROM todos1 WHERE list_type="todo" ORDER BY id').fetchall()

    return render_template('todo.html', tickers=tickers, todos=todos)

@app.route('/notes', methods=['GET', 'POST'])
@login_required
def notes():
    conn = get_db()
    
    if request.method == 'POST':
        action = request.form.get('action')
        note_id = request.form.get('id')
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        color = request.form.get('color', 'yellow')

        if action == 'create' and content:
            conn.execute('INSERT INTO notes1 (title, content, color) VALUES (?, ?, ?)',
                         (title, content, color))
            conn.commit()
            flash('Note created!', 'success')
            
        elif action == 'edit' and note_id and content:
            conn.execute('UPDATE notes1 SET title=?, content=?, color=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
                         (title, content, color, note_id))
            conn.commit()
            flash('Note updated!', 'success')
            
        elif action == 'delete' and note_id:
            conn.execute('DELETE FROM notes1 WHERE id=?', (note_id,))
            conn.commit()
            flash('Note deleted!', 'success')
            
        elif action == 'pin' and note_id:
            pinned = 1 if request.form.get('pinned') == '0' else 0
            conn.execute('UPDATE notes1 SET pinned=? WHERE id=?', (pinned, note_id))
            conn.commit()

    search = request.args.get('search', '').strip()
    search_condition = ''
    params = []
    if search:
        search_condition = 'WHERE (title LIKE ? OR content LIKE ?)'
        search_param = f'%{search}%'
        params = [search_param, search_param]

    notes_list = conn.execute(f'''
        SELECT * FROM notes1 
        {search_condition}
        ORDER BY pinned DESC, updated_at DESC
    ''', params).fetchall()
     

    pinned_notes = [note for note in notes_list if note['pinned']]
    other_notes = [note for note in notes_list if not note['pinned']]

    return render_template('notes.html', pinned_notes=pinned_notes, other_notes=other_notes, search=search)



@app.route('/gallery', methods=['GET', 'POST'])
@login_required
def gallery():
    conn = get_db()
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            images = request.files.getlist('images')
            
            if not title:
                flash('Title is required', 'error')
                 
                return redirect(url_for('gallery'))  
            
            if not images or any(not allowed_file(img.filename) for img in images if img.filename):
                flash('Invalid image file(s)', 'error')
                 
                return redirect(url_for('gallery')) 
            image_paths = []
            for image in images:
                if image.filename == '': continue
                filename = secure_filename(image.filename)
                filename = f"gallery_{int(time.time())}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image.save(filepath)
                image_paths.append(filename)
            
            if not image_paths:
                flash('At least one image required', 'error')
                 
                return redirect(url_for('gallery')) 
            
            json_paths = json.dumps(image_paths)
            conn.execute('INSERT INTO gallery (title, description, image_path) VALUES (?, ?, ?)',
                         (title, description, json_paths))
            conn.commit()
            flash('Post added successfully!', 'success')
             
            return redirect(url_for('gallery'))
        
        elif action == 'edit':
            img_id = request.form.get('id')
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            if img_id and title:
                conn.execute('UPDATE gallery SET title=?, description=? WHERE id=?',
                             (title, description, img_id))
                conn.commit()
                flash('Post updated successfully!', 'success')
                 
                return redirect(url_for('gallery'))
            else:
                flash('Invalid edit data', 'error')
                 
                return redirect(url_for('gallery'))  
        
        elif action == 'delete':
            img_id = request.form.get('id')
            if img_id:
                img = conn.execute('SELECT image_path FROM gallery WHERE id=?', (img_id,)).fetchone()
                if img and img['image_path']:
                    try:
                        paths = json.loads(img['image_path'])
                    except json.JSONDecodeError:
                        paths = [img['image_path']]
                    for path in paths:
                        try:
                            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], path))
                        except OSError:
                            pass
                conn.execute('DELETE FROM gallery WHERE id=?', (img_id,))
                conn.commit()
                flash('Post deleted successfully!', 'success')
                 
                return redirect(url_for('gallery'))
            else:
                flash('Invalid delete request', 'error')
                 
                return redirect(url_for('gallery'))  
       
        flash('Invalid action', 'error')
         
        return redirect(url_for('gallery'))

    page = request.args.get('page', 1, type=int)
    per_page = 24  # 4×6 grid looks perfect
    offset = (page - 1) * per_page
    search = request.args.get('search', '').strip()

    where_clause = ""
    search_params = []
    if search:
        where_clause = "WHERE (title LIKE ? OR description LIKE ?)"
        search_param = f"%{search}%"
        search_params = [search_param, search_param]

    # Count total for pagination
    count_query = f"SELECT COUNT(*) as total FROM gallery {where_clause}"
    total = conn.execute(count_query, search_params).fetchone()['total']
    total_pages = math.ceil(total / per_page)

    # Fetch current page
    query = f"""
        SELECT * FROM gallery {where_clause}
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    """
    all_params = search_params + [per_page, offset]  # This creates all_params
    rows = conn.execute(query, all_params).fetchall()

    images = []
    for row in rows:
        try:
            paths = json.loads(row['image_path']) if row['image_path'] else []
        except json.JSONDecodeError:
            paths = [row['image_path']] if row['image_path'] else []
        images.append({
            'id': row['id'],
            'title': row['title'],
            'description': row['description'],
            'image_path': paths,
            'created_at': row['created_at']
        })

    # AJAX request for "Load More"
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'images': images,
            'has_more': page < total_pages,
            'next_page': page + 1 if page < total_pages else None
        })

    return render_template('gallery.html',
                           images=images,
                           page=page,
                           total_pages=total_pages,
                           has_more=page < total_pages,
                           search=search)


@app.route('/knowledge', methods=['GET', 'POST'])
@app.route('/knowledge/<int:article_id>', methods=['GET', 'POST'])
@login_required
def knowledge(article_id=None):
    conn = get_db()

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        action = request.form.get('action') or request.args.get('action')
        
        if action == 'get_article':
            article = conn.execute('SELECT * FROM knowledge_articles WHERE id = ?', 
                                  (request.args.get('id'),)).fetchone()
            if article:
                 
                return jsonify({
                    'id': article['id'],
                    'title': article['title'],
                    'content': article['content'],
                    'category': article['category'],
                    'tags': article['tags'],
                    'featured_image': article['featured_image'],
                    'type': article['type'] or 'document',  # Fallback
                    'created_at': article['created_at'][:10] if article['created_at'] else '',
                    'updated_at': article['updated_at'][:10] if article['updated_at'] else ''
                })
             
            return jsonify({'error': 'Article not found'}), 404
        
        elif action == 'delete':
            try:
                del_article_id = request.form.get('id')
                article = conn.execute('SELECT featured_image FROM knowledge_articles WHERE id = ?', 
                                      (del_article_id,)).fetchone()
                
                if article and article['featured_image']:
                    try:
                        os.remove(os.path.join(KNOWLEDGE_UPLOAD_FOLDER, article['featured_image']))
                    except OSError:
                        pass
                
                conn.execute('DELETE FROM knowledge_articles WHERE id = ?', (del_article_id,))
                conn.commit()
                 
                return jsonify({'success': True})
            except Exception as e:
                 
                return jsonify({'success': False, 'error': str(e)}), 500
        
        elif action == 'edit':
            try:
                edit_article_id = request.form.get('id')
                title = request.form.get('title', '').strip()
                content = request.form.get('content', '')
                category = request.form.get('category', '')
                tags = request.form.get('tags', '')
                entry_type = request.form.get('type', 'document')
                
                if not title:
                    return jsonify({'success': False, 'error': 'Title is required'}), 400
                
                conn.execute('''
                    UPDATE knowledge_articles 
                    SET title=?, content=?, category=?, tags=?, type=?, updated_at=CURRENT_TIMESTAMP
                    WHERE id=?
                ''', (title, content, category, tags, entry_type, edit_article_id))
                conn.commit()
                 
                return jsonify({'success': True})
            except Exception as e:
                 
                return jsonify({'success': False, 'error': str(e)}), 500

    if request.method == 'POST' and not request.headers.get('X-Requested-With'):
        action = request.form.get('action')
        entry_type = request.form.get('type', 'document')  
        
        if action in ['upload', 'edit']:
            title = request.form.get('title', '').strip()
            content = request.form.get('content', '')
            category = request.form.get('category', '')
            tags = request.form.get('tags', '')
            
            if not title:
                flash('Title is required', 'error')
                 
                return redirect(url_for('knowledge'))
            
            file = request.files.get('file')
            filename = None
            if file and file.filename:
                file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
                allowed_extensions = {'pdf', 'mp4', 'webm', 'ogg', 'avi', 'mov', 'png', 'jpg', 'jpeg', 'gif'}
                if file_ext not in allowed_extensions:
                    flash('Invalid file type', 'error')
                     
                    return redirect(url_for('knowledge'))
                
                filename = secure_filename(file.filename)
                timestamp = int(time.time())
                filename = f"{timestamp}_{filename}"
                filepath = os.path.join(KNOWLEDGE_UPLOAD_FOLDER, filename)
                os.makedirs(KNOWLEDGE_UPLOAD_FOLDER, exist_ok=True)
                
                try:
                    with open(filepath, 'wb') as f:
                        while True:
                            chunk = file.stream.read(1024 * 1024)  
                            if not chunk:
                                break
                            f.write(chunk)
                except Exception as e:
                    flash(f'Upload failed: {str(e)}', 'error')
                     
                    return redirect(url_for('knowledge'))
            
            if action == 'upload':
                created_at = datetime.utcnow().isoformat()
                conn.execute('''
                    INSERT INTO knowledge_articles (title, content, category, tags, featured_image, created_at, type)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (title, content, category, tags, filename, created_at, entry_type))
                conn.commit()
                flash('Entry added successfully!', 'success')
            
            elif action == 'edit' and article_id:
                sql = '''
                    UPDATE knowledge_articles 
                    SET title=?, content=?, category=?, tags=?, type=?, updated_at=CURRENT_TIMESTAMP
                '''
                params = [title, content, category, tags, entry_type]
                if filename:  
                    old_article = conn.execute('SELECT featured_image FROM knowledge_articles WHERE id=?', (article_id,)).fetchone()
                    if old_article and old_article['featured_image']:
                        try:
                            os.remove(os.path.join(KNOWLEDGE_UPLOAD_FOLDER, old_article['featured_image']))
                        except OSError:
                            pass
                    sql += ', featured_image=?'
                    params.append(filename)
                sql += ' WHERE id=?'
                params.append(article_id)
                conn.execute(sql, params)
                conn.commit()
                flash('Entry updated successfully!', 'success')
            
             
            return redirect(url_for('knowledge'))

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    query = 'SELECT * FROM knowledge_articles WHERE 1=1'
    params = []

    if search:
        query += ' AND (title LIKE ? OR content LIKE ? OR tags LIKE ?)'
        search_param = f'%{search}%'
        params.extend([search_param, search_param, search_param])

    if category_filter:
        query += ' AND category LIKE ?'
        params.append(f'%{category_filter}%')

    query += ' ORDER BY created_at DESC'

    articles = conn.execute(query, params).fetchall()

    categories_result = conn.execute('''
        SELECT category FROM knowledge_articles 
        WHERE category IS NOT NULL AND category != ''
    ''').fetchall()

    all_categories = set()
    for row in categories_result:
        all_categories.update(c.strip() for c in row['category'].split(',') if c.strip())

    categories = sorted(all_categories)

    selected_article = None
    if article_id:
        selected_article = conn.execute('SELECT * FROM knowledge_articles WHERE id = ?', 
                                       (article_id,)).fetchone()

    articles_list = []
    for article in articles:
        article_dict = {
            'id': article['id'],
            'title': article['title'],
            'content': article['content'],
            'category': article['category'],
            'tags': article['tags'],
            'featured_image': article['featured_image'],
            'created_at': article['created_at'],
            'type': article['type'] or 'document'  
        }
        articles_list.append(article_dict)

  
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'articles': articles_list})

    return render_template('knowledge.html', 
                           articles=articles_list,
                           categories=categories,
                           search=search,
                           selected_category=category_filter,
                           selected_article=selected_article)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    APP_VERSION = datetime.now().strftime('%B %d, %Y')
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    user = cursor.execute('SELECT * FROM users LIMIT 1').fetchone()

    if request.method == 'POST':
        if 'new_email' in request.form:
            new_email = request.form['new_email']
            cursor.execute('UPDATE users SET email = ? WHERE id = ?', (new_email, user['id']))
            conn.commit()
            flash('Email updated successfully!', 'success')
            session['username'] = new_email
            return redirect(url_for('settings'))
        elif 'current_password' in request.form:
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            
            if not check_password_hash(user['password'], current_password):
                flash('Current password is incorrect.', 'danger')
            elif new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
            else:
                hashed = generate_password_hash(new_password)
                cursor.execute('UPDATE users SET password = ? WHERE id = ?', (hashed, user['id']))
                conn.commit()
                flash('Password changed successfully!', 'success')
            return redirect(url_for('settings'))
        
    
    return render_template('settings.html', user=user, app_version=APP_VERSION)

@app.route('/toggle_theme', methods=['POST'])
@login_required
def toggle_theme():
    current = session.get('theme', 'light')
    session['theme'] = 'dark' if current == 'light' else 'light'
    return redirect(request.referrer or url_for('index'))

@app.route('/add', methods=['POST'])
@login_required
def add_trade():
    
    symbol = request.form.get('symbol', '').upper()
    open_time = request.form.get('open_time', '').replace('T', ' ').strip()
    close_time = request.form.get('close_time', '').replace('T', ' ').strip()
    type = request.form.get('type', '')
    status = request.form.get('status', '').upper()
    sort = request.form.get('sort', '').upper()
    open_price = request.form.get('open_price')
    close_price = request.form.get('close_price')
    risk = request.form.get('risk')
    SL = request.form.get('SL')
    TP = request.form.get('TP')
    reason = request.form.get('reason')
    feedback = request.form.get('feedback')

    open_dt = parse_time(open_time)
    close_dt = parse_time(close_time)
    if open_dt and close_dt and close_dt < open_dt:
        flash('Close time cannot be before open time.', 'error')
        return redirect(url_for('index'))

    open_price = float(open_price) if open_price else None
    close_price= float(close_price) if close_price else None
    risk = float(risk) if risk else None
    SL = float(SL) if SL else None
    TP = float(TP) if TP else None
    
    RR = ((close_price-open_price)/(open_price-SL)) if (close_price is not None) else None

    sql = '''INSERT INTO trades (symbol, open_time, close_time, type, status, sort, open_price, close_price, risk, SL, TP, RR, reason, feedback)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'''

    with get_db() as conn:
        conn.execute(sql, (symbol, open_time, close_time, type, status, sort, open_price, close_price, risk, SL, TP, RR, reason, feedback))    
        conn.commit()
     
    flash('Trade added!', 'success')
    return redirect(url_for('index'))


@app.route('/edit/<int:user_id>', methods=['POST'])
@login_required
def edit_trade(user_id):
    try: 

        conn = get_db()
        current = conn.execute('SELECT * FROM trades WHERE id=?', (user_id,)).fetchone()
        if current is None:
            return {'success': False, 'message': 'Trade not found'}

        symbol = request.form.get('symbol', '').upper()
        open_time = request.form.get('open_time', '')
        close_time = request.form.get('close_time', '')
        type = request.form.get('type', '')
        status = request.form.get('status', '').upper()
        sort = request.form.get('sort', '').upper()
        open_price = request.form.get('open_price')
        close_price = request.form.get('close_price')
        risk = request.form.get('risk')
        SL = request.form.get('SL')
        TP = request.form.get('TP')
        reason = request.form.get('reason')
        feedback = request.form.get('feedback')

        symbol = symbol if symbol else current['symbol']
        open_time = open_time if open_time else current['open_time']
        close_time = close_time if close_time else current['close_time']
        type = type if type else current['type']
        status = status if status else current['status']
        sort = sort if sort else current['sort']
        reason = reason if reason else current['reason']
        feedback = feedback if feedback else current['feedback']

        open_price = float(open_price) if open_price else current['open_price']
        close_price = float(close_price) if close_price else current['close_price']
        risk = float(risk) if risk else current['risk']
        SL = float(SL) if SL else current['SL']
        TP = float(TP) if TP else current['TP']

        open_dt = parse_time(open_time)
        close_dt = parse_time(close_time)
        if open_dt and close_dt and close_dt < open_dt:
            return {'success': False, 'message': 'Close time cannot be before open time.'}

        if current['parent_id']:
            parent = conn.execute('SELECT * FROM trades WHERE id=?', (current['parent_id'],)).fetchone()
            if parent:
                old_risk = current['risk'] if current['risk'] is not None else 0
                new_risk = risk if risk is not None else 0
                risk_diff = new_risk - old_risk
                
                parent_new_risk = (parent['risk'] if parent['risk'] is not None else 0) + risk_diff
                
                if parent_new_risk <= 0 and parent['status'] != 'CLOSED':
                    from datetime import datetime
                    parent_close_time = datetime.now().strftime('%Y-%m-%d %H:%M')
                    parent_status = 'CLOSED'
                else:
                    parent_close_time = parent['close_time']
                    parent_status = parent['status']
                
                if parent_new_risk <= 0 and parent['status'] != 'CLOSED':
                    conn.execute('''
                        UPDATE trades SET risk=?, status=?, close_time=? WHERE id=?
                    ''', (max(0, parent_new_risk), parent_status, parent_close_time, parent['id']))
                else:
                    conn.execute('''
                        UPDATE trades SET risk=? WHERE id=?
                    ''', (parent_new_risk, parent['id']))

        if current['parent_id']:
            parent = conn.execute('SELECT * FROM trades WHERE id=?', (current['parent_id'],)).fetchone()
            if parent and close_price is not None and parent['SL'] is not None:
                if parent['sort'] == 'LONG':
                    RR = ((close_price - open_price) / (open_price - parent['SL']))
                elif parent['sort'] == 'SHORT':
                    RR = ((open_price - close_price) / (parent['SL'] - open_price))
                else:
                    RR = current['RR']
            else:
                RR = current['RR']
        else:
            RR = ((close_price-open_price)/(open_price-SL)) if (close_price is not None and SL is not None and open_price is not None) else current['RR']

        conn.execute('''UPDATE trades SET symbol=?, open_time=?, close_time=?, type=?, status=?, sort=?, open_price=?, close_price=?, risk=?, SL=?, TP=?, RR=?, reason=?, feedback=? WHERE id=?''', 
                    (symbol, open_time, close_time, type, status, sort, open_price, close_price, risk, SL, TP, RR, reason, feedback, user_id))
        
        if current['parent_id']:
            parent = conn.execute('SELECT * FROM trades WHERE id=?', (current['parent_id'],)).fetchone()
            if parent:
                all_partials = conn.execute('SELECT * FROM trades WHERE parent_id=?', (parent['id'],)).fetchall()
                parent_rr = calculate_parent_rr_with_partials(parent, all_partials)
                #print("Parent RR recalculated:", parent_rr)
                conn.execute(f'UPDATE trades SET RR=? WHERE id=?', (parent_rr, parent['id']))
        
        conn.commit()
         
        return {'success': True}
    
    except Exception as e:
        return {'success': False, 'message': str(e)}
    
@app.route('/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_trade(user_id):

    with get_db() as conn:
        trade = conn.execute('SELECT * FROM trades WHERE id=?', (user_id,)).fetchone()
        if not trade:
            flash('Trade not found.', 'error')
            return redirect(url_for('index'))

        parent_id = trade['parent_id']

        conn.execute('DELETE FROM trades WHERE id=?', (user_id,))

        if parent_id:
            parent = conn.execute('SELECT * FROM trades WHERE id=?', (parent_id,)).fetchone()
            if parent:
                all_partials = conn.execute('SELECT * FROM trades WHERE parent_id=?', (parent_id,)).fetchall()
                parent_rr = calculate_parent_rr_with_partials(parent, all_partials)
                conn.execute('UPDATE trades SET RR=? WHERE id=?', (parent_rr, parent_id))

        conn.commit()
    flash('Trade deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/import', methods=['POST'])
@login_required
def import_trades():
    if 'import_file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('index'))
    file = request.files['import_file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('index'))
    if not file.filename.endswith('.xlsx'):
        flash('Only .xlsx files are supported', 'error')
        return redirect(url_for('index'))
    try:
        df = pd.read_excel(file)
        required_columns = ['symbol', 'open_time', 'status', 'sort', 'open_price', 'risk']
        allowed_columns = [
            'id', 'symbol', 'open_time', 'close_time', 'type', 'status', 'sort', 'open_price', 'close_price', 'risk',
            'SL', 'TP', 'RR', 'reason', 'feedback', 'reason_image', 'feedback_image', 'parent_id'
        ]
        missing = [col for col in required_columns if col not in df.columns]
        if missing:
            flash("Missing required columns: {', '.join(missing)}", 'error')
            return redirect(url_for('index'))
        
        df = df[[col for col in allowed_columns if col in df.columns]]

        for col in allowed_columns:
            if col not in df.columns:
                df[col] = None

        def excel_date_to_str(val):
            if pd.isnull(val):
                return None
            if isinstance(val, float) or isinstance(val, int):
                try:
                    return pd.to_datetime('1899-12-30') + pd.to_timedelta(val, 'D')
                except Exception:
                    return None
            try:
                dt = pd.to_datetime(val, errors='coerce')
                if pd.isnull(dt):
                    return None
                return dt.strftime('%Y-%m-%d %H:%M')
            except Exception:
                return None

        for col in ['open_time', 'close_time']:
            if col in df.columns:
                df[col] = df[col].apply(excel_date_to_str)
        
        df = df[
            df['symbol'].notnull() & (df['symbol'].astype(str).str.strip() != '') &
            df['sort'].notnull() & (df['sort'].astype(str).str.strip() != '')
        ]

        numeric_cols = ['risk', 'SL', 'TP', 'pnl', 'RR']
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')
                df[col] = df[col].apply(lambda x: int(x) if pd.notnull(x) and float(x).is_integer() else (float(x) if pd.notnull(x) else None))

        if 'parent_id' in df.columns:
            df['parent_id'] = pd.to_numeric(df['parent_id'], errors='coerce')
        else:
            df['parent_id'] = None

        df['excel_id'] = df['id'] 

        parents_df = df[df['parent_id'].isnull()].copy()
        partials_df = df[df['parent_id'].notnull()].copy()

        parents_df = parents_df.sort_values(by='excel_id', ascending=True)
        partials_df = partials_df.sort_values(by='excel_id', ascending=True)

        conn = get_db()
        conn.execute('PRAGMA foreign_keys = ON')
        parent_id_map = {}
        parent_count = 0
        partial_count = 0
        

        for _, row in parents_df.iterrows():
            excel_id = row['excel_id']
            if pd.isnull(excel_id):
                continue
            excel_id = int(excel_id)
            cursor = conn.execute('''
                INSERT INTO trades (symbol, open_time, close_time, type, status, sort, open_price, close_price, risk, SL, TP, RR, reason, feedback, reason_image, feedback_image, parent_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                row['symbol'], row['open_time'], row['close_time'], row['type'], row['status'], row['sort'],
                row['open_price'], row['close_price'], row['risk'], row['SL'], row['TP'], row['RR'], row['reason'], row['feedback'], row['reason_image'], row['feedback_image'], None
            ))
            db_id = cursor.lastrowid
            parent_id_map[excel_id] = db_id
            parent_count += 1

        for _, row in partials_df.iterrows():
            old_parent_id = row['parent_id']
            if pd.isnull(old_parent_id):
                continue
            old_parent_id = int(old_parent_id)
            db_parent_id = parent_id_map.get(old_parent_id)
            if db_parent_id is None:
                continue 
            conn.execute('''
                INSERT INTO trades (symbol, open_time, close_time, type, status, sort, open_price, close_price, risk, SL, TP, RR, reason, feedback, reason_image, feedback_image, parent_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                row['symbol'], row['open_time'], row['close_time'], row['type'], row['status'], row['sort'],
                row['open_price'], row['close_price'], row['risk'], row['SL'], row['TP'],  row['RR'], row['reason'], row['feedback'], row['reason_image'], row['feedback_image'], db_parent_id
            ))
            partial_count += 1

        conn.commit()
         
        
        total_imported = parent_count + partial_count
        flash(f'Imported {total_imported} trades successfully! ({parent_count} parent trades, {partial_count} partial trades)', 'success')
    except Exception as e:
        flash(f'Import failed: {e}', 'error')
    return redirect(url_for('index'))

@app.route('/export')
@login_required
def export_trades():
    conn = get_db()
    df = pd.read_sql_query('SELECT * FROM trades ORDER BY id DESC', conn)
     

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Trades')
    output.seek(0)

    return send_file(output, download_name="trades_export.xlsx", as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/partial_close_inline/<int:parent_id>', methods=['POST'])
@login_required
def partial_close_inline(parent_id):
    with get_db() as conn:
        parent_trade = conn.execute('SELECT * FROM trades WHERE id=?', (parent_id,)).fetchone()
        if parent_trade is None:
            flash('Parent trade not found', 'error')
            return redirect(url_for('index'))

        risk = request.form.get('risk')
        status = request.form.get('status', '').upper()
        risk = float(risk) if risk else None

        reason = request.form.get('reason', '')
        feedback = request.form.get('feedback', '')

        if status not in ('OPEN', 'CLOSED'):
            flash('Invalid status', 'error')
            return redirect(url_for('index'))

        if risk is None or risk <= 0:
            flash('Risk must be provided and > 0', 'error')
            return redirect(url_for('index'))

        if status == 'OPEN':
            open_price = request.form.get('open_price')
            open_time = request.form.get('open_time')
            open_price = float(open_price) if open_price else None
            close_price = None
            close_time = None

            if open_price is None:
                flash('Open price is required for OPEN partial', 'error')
                return redirect(url_for('index'))

            RR = 0.0

            new_parent_risk = (parent_trade['risk'] if parent_trade['risk'] is not None else 0.0) + risk
            new_parent_status = parent_trade['status']
            parent_close_time = parent_trade['close_time']

        else:  
            close_price = request.form.get('close_price')
            close_time = request.form.get('close_time')
            close_price = float(close_price) if close_price else None
            open_price = parent_trade['open_price']
            open_time = None  

            if close_price is None:
                flash('Close price is required for CLOSED partial', 'error')
                return redirect(url_for('index'))

            if parent_trade['sort'] == 'LONG':
                if parent_trade['SL'] is not None:
                    denom = open_price - parent_trade['SL']
                    RR = ((close_price - open_price) / denom) if denom != 0 else 0.0
                else:
                    RR = 0.0
            elif parent_trade['sort'] == 'SHORT':
                if parent_trade['SL'] is not None:
                    denom = parent_trade['SL'] - open_price
                    RR = ((open_price - close_price) / denom) if denom != 0 else 0.0
                else:
                    RR = 0.0
            else:
                RR = 0.0

            old_parent_risk = parent_trade['risk'] if parent_trade['risk'] is not None else 0.0
            new_parent_risk = old_parent_risk - risk

            if new_parent_risk <= 0:
                new_parent_status = 'CLOSED'
                parent_close_time = parent_trade['close_time'] or datetime.now().strftime('%Y-%m-%d %H:%M')
            else:
                new_parent_status = parent_trade['status']
                parent_close_time = parent_trade['close_time']

        conn.execute('''
            INSERT INTO trades (
                symbol, open_time, close_time, type, status, sort,
                open_price, close_price, risk, SL, TP, RR,
                reason, feedback, parent_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            parent_trade['symbol'],
            open_time,
            close_time,
            parent_trade['type'],
            status,
            parent_trade['sort'],
            open_price,
            close_price,
            risk,
            parent_trade['SL'],
            parent_trade['TP'],
            RR,
            reason,
            feedback,
            parent_id
        ))

        if status == 'CLOSED' and new_parent_risk <= 0:
            conn.execute('''
                UPDATE trades
                SET risk = ?, status = ?, close_time = ?
                WHERE id = ?
            ''', (
                max(0.0, new_parent_risk),
                new_parent_status,
                parent_close_time,
                parent_id
            ))
        else:
            conn.execute('''
                UPDATE trades
                SET risk = ?, status = ?
                WHERE id = ?
            ''', (
                new_parent_risk,
                new_parent_status,
                parent_id
            ))

        updated_parent = conn.execute('SELECT * FROM trades WHERE id=?', (parent_id,)).fetchone()
        all_partials = conn.execute('SELECT * FROM trades WHERE parent_id=?', (parent_id,)).fetchall()

        parent_rr = calculate_parent_rr_with_partials(updated_parent, all_partials)

        conn.execute('UPDATE trades SET RR=? WHERE id=?', (parent_rr, parent_id))

        conn.commit()

    flash('Partial trade added!', 'success')
    return redirect(url_for('index'))


@app.route('/user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def user_detail(user_id):
    conn = get_db()
    user = conn.execute('SELECT * FROM trades WHERE id = ?', (user_id,)).fetchone()

    if user is None:
        flash('Not found', 'error')
         
        return redirect(url_for('index'))

    if request.method == 'POST':
        reason = request.form.get('reason', user['reason'])
        feedback = request.form.get('feedback', user['feedback'])

        delete_reason = request.form.get('delete_reason_image') == 'true'
        delete_feedback = request.form.get('delete_feedback_image') == 'true'
  
        reason_image = request.files.get('reason_image')
        feedback_image = request.files.get('feedback_image')
 
        reason_image_filename = user['reason_image']
        feedback_image_filename = user['feedback_image']

        if delete_reason:
            if user['reason_image']:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user['reason_image']))
                except OSError:
                    pass  
            reason_image_filename = None
  
        elif reason_image and reason_image.filename != '':
            if not allowed_file(reason_image.filename):
                flash('Invalid reason image file extension', 'error')
                return redirect(url_for('user_detail', user_id=user_id))  
            if reason_image.content_type not in ['image/jpeg', 'image/png']:
                flash('Invalid reason image MIME type', 'error')
                return redirect(url_for('user_detail', user_id=user_id))  
            try:
                reason_image.seek(0) 
                test_img = Image.open(reason_image)  
                reason_image.seek(0)  
            except Exception as e:
                flash('Faulty or corrupt reason image file', 'error')
                return redirect(url_for('user_detail', user_id=user_id))  
            if user['reason_image']: 
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user['reason_image']))
                except OSError:
                    pass
            filename = secure_filename(reason_image.filename)
            filename = f"{int(time.time())}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            reason_image.save(filepath)
            reason_image_filename = filename

        if delete_feedback:
            if user['feedback_image']:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user['feedback_image']))
                except OSError:
                    pass 
            feedback_image_filename = None

        elif feedback_image and feedback_image.filename != '':
            if not allowed_file(feedback_image.filename):
                flash('Invalid feedback image file extension', 'error')
                return redirect(url_for('user_detail', user_id=user_id))  
            if feedback_image.content_type not in ['image/jpeg', 'image/png']:
                flash('Invalid feedback image MIME type', 'error')
                return redirect(url_for('user_detail', user_id=user_id))  
            try:
                feedback_image.seek(0)  
                test_img = Image.open(feedback_image)  
                feedback_image.seek(0)  
            except Exception as e:
                flash('Faulty or corrupt feedback image file', 'error')
                return redirect(url_for('user_detail', user_id=user_id))  
            if user['feedback_image']:  
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user['feedback_image']))
                except OSError:
                    pass
            filename = secure_filename(feedback_image.filename)
            filename = f"{int(time.time())}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            feedback_image.save(filepath) 
            feedback_image_filename = filename

        conn.execute('''UPDATE trades SET reason = ?, feedback = ?, reason_image = ?, feedback_image = ? WHERE id = ?''', 
                    (reason, feedback, reason_image_filename, feedback_image_filename, user_id))
        conn.commit()
         
        flash('Changes saved successfully!', 'success')
        return redirect(url_for('user_detail', user_id=user_id))  

     
    return render_template('user_detail.html', user=user)

@app.route('/statistics')
@login_required
def statistics():
    conn = get_db()
    return render_template('statistics.html', stats=stats_data)

def smart_price(value):
    try:
        if value is None:
            return ""
        val = float(value)
        if val == 0:
            return "0"
        abs_val = abs(val)
        if abs_val < 1e-6:
            return f"{val:.2e}"

        if abs_val < 0.01:
            prec = 8
        elif abs_val < 1:
            prec = 6
        elif abs_val < 10:
            prec = 5
        elif abs_val < 1000:
            prec = 3
        elif abs_val < 10000:
            prec = 2
        elif abs_val < 100000:
            prec = 1
        else:
            prec = 0

        formatted = f"{val:.{prec}f}"
        formatted = formatted.rstrip('0').rstrip('.') if '.' in formatted else formatted
        return formatted
    except Exception:
        return str(value)


app.jinja_env.filters['smart_price'] = smart_price

def get_date_filter(start_date=None, end_date=None):
    if start_date and end_date:
        return "AND close_time BETWEEN :start_date AND :end_date", {
            "start_date": start_date,
            "end_date": end_date
        }
    elif start_date:
        return "AND close_time >= :start_date", {"start_date": start_date}
    elif end_date:
        return "AND close_time <= :end_date", {"end_date": end_date}
    else:
        return "", {}





if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1',  
        port=5000,
        debug=True)
