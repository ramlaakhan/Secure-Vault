import os
import time
import math
from flask import Flask, request, render_template, redirect, url_for, session, send_file, flash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from werkzeug.utils import secure_filename
from PIL import Image
from functools import wraps
import sqlite3
from datetime import datetime
import logging
from cryptography.fernet import Fernet
from apscheduler.schedulers.background import BackgroundScheduler
import bcrypt
import re
import shutil
import gzip
from contextlib import contextmanager
from typing import Optional, Dict, Any, List, Tuple
import enum
import json


class Country(enum.Enum):
    PAKISTAN = "Pakistan"
    TURKISH = "Turkey"
    CHINESE = "China"


app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'bmp', 'gif'}
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['DATABASE'] = 'data/professional_app.db'
app.config['BACKUP_DIR'] = 'backups'
app.config['MAX_BACKUPS'] = 30
app.config['BACKUP_ENCRYPTION_KEY'] = Fernet.generate_key()
app.config['SQLITE_PRAGMAS'] = {
    'journal_mode': 'WAL',
    'foreign_keys': 1,
    'ignore_check_constraints': 0,
    'synchronous': 0
}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('data', exist_ok=True)
os.makedirs(app.config['BACKUP_DIR'], exist_ok=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseManager:
    def __init__(self, app=None):
        self.app = app
        self.logger = logging.getLogger(__name__)
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        app.config['DATABASE'] = 'data/professional_app.db'
        app.config['BACKUP_DIR'] = 'backups'
        app.config['MAX_BACKUPS'] = 30
        app.config['BACKUP_ENCRYPTION_KEY'] = Fernet.generate_key()
        app.config['SQLITE_PRAGMAS'] = {
            'journal_mode': 'WAL',
            'foreign_keys': 1,
            'ignore_check_constraints': 0,
            'synchronous': 0
        }

        os.makedirs('data', exist_ok=True, mode=0o755)
        os.makedirs(app.config['BACKUP_DIR'], exist_ok=True, mode=0o750)

        self._verify_encryption_key()
        self.init_database()

    def _verify_encryption_key(self):
        try:
            Fernet(self.app.config['BACKUP_ENCRYPTION_KEY'])
        except ValueError:
            self.logger.warning("Generating new encryption key")
            self.app.config['BACKUP_ENCRYPTION_KEY'] = Fernet.generate_key()

    def init_database(self):
        with self.get_db() as conn:
            for pragma, value in self.app.config['SQLITE_PRAGMAS'].items():
                conn.execute(f"PRAGMA {pragma}={value}")

            conn.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1 NOT NULL,
                    failed_attempts INTEGER DEFAULT 0 NOT NULL,
                    country TEXT NOT NULL CHECK(country IN ('Pakistan', 'Turkey', 'China')),
                    CONSTRAINT chk_username CHECK(length(username) >= 3),
                    CONSTRAINT chk_email CHECK(email LIKE '%@%.%')
                );

                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

                CREATE TABLE IF NOT EXISTS uploads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    original_filename TEXT NOT NULL,
                    stored_filename TEXT NOT NULL UNIQUE,
                    operation_type TEXT NOT NULL CHECK(operation_type IN ('upload', 'encrypt', 'compare')),
                    encryption_mode TEXT CHECK(encryption_mode IN ('ECB', 'CBC', 'GCM')),
                    file_size INTEGER NOT NULL,
                    encrypted_size INTEGER,
                    iv TEXT,
                    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    last_accessed TIMESTAMP,
                    access_count INTEGER DEFAULT 0 NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    CONSTRAINT chk_file_size CHECK(file_size > 0)
                );

                CREATE INDEX IF NOT EXISTS idx_uploads_user ON uploads(user_id);

                CREATE TABLE IF NOT EXISTS encryption_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    upload_id INTEGER NOT NULL,
                    operation TEXT NOT NULL CHECK(operation IN ('encrypt', 'decrypt')),
                    mode TEXT NOT NULL CHECK(mode IN ('ECB', 'CBC', 'GCM')),
                    duration REAL NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    FOREIGN KEY(upload_id) REFERENCES uploads(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS system_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    total_users INTEGER NOT NULL,
                    active_users INTEGER NOT NULL,
                    total_uploads INTEGER NOT NULL,
                    total_storage INTEGER NOT NULL,
                    daily_bandwidth INTEGER
                );

                CREATE TABLE IF NOT EXISTS user_sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    ip_address TEXT NOT NULL,
                    user_agent TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TRIGGER IF NOT EXISTS trg_after_upload
                AFTER INSERT ON uploads
                BEGIN
                    INSERT INTO encryption_logs(upload_id, operation, mode, duration)
                    VALUES (NEW.id, 'encrypt', NEW.encryption_mode, 0);

                    UPDATE system_metrics 
                    SET total_uploads = total_uploads + 1,
                        total_storage = total_storage + NEW.file_size
                    WHERE id = (SELECT MAX(id) FROM system_metrics);
                END;
            ''')

            conn.execute('''
                INSERT OR IGNORE INTO system_metrics 
                (total_users, active_users, total_uploads, total_storage)
                VALUES (0, 0, 0, 0)
            ''')

            self.logger.info("Database initialized with professional schema")
    @contextmanager
    def get_db(self):
        conn = None
        attempts = 0
        max_attempts = 3

        while attempts < max_attempts:
            try:
                conn = sqlite3.connect(self.app.config['DATABASE'], timeout=30)
                conn.row_factory = sqlite3.Row

                for pragma, value in self.app.config['SQLITE_PRAGMAS'].items():
                    conn.execute(f"PRAGMA {pragma}={value}")

                yield conn
                conn.commit()
                break
            except sqlite3.OperationalError:
                attempts += 1
                if conn:
                    conn.close()
                if attempts == max_attempts:
                    self.logger.error(f"Database connection failed after {max_attempts} attempts")
                    raise
                time.sleep(0.1 * attempts)
            except Exception as e:
                if conn:
                    conn.rollback()
                self.logger.error(f"Database error: {str(e)}")
                raise
            finally:
                if conn:
                    conn.close()

    def create_backup(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"backup_{timestamp}"
        backup_path = os.path.join(self.app.config['BACKUP_DIR'], backup_name)

        try:
            os.makedirs(backup_path, mode=0o750)

            db_hash = self._generate_db_checksum()

            db_path = self.app.config['DATABASE']
            backup_file = os.path.join(backup_path, 'database.db.gz')
            with open(db_path, 'rb') as f_in, gzip.open(backup_file, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

            metadata = {
                "backup_time": datetime.utcnow().isoformat(),
                "database_checksum": db_hash,
                "schema_version": 1,
                "system_stats": self.get_system_stats(),
                "backup_size": os.path.getsize(backup_file),
                "app_version": getattr(self.app, 'version', '1.0')
            }

            metadata_path = os.path.join(backup_path, 'metadata.json.enc')
            cipher = Fernet(self.app.config['BACKUP_ENCRYPTION_KEY'])
            encrypted_data = cipher.encrypt(json.dumps(metadata).encode('utf-8'))
            with open(metadata_path, 'wb') as f:
                f.write(encrypted_data)

            self.rotate_backups()
            self.logger.info(f"Created verified backup at {backup_path}")
            return backup_path
        except Exception as e:
            self.logger.error(f"Backup failed: {str(e)}")
            if os.path.exists(backup_path):
                shutil.rmtree(backup_path)
            raise

    def _generate_db_checksum(self) -> str:
        import hashlib
        db_path = self.app.config['DATABASE']
        sha256 = hashlib.sha256()

        with open(db_path, 'rb') as f:
            while chunk := f.read(4096):
                sha256.update(chunk)

        return sha256.hexdigest()

    def rotate_backups(self):
        backups = []
        backup_dir = self.app.config['BACKUP_DIR']

        for entry in os.scandir(backup_dir):
            if entry.is_dir() and entry.name.startswith('backup_'):
                backups.append((entry.name, entry.stat().st_mtime))

        backups.sort(key=lambda x: x[1], reverse=True)

        for backup in backups[self.app.config['MAX_BACKUPS']:]:
            shutil.rmtree(os.path.join(backup_dir, backup[0]))
            self.logger.info(f"Rotated out old backup: {backup[0]}")

    def get_system_stats(self) -> Dict[str, Any]:
        stats = {}

        with self.get_db() as conn:
            stats['users'] = dict(conn.execute('''
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN is_active THEN 1 ELSE 0 END) as active,
                    SUM(failed_attempts) as failed_attempts
                FROM users
            ''').fetchone())

            stats['uploads'] = dict(conn.execute('''
                SELECT 
                    COUNT(*) as total,
                    SUM(file_size) as total_size,
                    COUNT(DISTINCT user_id) as active_users
                FROM uploads
            ''').fetchone())

            stats['encryption_modes'] = dict(conn.execute('''
                SELECT encryption_mode, COUNT(*) as count
                FROM uploads
                WHERE encryption_mode IS NOT NULL
                GROUP BY encryption_mode
            ''').fetchall())

            stats['metrics'] = dict(conn.execute('''
                SELECT * FROM system_metrics
                ORDER BY timestamp DESC
                LIMIT 1
            ''').fetchone())

        return stats

    def vacuum(self):
        with self.get_db() as conn:
            conn.execute("VACUUM")
            conn.execute("ANALYZE")
            self.logger.info("Performed database maintenance (VACUUM, ANALYZE)")


class BackupScheduler:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.scheduler = BackgroundScheduler()
        self.logger = logging.getLogger(__name__)

    def start(self):
        try:
            self.scheduler.add_job(
                self.run_backup_cycle,
                'cron',
                hour=2,
                minute=0,
                name="Nightly backup cycle"
            )

            self.scheduler.add_job(
                self.record_metrics,
                'cron',
                day_of_week='sun',
                hour=3,
                name="Weekly metrics"
            )

            self.scheduler.add_job(
                self.db_manager.vacuum,
                'cron',
                day=1,
                hour=4,
                name="Monthly maintenance"
            )

            self.scheduler.start()
            self.logger.info("Started professional backup scheduler")
        except Exception as e:
            self.logger.error(f"Failed to start scheduler: {str(e)}")
            raise

    def run_backup_cycle(self):
        try:
            self.logger.info("Starting backup cycle")
            backup_path = self.db_manager.create_backup()
            self.logger.info(f"Successfully created backup: {backup_path}")
        except Exception as e:
            self.logger.error(f"Backup cycle failed: {str(e)}")

    def record_metrics(self):
        with self.db_manager.get_db() as conn:
            stats = self.db_manager.get_system_stats()
            conn.execute('''
                INSERT INTO system_metrics
                (total_users, active_users, total_uploads, total_storage)
                VALUES (?, ?, ?, ?)
            ''', (
                stats['users']['total'],
                stats['users']['active'],
                stats['uploads']['total'],
                stats['uploads']['total_size'] or 0
            ))
            self.logger.info("Recorded system metrics")
class UserStats:
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def get_encryption_summary(self, user_id: int) -> Dict[str, int]:
        stats = self.db.get_user_stats(user_id)
        return {
            'ECB': stats.get('ecb_count', 0),
            'CBC': stats.get('cbc_count', 0),
            'GCM': stats.get('gcm_count', 0),
            'total': stats.get('total_encryptions', 0)
        }

    def get_activity_summary(self, user_id: int) -> Dict[str, Any]:
        stats = self.db.get_user_stats(user_id)
        return {
            'uploads': stats.get('total_uploads', 0),
            'encryptions': stats.get('total_encryptions', 0),
            'comparisons': stats.get('comparison_count', 0),
            'last_activity': stats.get('last_activity'),
            'favorite_mode': self._get_favorite_mode(user_id),
            'account_age_days': self._get_account_age_days(user_id)
        }

    def _get_favorite_mode(self, user_id: int) -> Optional[str]:
        stats = self.db.get_user_stats(user_id)
        modes = {
            'ECB': stats.get('ecb_count', 0),
            'CBC': stats.get('cbc_count', 0),
            'GCM': stats.get('gcm_count', 0)
        }
        if sum(modes.values()) == 0:
            return None
        return max(modes.items(), key=lambda x: x[1])[0]

    def _get_account_age_days(self, user_id: int) -> int:
        stats = self.db.get_user_stats(user_id)
        if not stats or 'registration_date' not in stats:
            return 0
        from datetime import datetime
        created = datetime.strptime(stats['registration_date'], '%Y-%m-%d %H:%M:%S')
        return (datetime.now() - created).days


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def encrypt_ecb(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(data, AES.block_size)
    start = time.time()
    ct = cipher.encrypt(padded)
    return ct, None, None, time.time() - start


def encrypt_cbc(data, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(data, AES.block_size)
    start = time.time()
    ct = cipher.encrypt(padded)
    return ct, iv, None, time.time() - start


def encrypt_gcm(data, key):
    iv = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    start = time.time()
    ct, tag = cipher.encrypt_and_digest(data)
    return ct, iv, tag, time.time() - start


def security_level(mode):
    levels = {
        "ECB": "🟡 Low - Pattern leakage, not semantically secure",
        "CBC": "🟠 Medium - Requires IV, better than ECB but no integrity",
        "GCM": "🟢 High - Confidentiality + integrity checks"
    }
    return levels.get(mode, "⚪ Unknown")


def integrity_check(mode):
    return "✅ Yes (via authentication tag)" if mode == "GCM" else "❌ No"


def recommend_best_mode():
    return "🌟 Recommendation: GCM provides the best security with integrity checks and good performance"


def ciphertext_to_png(ct_bytes, filename):
    width = 256
    length = len(ct_bytes)
    height = math.ceil(length / width)
    padded_len = width * height
    padded_bytes = ct_bytes + b'\x00' * (padded_len - length)
    img = Image.frombytes('L', (width, height), padded_bytes)
    img.save(filename)


def sanitize_filename_path(filename):
    filename = filename.replace('\\', '/')
    filename = re.sub(r'(\.\./|\.\.\\|\.\.\/|\.\.\\).*', '', filename)
    filename = re.sub(r'(\./|\.\\|\.\/|\.\\).*', '', filename)
    filename = os.path.basename(filename)
    filename = secure_filename(filename) or "default_filename.txt"
    return filename


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('🔒 You must be logged in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def get_user_id(username):
    with db_manager.get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        return user['id'] if user else None


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(413)
def file_too_large(e):
    flash('⚠️ File too large! Maximum size is 50MB', 'error')
    return redirect(request.url)


@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500


@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('upload'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('upload'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()
        confirm_password = request.form['confirm_password'].strip()
        country = request.form['country'].strip()
        phone_number = request.form.get('phone_number', '').strip()

        if not username or not email or not password or not confirm_password or not country:
            flash('❌ All fields are required', 'error')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('❌ Passwords do not match', 'error')
            return redirect(url_for('register'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            db_manager.create_user(
                username=username,
                email=email,
                password_hash=hashed_password.decode('utf-8'),
                country=country,
                phone_number=phone_number
            )
            flash('🎉 Registration successful! Please log in', 'success')
            return redirect(url_for('login'))
        except ValueError as e:
            flash(str(e), 'error')

    return render_template('register.html', countries=[c.value for c in Country])

