import sqlite3
import time
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "mirage.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            created_at REAL,
            last_seen REAL,
            cwd TEXT,
            threat_score INTEGER DEFAULT 0,
            threat_level TEXT DEFAULT 'Low',
            containment_active INTEGER DEFAULT 0,
            threat_summary TEXT
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            timestamp REAL,
            command TEXT,
            output TEXT,
            source TEXT
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS virtual_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            path TEXT,
            content TEXT,
            is_honeytoken INTEGER DEFAULT 0,
            permissions TEXT DEFAULT '-rw-r--r--',
            owner TEXT DEFAULT 'root',
            filesize INTEGER DEFAULT 0,
            is_dir INTEGER DEFAULT 0
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            timestamp REAL,
            event_type TEXT,
            details TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def migrate_add_threat_summary():
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute('ALTER TABLE sessions ADD COLUMN threat_summary TEXT')
        conn.commit()
    except sqlite3.OperationalError:
        pass
    finally:
        conn.close()

def migrate_add_containment_active():
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute('ALTER TABLE sessions ADD COLUMN containment_active INTEGER DEFAULT 0')
        conn.commit()
    except sqlite3.OperationalError:
        pass
    finally:
        conn.close()

def get_or_create_session(session_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
    row = c.fetchone()
    
    if not row:
        now = time.time()
        default_cwd = "/home/ubuntu"
        c.execute('''
            INSERT INTO sessions (session_id, created_at, last_seen, cwd, threat_score, threat_level, containment_active, threat_summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session_id, now, now, default_cwd, 0, "Low", 0, None))
        
        honeytokens = [
            (".env", "DB_PASSWORD=supersecret123\nAPI_KEY=sk-12345"),
            ("aws_credentials.txt", "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE"),
            ("db_backup.sql", "-- Dump of database users\nINSERT INTO users VALUES...")
        ]
        for fname, content in honeytokens:
            full_path = os.path.normpath(f"{default_cwd}/{fname}")
            c.execute('''
                INSERT INTO virtual_files (session_id, path, content, is_honeytoken)
                VALUES (?, ?, ?, 1)
            ''', (session_id, full_path, content))
            
        conn.commit()
        row = c.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
    
    conn.close()
    return dict(row)

def update_session(session_id, cwd=None, threat_score=None, threat_level=None, 
                   containment_active=None, threat_summary=None):
    conn = get_connection()
    c = conn.cursor()
    updates = []
    values = []
    
    if cwd is not None:
        updates.append("cwd = ?")
        values.append(cwd)
    if threat_score is not None:
        updates.append("threat_score = ?")
        values.append(threat_score)
    if threat_level is not None:
        updates.append("threat_level = ?")
        values.append(threat_level)
    if containment_active is not None:
        updates.append("containment_active = ?")
        values.append(containment_active)
    if threat_summary is not None:
        updates.append("threat_summary = ?")
        values.append(threat_summary)
        
    updates.append("last_seen = ?")
    values.append(time.time())
    values.append(session_id)
    
    sql = f"UPDATE sessions SET {', '.join(updates)} WHERE session_id = ?"
    c.execute(sql, values)
    conn.commit()
    conn.close()

def get_session_commands(session_id, limit=10):
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        SELECT command, output, source, timestamp 
        FROM logs 
        WHERE session_id = ? 
        ORDER BY timestamp DESC 
        LIMIT ?
    ''', (session_id, limit))
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def log_command(session_id, command, output, source):
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO logs (session_id, timestamp, command, output, source)
        VALUES (?, ?, ?, ?, ?)
    ''', (session_id, time.time(), command, output, source))
    conn.commit()
    conn.close()

def log_event(session_id, event_type, details):
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO events (session_id, timestamp, event_type, details)
        VALUES (?, ?, ?, ?)
    ''', (session_id, time.time(), event_type, details))
    conn.commit()
    conn.close()

def get_virtual_file(session_id, path):
    conn = get_connection()
    c = conn.cursor()
    normalized_path = os.path.normpath(path)
    c.execute('''
        SELECT * FROM virtual_files WHERE session_id = ? AND path = ?
    ''', (session_id, normalized_path))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None

def save_virtual_file(session_id, path, content, is_honeytoken=0, permissions="-rw-r--r--", owner="root", is_dir=0):
    conn = get_connection()
    c = conn.cursor()
    normalized_path = os.path.normpath(path)
    filesize = len(content) if content else 0
    
    c.execute("SELECT id FROM virtual_files WHERE session_id = ? AND path = ?", (session_id, normalized_path))
    if c.fetchone():
        c.execute('''
            UPDATE virtual_files SET content = ?, filesize = ?, permissions = ?, owner = ?, is_dir = ?, is_honeytoken = ?
            WHERE session_id = ? AND path = ?
        ''', (content, filesize, permissions, owner, is_dir, is_honeytoken, session_id, normalized_path))
    else:
        c.execute('''
            INSERT INTO virtual_files (session_id, path, content, is_honeytoken, permissions, owner, filesize, is_dir)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session_id, normalized_path, content, is_honeytoken, permissions, owner, filesize, is_dir))
    
    conn.commit()
    conn.close()

def delete_virtual_file(session_id, path):
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        DELETE FROM virtual_files WHERE session_id = ? AND path = ?
    ''', (session_id, path))
    conn.commit()
    conn.close()

def list_virtual_files(session_id, cwd):
    conn = get_connection()
    c = conn.cursor()
    prefix = cwd.rstrip('/') + '/'
    if cwd == "/":
        prefix = "/"
    c.execute('''
        SELECT * FROM virtual_files 
        WHERE session_id = ? AND (path LIKE ? OR path LIKE ?)
    ''', (session_id, prefix + '%', cwd + '/%'))
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_all_logs():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100")
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_all_sessions():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM sessions ORDER BY last_seen DESC")
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_all_events():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_session_by_id(session_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None