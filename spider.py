#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    ███████╗██████╗ ██╗██████╗ ███████╗██████╗
    ██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗
    ███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝
    ╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗
    ███████║██║     ██║██████╔╝███████╗██║  ██║
    ╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝

SPIDER v3.0 — كل شيء في ملف واحد
- يكتشف IP تلقائياً
- يشغّل قاعدة البيانات بنفسه
- لا يحتاج إعداد

  pip install requests argon2-cffi cryptography
  python3 spider.py
"""

import os, sys, re, json, time, base64, hashlib, secrets, sqlite3, socket
import mimetypes, getpass, threading, argparse, subprocess
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ================= ثبّت المكتبات تلقائياً =================
def auto_install():
    missing = []
    try:
        import requests  # noqa
    except ImportError:
        missing.append("requests")
    try:
        from argon2 import PasswordHasher  # noqa
    except ImportError:
        missing.append("argon2-cffi")
    try:
        from cryptography.fernet import Fernet  # noqa
    except ImportError:
        missing.append("cryptography")
    if missing:
        print(f"📦 تثبيت المكتبات الناقصة: {', '.join(missing)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q"] + missing)
        os.execv(sys.executable, [sys.executable] + sys.argv)

auto_install()

import requests
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet

PH = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=4)

# ================= إعدادات =================
BASE         = os.path.dirname(os.path.abspath(__file__))
DB_PATH      = os.path.join(BASE, "spider.db")
KEY_PATH     = os.path.join(BASE, "spider.key")
BLOB_DIR     = os.path.join(BASE, "blobs")
MAX_BODY     = 30 * 1024 * 1024
USERNAME_RE  = re.compile(r"^[a-z0-9_]{4,20}$")
GROUP_RE     = re.compile(r"^[a-z0-9_\-]{3,32}$")
TOKEN_RE     = re.compile(r"^[A-Za-z0-9_\-]{20,120}$")

os.makedirs(BLOB_DIR, exist_ok=True)

# ================= كشف IP =================
def detect_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            ip = socket.gethostbyname(socket.gethostname())
            if ip.startswith("127."):
                return "127.0.0.1"
            return ip
        except Exception:
            return "127.0.0.1"

def detect_public_ip():
    try:
        r = requests.get("https://api.ipify.org", timeout=3)
        if r.status_code == 200:
            return r.text.strip()
    except Exception:
        pass
    return None

# ================= تشفير =================
def _load_key():
    if not os.path.exists(KEY_PATH):
        with open(KEY_PATH, "wb") as f:
            f.write(secrets.token_bytes(32))
        try:
            os.chmod(KEY_PATH, 0o600)
        except Exception:
            pass
    with open(KEY_PATH, "rb") as f:
        return f.read()

MASTER = _load_key()
FERNET = Fernet(base64.urlsafe_b64encode(hashlib.sha256(MASTER).digest()))

def enc(b):
    return FERNET.encrypt(b)

def dec(b):
    return FERNET.decrypt(b)

# ================= قاعدة البيانات =================
def db():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    return c

def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS accounts(
        username      TEXT PRIMARY KEY,
        display_name  TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at    INTEGER NOT NULL,
        last_seen     INTEGER
    );
    CREATE TABLE IF NOT EXISTS sessions(
        token      TEXT PRIMARY KEY,
        username   TEXT NOT NULL,
        expires    INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS groups(
        name        TEXT PRIMARY KEY,
        owner       TEXT NOT NULL,
        description TEXT,
        is_private  INTEGER NOT NULL DEFAULT 0,
        created_at  INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS group_members(
        group_name TEXT NOT NULL,
        username   TEXT NOT NULL,
        role       TEXT NOT NULL DEFAULT 'member',
        joined_at  INTEGER NOT NULL,
        PRIMARY KEY(group_name, username)
    );
    CREATE TABLE IF NOT EXISTS messages_dm(
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        sender     TEXT NOT NULL,
        recipient  TEXT NOT NULL,
        enc        BLOB NOT NULL,
        msg_type   TEXT NOT NULL,
        sent_at    INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS messages_group(
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        group_name TEXT NOT NULL,
        sender     TEXT NOT NULL,
        enc        BLOB NOT NULL,
        msg_type   TEXT NOT NULL,
        sent_at    INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS files(
        file_id    TEXT PRIMARY KEY,
        owner      TEXT NOT NULL,
        name       TEXT NOT NULL,
        mime       TEXT,
        size       INTEGER NOT NULL,
        sha256     TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sess_user ON sessions(username);
    CREATE INDEX IF NOT EXISTS idx_dm_pair   ON messages_dm(sender, recipient, id);
    CREATE INDEX IF NOT EXISTS idx_gm_group  ON messages_group(group_name, id);
    """)
    c.commit()
    c.close()

init_db()

# ================= Helpers =================
def user_from_token(tok):
    if not tok or not TOKEN_RE.match(tok):
        return None
    c = db()
    r = c.execute("SELECT username,expires FROM sessions WHERE token=?", (tok,)).fetchone()
    c.close()
    if not r or r["expires"] < int(time.time()):
        return None
    return r["username"]

def user_exists(u):
    c = db()
    r = c.execute("SELECT 1 FROM accounts WHERE username=?", (u,)).fetchone()
    c.close()
    return bool(r)

def touch_user(u):
    c = db()
    c.execute("UPDATE accounts SET last_seen=? WHERE username=?", (int(time.time()), u))
    c.commit()
    c.close()

# ================= HTTP Server =================
class API(BaseHTTPRequestHandler):
    server_version = "SPIDER/3.0"

    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", ctype="application/json; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Filename, X-Mime")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode())

    def _body(self, limit=MAX_BODY + 8192):
        n = int(self.headers.get("Content-Length", "0"))
        if n <= 0 or n > limit:
            return None
        return self.rfile.read(n)

    def _jbody(self):
        raw = self._body()
        if not raw:
            return None
        try:
            return json.loads(raw.decode())
        except Exception:
            return None

    def _tok(self):
        a = self.headers.get("Authorization", "")
        return a[7:].strip() if a.startswith("Bearer ") else None

    def _auth(self):
        u = user_from_token(self._tok())
        if u:
            touch_user(u)
        return u

    def do_OPTIONS(self):
        self._send(204)

    def do_GET(self):
        p = urlparse(self.path)
        path = p.path
        qs = parse_qs(p.query)

        if path == "/health":
            return self._json(200, {"ok": True, "time": int(time.time()), "service": "SPIDER"})

        if path == "/accounts/exists":
            u = (qs.get("username") or [""])[0].lower()
            return self._json(200, {"ok": True, "exists": user_exists(u)})

        if path == "/accounts/lookup":
            u = (qs.get("username") or [""])[0].lower()
            c = db()
            r = c.execute("SELECT username,display_name,password_hash FROM accounts WHERE username=?", (u,)).fetchone()
            c.close()
            if not r:
                return self._json(404, {"ok": False})
            return self._json(200, {"ok": True, "account": dict(r)})

        if path == "/accounts":
            if not self._auth():
                return self._json(401, {"ok": False})
            c = db()
            rows = c.execute("SELECT username,display_name,last_seen FROM accounts ORDER BY username").fetchall()
            c.close()
            now = int(time.time())
            out = [
                {
                    "username": r["username"],
                    "display_name": r["display_name"],
                    "online": bool(r["last_seen"] and (now - r["last_seen"]) < 300),
                }
                for r in rows
            ]
            return self._json(200, {"ok": True, "accounts": out})

        if path == "/messages/dm":
            u = self._auth()
            if not u:
                return self._json(401, {"ok": False})
            peer = (qs.get("with") or [""])[0].lower()
            c = db()
            rows = c.execute(
                """SELECT id,sender,recipient,enc,msg_type,sent_at FROM messages_dm
                   WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?)
                   ORDER BY id DESC LIMIT 200""",
                (u, peer, peer, u),
            ).fetchall()
            c.close()
            out = []
            for r in rows:
                try:
                    content = json.loads(dec(r["enc"]))["c"]
                except Exception:
                    content = "[!]"
                out.append(
                    {
                        "id": r["id"],
                        "from": r["sender"],
                        "to": r["recipient"],
                        "content": content,
                        "type": r["msg_type"],
                        "ts": r["sent_at"],
                    }
                )
            out.reverse()
            return self._json(200, {"ok": True, "messages": out})

        if path == "/messages/group":
            u = self._auth()
            if not u:
                return self._json(401, {"ok": False})
            name = (qs.get("name") or [""])[0].lower()
            c = db()
            m = c.execute("SELECT 1 FROM group_members WHERE group_name=? AND username=?", (name, u)).fetchone()
            if not m:
                c.close()
                return self._json(403, {"ok": False})
            rows = c.execute(
                "SELECT id,sender,enc,msg_type,sent_at FROM messages_group WHERE group_name=? ORDER BY id DESC LIMIT 200",
                (name,),
            ).fetchall()
            c.close()
            out = []
            for r in rows:
                try:
                    content = json.loads(dec(r["enc"]))["c"]
                except Exception:
                    content = "[!]"
                out.append(
                    {
                        "id": r["id"],
                        "from": r["sender"],
                        "group": name,
                        "content": content,
                        "type": r["msg_type"],
                        "ts": r["sent_at"],
                    }
                )
            out.reverse()
            return self._json(200, {"ok": True, "messages": out})

        if path == "/groups/mine":
            u = self._auth()
            if not u:
                return self._json(401, {"ok": False})
            c = db()
            rows = c.execute(
                """SELECT g.name,g.description,g.is_private,
                   (SELECT COUNT(*) FROM group_members WHERE group_name=g.name) as members
                   FROM groups g JOIN group_members m ON m.group_name=g.name
                   WHERE m.username=? ORDER BY g.name""",
                (u,),
            ).fetchall()
            c.close()
            return self._json(
                200,
                {
                    "ok": True,
                    "groups": [
                        {
                            "name": r["name"],
                            "description": r["description"] or "",
                            "is_private": bool(r["is_private"]),
                            "members": r["members"],
                        }
                        for r in rows
                    ],
                },
            )

        if path == "/groups/public":
            if not self._auth():
                return self._json(401, {"ok": False})
            c = db()
            rows = c.execute(
                """SELECT g.name,g.description,
                   (SELECT COUNT(*) FROM group_members WHERE group_name=g.name) as members
                   FROM groups g WHERE g.is_private=0 ORDER BY g.name"""
            ).fetchall()
            c.close()
            return self._json(
                200,
                {
                    "ok": True,
                    "groups": [
                        {
                            "name": r["name"],
                            "description": r["description"] or "",
                            "members": r["members"],
                        }
                        for r in rows
                    ],
                },
            )

        if path == "/groups/members":
            u = self._auth()
            if not u:
                return self._json(401, {"ok": False})
            name = (qs.get("name") or [""])[0].lower()
            c = db()
            m = c.execute("SELECT 1 FROM group_members WHERE group_name=? AND username=?", (name, u)).fetchone()
            if not m:
                c.close()
                return self._json(403, {"ok": False})
            rows = c.execute(
                """SELECT gm.username,gm.role,a.display_name FROM group_members gm
                   LEFT JOIN accounts a ON a.username=gm.username
                   WHERE gm.group_name=? ORDER BY gm.role DESC, gm.username""",
                (name,),
            ).fetchall()
            c.close()
            return self._json(
                200,
                {
                    "ok": True,
                    "members": [
                        {
                            "username": r["username"],
                            "role": r["role"],
                            "display_name": r["display_name"] or "",
                        }
                        for r in rows
                    ],
                },
            )

        if path == "/search/users":
            if not self._auth():
                return self._json(401, {"ok": False})
            q = (qs.get("q") or [""])[0].lower()
            c = db()
            rows = c.execute(
                "SELECT username,display_name FROM accounts WHERE username LIKE ? OR LOWER(display_name) LIKE ? LIMIT 30",
                (f"%{q}%", f"%{q}%"),
            ).fetchall()
            c.close()
            return self._json(200, {"ok": True, "users": [dict(r) for r in rows]})

        if path == "/search/messages":
            u = self._auth()
            if not u:
                return self._json(401, {"ok": False})
            q = (qs.get("q") or [""])[0].lower()
            c = db()
            rows = c.execute(
                "SELECT id,sender,recipient,enc,sent_at FROM messages_dm WHERE sender=? OR recipient=? ORDER BY id DESC LIMIT 500",
                (u, u),
            ).fetchall()
            c.close()
            out = []
            for r in rows:
                try:
                    content = json.loads(dec(r["enc"]))["c"]
                except Exception:
                    continue
                if q in content.lower():
                    out.append(
                        {
                            "id": r["id"],
                            "from": r["sender"],
                            "to": r["recipient"],
                            "content": content,
                            "ts": r["sent_at"],
                        }
                    )
                    if len(out) >= 30:
                        break
            return self._json(200, {"ok": True, "messages": out})

        if path == "/files":
            if not self._auth():
                return self._json(401, {"ok": False})
            fid = (qs.get("id") or [""])[0]
            if not re.match(r"^[a-f0-9]{32}$", fid):
                return self._json(400, {"ok": False})
            c = db()
            r = c.execute("SELECT name,mime FROM files WHERE file_id=?", (fid,)).fetchone()
            c.close()
            if not r:
                return self._json(404, {"ok": False})
            path_disk = os.path.join(BLOB_DIR, fid + ".bin")
            if not os.path.exists(path_disk):
                return self._json(404, {"ok": False})
            with open(path_disk, "rb") as f:
                data = dec(f.read())
            return self._send(
                200,
                data,
                r["mime"] or "application/octet-stream",
                extra={"Content-Disposition": f'attachment; filename="{r["name"]}"'},
            )

        self._send(404, b'{"ok":false}')

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/accounts":
            b = self._jbody() or {}
            u = (b.get("username") or "").strip().lower()
            disp = (b.get("display_name") or "").strip()[:40]
            ph = b.get("password_hash") or ""
            if not USERNAME_RE.match(u):
                return self._json(400, {"ok": False})
            if not disp or not ph:
                return self._json(400, {"ok": False})
            c = db()
            try:
                c.execute(
                    "INSERT INTO accounts(username,display_name,password_hash,created_at,last_seen) VALUES(?,?,?,?,?)",
                    (u, disp, ph, int(time.time()), int(time.time())),
                )
                c.commit()
                return self._json(200, {"ok": True})
            except sqlite3.IntegrityError:
                return self._json(409, {"ok": False, "msg": "username_taken"})
            finally:
                c.close()

        if path == "/sessions":
            b = self._jbody() or {}
            u = (b.get("username") or "").lower()
            tok = b.get("token") or ""
            ttl = int(b.get("ttl") or 604800)
            if not u or not tok or not user_exists(u):
                return self._json(400, {"ok": False})
            c = db()
            c.execute(
                "INSERT OR REPLACE INTO sessions(token,username,expires,created_at) VALUES(?,?,?,?)",
                (tok, u, int(time.time()) + ttl, int(time.time())),
            )
            c.commit()
            c.close()
            return self._json(200, {"ok": True})

        if path == "/sessions/delete":
            tok = self._tok()
            if tok:
                c = db()
                c.execute("DELETE FROM sessions WHERE token=?", (tok,))
                c.commit()
                c.close()
            return self._json(200, {"ok": True})

        if path == "/messages/dm":
            u = self._auth()
            if not u:
                return self._json(401, {"ok": False})
            b = self._jbody() or {}
            to = (b.get("to") or "").lower()
            content = b.get("content") or ""
            mtype = b.get("type") or "text"
            if not USERNAME_RE.match(to) or not content:
                return self._json(400, {"ok": False})
            if not user_exists(to):
                return self._json(404, {"ok": False})
            payload = json.dumps({"c": content}, ensure_ascii=False).encode()
            c = db()
            c.execute(
                "INSERT INTO messages_dm(sender,recipient,enc,msg_type,sent_at) VALUES(?,?,?,?,?)",
                (u, to, enc(payload), mtype, int(time.time())),
            )
            c.commit()
            c.close()
            return self._json(200, {"ok": True})

        if path == "/messages/group":
            u = self._auth()
            if not u:
                return self._json(401, {"ok": False})
            b = self._jbody() or {}
            name = (b.get("name") or "").lower()
            content = b.get("content") or ""
            mtype = b.get("type") or "text"
            if not content:
                return self._json(400, {"ok": False})
            c = db()
            m = c.execute("SELECT 1 FROM group_members WHERE group_name=? AND username=?", (name, u)).fetchone()
            if not m:
                c.close()
                return self._json(403, {"ok": False})
            payload = json.dumps({"c": content}, ensure_ascii=False).encode()
            c.execute(
                "INSERT INTO messages_group(group_name,sender,enc,msg_type,sent_at) VALUES(?,?,?,?,?)",
                (name, u, enc(payload), mtype, int(time.time())),
            )
            c.commit()
            c.close()
            return self._json(200, {"ok": True})

        if path == "/groups":
            u = self._auth()
            if not u:
                return self._json(401, {"ok": False})
            b = self._jbody() or {}
            name = (b.get("name") or "").lower()
            if not GROUP_RE.match(name):
                return self._json(400, {"ok": False})
            desc = (b.get("description") or "")[:200]
            priv = 1 if b.get("is_private") else 0
            c = db()
            try:
                c.execute(
                    "INSERT INTO groups(name,owner,description,is_private,created_at) VALUES(?,?,?,?,?)",
                    (name, u, desc, priv, int(time.time())),
                )
                c.execute(
                    "INSERT INTO group_members(group_name,username,role,joined_at) VALUES(?,?,?,?)",
                    (name, u, "admin", int(time.time())),
                )
                c.commit()
                return self._json(200, {"ok": True})
            except sqlite3.IntegrityError:
                return self._json(409, {"ok": False, "msg": "taken"})
            finally:
                c.close()

        if path == "/groups/join":
            u = self._auth()
            if not u:
                return self._json(401, {"ok": False})
            b = self._jbody() or {}
            name = (b.get("name") or "").lower()
            c = db()
            g = c.execute("SELECT is_private FROM groups WHERE name=?", (name,)).fetchone()
            if not g:
                c.close()
                return self._json(404, {"ok": False})
            if g["is_private"]:
                c.close()
                return self._json(403, {"ok": False})
            try:
                c.execute(
                    "INSERT INTO group_members(group_name,username,role,joined_at) VALUES(?,?,?,?)",
                    (name, u, "member", int(time.time())),
                )
                c.commit()
            except sqlite3.IntegrityError:
                pass
            c.close()
            return self._json(200, {"ok": True})

        if path == "/files":
            u = self._auth()
            if not u:
                return self._json(401, {"ok": False})
            raw = self._body()
            if not raw:
                return self._json(400, {"ok": False})
            name = re.sub(r"[^\w\.\-]", "_", self.headers.get("X-Filename", "file"))[:80] or "file"
            mime = self.headers.get("X-Mime", "application/octet-stream")
            fid = secrets.token_hex(16)
            with open(os.path.join(BLOB_DIR, fid + ".bin"), "wb") as f:
                f.write(enc(raw))
            c = db()
            c.execute(
                "INSERT INTO files(file_id,owner,name,mime,size,sha256,created_at) VALUES(?,?,?,?,?,?,?)",
                (fid, u, name, mime, len(raw), hashlib.sha256(raw).hexdigest(), int(time.time())),
            )
            c.commit()
            c.close()
            return self._json(200, {"ok": True, "file_id": fid, "name": name, "size": len(raw)})

        self._send(404, b'{"ok":false}')

# ================= حالة الأداة =================
STATE = {
    "server": None,
    "port": 8000,
    "token": None,
    "username": None,
    "display": None,
    "chat": None,
    "local_ip": None,
    "public_ip": None,
}

class C:
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[94m"
    M = "\033[95m"
    CY = "\033[96m"
    W = "\033[97m"
    D = "\033[2m"
    BOLD = "\033[1m"
    X = "\033[0m"

def hr():
    print(C.D + "─" * 66 + C.X)

def ok(m):
    print(f"  {C.G}✓{C.X} {m}")

def err(m):
    print(f"  {C.R}✗{C.X} {m}")

def info(m):
    print(f"  {C.B}ℹ{C.X} {m}")

def warn(m):
    print(f"  {C.Y}!{C.X} {m}")

SPIDER_ART = f"""{C.M}
    ╔═══════════════════════════════════════════════════════════╗
    ║      ███████╗██████╗ ██╗██████╗ ███████╗██████╗           ║
    ║      ██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗          ║
    ║      ███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝          ║
    ║      ╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗          ║
    ║      ███████║██║     ██║██████╔╝███████╗██║  ██║          ║
    ║      ╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝          ║
    ║              {C.CY}أداة تواصل التقنيين{C.M}  v3.0                  ║
    ╚═══════════════════════════════════════════════════════════╝{C.X}"""

def banner():
    print(SPIDER_ART)
    print(f"  {C.D}» Local:{C.X}  {C.G}{STATE['local_ip']}:{STATE['port']}{C.X}  {C.D}(للشبكة الداخلية){C.X}")
    if STATE["public_ip"]:
        print(f"  {C.D}» Public:{C.X} {C.CY}{STATE['public_ip']}:{STATE['port']}{C.X} {C.D}(للإنترنت — يحتاج port forward){C.X}")
    if STATE["username"]:
        print(f"  {C.D}» User:{C.X}   {C.G}{STATE['display']}{C.X} {C.D}(@{STATE['username']}){C.X}")
        if STATE["chat"]:
            c = STATE["chat"]
            label = f"@{c['id']}" if c["type"] == "dm" else f"#{c['id']}"
            print(f"  {C.D}» Chat:{C.X}   {C.CY}{label}{C.X}")
    else:
        print(f"  {C.D}» User:{C.X}   {C.Y}(غير مسجل){C.X}")
    hr()

def http(method, path, body=None, headers=None, raw=None, timeout=30):
    url = STATE["server"].rstrip("/") + path
    h = {"User-Agent": "SPIDER/3.0"}
    if STATE["token"]:
        h["Authorization"] = "Bearer " + STATE["token"]
    if headers:
        h.update(headers)
    try:
        if raw is not None:
            r = requests.request(method, url, data=raw, headers=h, timeout=timeout)
        elif body is not None:
            h["Content-Type"] = "application/json"
            r = requests.request(method, url, json=body, headers=h, timeout=timeout)
        else:
            r = requests.request(method, url, headers=h, timeout=timeout)
        try:
            data = r.json()
        except Exception:
            data = r.content
        return r.status_code, data
    except requests.exceptions.RequestException as e:
        return 0, {"ok": False, "msg": str(e)}

# ================= التسجيل والدخول =================
def do_register():
    print(f"\n{C.CY}{C.BOLD}── إنشاء حساب جديد ──{C.X}")
    username = input("  اليوزر (a-z0-9_, 4-20): ").strip().lower()
    if not USERNAME_RE.match(username):
        return err("الصيغة غير صحيحة")
    code, r = http("GET", "/accounts/exists?username=" + username)
    if code != 200:
        return err("فشل الاتصال")
    if r.get("exists"):
        return err("اليوزر محجوز")
    display = input("  الاسم الظاهر: ").strip()[:40]
    if not display:
        return err("مطلوب")
    pw = getpass.getpass("  كلمة المرور (8+): ")
    pw2 = getpass.getpass("  تأكيد: ")
    if len(pw) < 8:
        return err("قصيرة")
    if pw != pw2:
        return err("غير متطابقة")
    code, r = http(
        "POST",
        "/accounts",
        {"username": username, "display_name": display, "password_hash": PH.hash(pw)},
    )
    if code == 200 and r.get("ok"):
        ok(f"تم إنشاء @{username}")
    elif code == 409:
        err("محجوز")
    else:
        err(str(r.get("msg") or r))

def do_login():
    print(f"\n{C.CY}{C.BOLD}── تسجيل الدخول ──{C.X}")
    username = input("  اليوزر: ").strip().lower()
    pw = getpass.getpass("  كلمة المرور: ")
    code, r = http("GET", "/accounts/lookup?username=" + username)
    if code == 404:
        return err("غير موجود")
    if code != 200:
        return err("فشل الاتصال")
    acc = r.get("account", {})
    try:
        if not PH.verify(acc["password_hash"], pw):
            return err("كلمة المرور خاطئة")
    except VerifyMismatchError:
        return err("كلمة المرور خاطئة")
    except Exception:
        return err("فشل التحقق")
    token = secrets.token_urlsafe(48)
    code, r2 = http("POST", "/sessions", {"username": username, "token": token, "ttl": 604800})
    if not (code == 200 and r2.get("ok")):
        return err("فشل إنشاء جلسة")
    STATE["token"] = token
    STATE["username"] = username
    STATE["display"] = acc.get("display_name", username)
    ok(f"مرحباً {STATE['display']}")

def do_logout():
    if STATE["token"]:
        http("POST", "/sessions/delete")
    STATE.update(token=None, username=None, display=None, chat=None)
    ok("خرجت")

# ================= البحث =================
def do_search():
    print(f"\n{C.CY}{C.BOLD}── بحث ──{C.X}")
    q = input("  استعلام: ").strip()
    if not q:
        return
    code, r = http("GET", "/search/users?q=" + q)
    users = r.get("users", []) if code == 200 else []
    code, r2 = http("GET", "/search/messages?q=" + q)
    msgs = r2.get("messages", []) if code == 200 else []
    print()
    hr()
    print(f"  {C.BOLD}المستخدمون ({len(users)}){C.X}")
    hr()
    if users:
        for i, u in enumerate(users, 1):
            print(f"  {i:>2}. @{u['username']:<20} {C.D}{u.get('display_name','')}{C.X}")
    else:
        info("لا نتائج")
    print()
    hr()
    print(f"  {C.BOLD}الرسائل ({len(msgs)}){C.X}")
    hr()
    if msgs:
        for m in msgs[:20]:
            t = time.strftime("%m-%d %H:%M", time.localtime(m["ts"]))
            print(f"  {C.D}[{t}]{C.X} {C.CY}@{m['from']}→@{m['to']}{C.X}  {m['content'][:80]}")
    else:
        info("لا نتائج")
    hr()

# ================= المستخدمون =================
def list_users():
    code, r = http("GET", "/accounts")
    if not (code == 200 and r.get("ok")):
        err("فشل")
        return [], []
    users = r["accounts"]
    if not users:
        info("لا مستخدمين")
        return [], []
    print()
    hr()
    print(f"  {C.BOLD}{'#':<3} {'@username':<22} {'الاسم':<28} الحالة{C.X}")
    hr()
    for i, u in enumerate(users, 1):
        online = f"{C.G}●{C.X}" if u.get("online") else f"{C.D}○{C.X}"
        print(f"  {i:<3} @{u['username']:<21} {(u.get('display_name') or ''):<28} {online}")
    hr()
    return users, users

# ================= الجروبات =================
def groups_menu():
    while True:
        print(f"\n{C.CY}{C.BOLD}── الجروبات ──{C.X}")
        print(f"  {C.G}[1]{C.X} جروباتي   {C.G}[2]{C.X} إنشاء   {C.G}[3]{C.X} انضمام   {C.G}[b]{C.X} رجوع")
        c = input(f"  {C.CY}>{C.X} ").strip().lower()
        if c == "1":
            code, r = http("GET", "/groups/mine")
            if code != 200 or not r.get("ok"):
                err("فشل")
                continue
            groups = r["groups"]
            if not groups:
                info("لا جروبات")
                continue
            hr()
            print(f"  {'#':<3} {'الاسم':<25} {'الأعضاء':<10} {'خاص؟':<5}")
            hr()
            for i, g in enumerate(groups, 1):
                priv = "🔒" if g.get("is_private") else "🌐"
                print(f"  {i:<3} #{g['name']:<24} {g['members']:<10} {priv}")
            hr()
            pick = input("  رقم للدخول (Enter لتجاهل): ").strip()
            if pick:
                try:
                    idx = int(pick) - 1
                    if 0 <= idx < len(groups):
                        chat_loop("group", groups[idx]["name"])
                except ValueError:
                    pass
        elif c == "2":
            name = input("  اسم الجروب (a-z0-9_-, 3-32): ").strip().lower()
            if not GROUP_RE.match(name):
                err("صيغة")
                continue
            desc = input("  وصف: ").strip()[:200]
            priv = input("  خاص؟ (y/N): ").strip().lower() == "y"
            code, r = http("POST", "/groups", {"name": name, "description": desc, "is_private": priv})
            if code == 200 and r.get("ok"):
                ok(f"أنشأت #{name}")
                chat_loop("group", name)
            else:
                err(str(r.get("msg") or r))
        elif c == "3":
            code, r = http("GET", "/groups/public")
            if code != 200 or not r.get("ok"):
                err("فشل")
                continue
            groups = r["groups"]
            if not groups:
                info("لا جروبات عامة")
                continue
            hr()
            print(f"  {'#':<3} {'الاسم':<25} {'الأعضاء':<10} الوصف")
            hr()
            for i, g in enumerate(groups, 1):
                print(f"  {i:<3} #{g['name']:<24} {g['members']:<10} {g.get('description','')[:25]}")
            hr()
            pick = input("  رقم الجروب: ").strip()
            try:
                idx = int(pick) - 1
                if 0 <= idx < len(groups):
                    gname = groups[idx]["name"]
                    code, r = http("POST", "/groups/join", {"name": gname})
                    if code == 200 and r.get("ok"):
                        ok(f"انضممت إلى #{gname}")
                        chat_loop("group", gname)
                    else:
                        err(str(r.get("msg") or "فشل"))
            except ValueError:
                pass
        elif c == "b":
            return
        else:
            warn("خيار غير صحيح")

# ================= إظهار الرسائل =================
def fetch_messages(chat_type, chat_id):
    if chat_type == "dm":
        code, r = http("GET", "/messages/dm?with=" + chat_id)
    else:
        code, r = http("GET", "/messages/group?name=" + chat_id)
    if not (code == 200 and r.get("ok")):
        return None
    return r.get("messages", [])

def show_messages(chat_type, chat_id):
    msgs = fetch_messages(chat_type, chat_id)
    if msgs is None:
        return err("فشل جلب الرسائل")
    label = f"@{chat_id}" if chat_type == "dm" else f"#{chat_id}"
    print()
    hr()
    print(f"  {C.CY}{C.BOLD}{label}{C.X}  ({len(msgs)} رسالة)")
    hr()
    if not msgs:
        info("لا رسائل — ابدأ الكتابة")
        hr()
        return
    for m in msgs:
        t = time.strftime("%H:%M", time.localtime(m["ts"]))
        arrow = f"{C.G}→{C.X}" if m["from"] == STATE["username"] else f"{C.CY}←{C.X}"
        sender = "" if m["from"] == STATE["username"] else f"{C.M}@{m['from']}{C.X}: "
        if chat_type == "group" and m["from"] == STATE["username"]:
            sender = f"{C.D}(أنت){C.X}: "
        kind = m.get("type", "text")
        content = m.get("content", "")
        if kind == "image":
            try:
                d = json.loads(content)
                content = f"{C.M}📷{C.X} {d.get('name','')} id={d.get('file_id','')[:10]}"
            except Exception:
                pass
        elif kind == "file":
            try:
                d = json.loads(content)
                content = f"{C.M}📎{C.X} {d.get('name','')} id={d.get('file_id','')[:10]}"
            except Exception:
                pass
        elif kind == "link":
            content = f"{C.B}🔗{C.X} {content}"
        print(f"  {C.D}{t}{C.X} {arrow} {sender}{content}")
    hr()

# ================= الإرسال =================
def send_message(chat_type, chat_id, content, mtype="text"):
    if chat_type == "dm":
        path, body = "/messages/dm", {"to": chat_id, "content": content, "type": mtype}
    else:
        path, body = "/messages/group", {"name": chat_id, "content": content, "type": mtype}
    code, r = http("POST", path, body)
    if code == 200 and r.get("ok"):
        return True
    err(str(r.get("msg") or "فشل"))
    return False

def send_blob(chat_type, chat_id, path, mtype):
    path = path.strip().strip('"').strip("'")
    if not os.path.exists(path):
        return err("الملف غير موجود")
    size = os.path.getsize(path)
    if size > 25 * 1024 * 1024:
        return err("> 25MB")
    name = os.path.basename(path)
    mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
    info(f"رفع {name} ({size//1024}KB)...")
    with open(path, "rb") as f:
        data = f.read()
    code, r = http(
        "POST",
        "/files",
        raw=data,
        headers={"X-Filename": name, "X-Mime": mime, "Content-Type": "application/octet-stream"},
    )
    if not (code == 200 and r.get("ok")):
        return err("فشل الرفع")
    payload = json.dumps(
        {"file_id": r["file_id"], "name": r["name"], "size": r["size"]}, ensure_ascii=False
    )
    send_message(chat_type, chat_id, payload, mtype)

def download_file(fid):
    fid = fid.strip()
    if not re.match(r"^[a-f0-9]{32}$", fid):
        return err("id غير صالح")
    info("تنزيل...")
    code, data = http("GET", "/files?id=" + fid)
    if code != 200 or not isinstance(data, (bytes, bytearray)):
        return err("فشل")
    out = f"spider_{fid[:8]}.bin"
    with open(out, "wb") as f:
        f.write(data)
    ok(f"حفظ في: {out}")

# ================= حلقة الشات =================
def chat_loop(chat_type, chat_id):
    STATE["chat"] = {"type": chat_type, "id": chat_id}
    label = f"@{chat_id}" if chat_type == "dm" else f"#{chat_id}"
    show_messages(chat_type, chat_id)
    print(f"  {C.D}/send /link /image /file /download /refresh /members /back{C.X}")
    while True:
        try:
            line = input(f"\n{C.CY}{label}{C.X} → ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            STATE["chat"] = None
            return
        if not line:
            continue
        if line in ("/back", "/exit", "/q"):
            STATE["chat"] = None
            return
        sent = False
        if line.startswith("/send "):
            sent = send_message(chat_type, chat_id, line[6:])
        elif line.startswith("/link "):
            sent = send_message(chat_type, chat_id, line[6:].strip(), "link")
        elif line.startswith("/image "):
            send_blob(chat_type, chat_id, line[7:], "image")
            sent = True
        elif line.startswith("/file "):
            send_blob(chat_type, chat_id, line[6:], "file")
            sent = True
        elif line.startswith("/download "):
            download_file(line[10:])
        elif line == "/refresh":
            sent = True
        elif line == "/members" and chat_type == "group":
            code, r = http("GET", "/groups/members?name=" + chat_id)
            if code == 200 and r.get("ok"):
                print()
                for m in r["members"]:
                    role = f"{C.Y}★{C.X}" if m.get("role") == "admin" else " "
                    print(f"  {role} @{m['username']:<20} {C.D}{m.get('display_name','')}{C.X}")
        elif line.startswith("/"):
            warn("أمر غير معروف")
        else:
            sent = send_message(chat_type, chat_id, line)
        if sent:
            show_messages(chat_type, chat_id)

# ================= القائمة الرئيسية =================
def menu():
    while True:
        banner()
        if not STATE["token"]:
            print(
                f"  {C.G}[1]{C.X} تسجيل    {C.G}[2]{C.X} دخول    "
                f"{C.G}[4]{C.X} اتصال بسيرفر آخر    {C.G}[q]{C.X} خروج"
            )
            c = input(f"\n  {C.CY}>{C.X} ").strip().lower()
            if c == "1":
                do_register()
            elif c == "2":
                do_login()
            elif c == "4":
                new = input("  URL (http://ip:8000): ").strip()
                if new:
                    STATE["server"] = new.rstrip("/")
                    code, _ = http("GET", "/health")
                    if code == 200:
                        ok("متصل")
                    else:
                        warn("فشل الاتصال")
            elif c == "q":
                return
        else:
            print(
                f"  {C.G}[u]{C.X} المستخدمون   {C.G}[c]{C.X} شات   {C.G}[g]{C.X} الجروبات   "
                f"{C.G}[s]{C.X} بحث   {C.G}[o]{C.X} خروج   {C.G}[q]{C.X} إنهاء"
            )
            c = input(f"\n  {C.CY}>{C.X} ").strip().lower()
            if c == "u":
                users, _ = list_users()
                if users:
                    pick = input("  رقم للشات (Enter للتجاهل): ").strip()
                    if pick:
                        try:
                            idx = int(pick) - 1
                            if 0 <= idx < len(users):
                                chat_loop("dm", users[idx]["username"])
                        except ValueError:
                            pass
            elif c == "c":
                peer = input("  @username: ").strip().lower()
                if USERNAME_RE.match(peer):
                    chat_loop("dm", peer)
                else:
                    err("صيغة غير صحيحة")
            elif c == "g":
                groups_menu()
            elif c == "s":
                do_search()
            elif c == "o":
                do_logout()
            elif c == "q":
                return
        print()

# ================= Main =================
def main():
    global STATE

    ap = argparse.ArgumentParser(description="SPIDER — أداة تواصل التقنيين")
    ap.add_argument("--port", type=int, default=8000, help="منفذ الخادم (افتراضي 8000)")
    ap.add_argument("--connect", help="اتصل بسيرفر آخر بدلاً من تشغيل خادم محلي")
    ap.add_argument("--no-server", action="store_true", help="لا تشغّل خادم (استخدم --connect)")
    args = ap.parse_args()

    STATE["port"] = args.port

    if args.connect:
        STATE["server"] = args.connect.rstrip("/")
        STATE["local_ip"] = "remote"
        STATE["public_ip"] = None
        code, _ = http("GET", "/health")
        if code != 200:
            warn(f"لا يمكن الاتصال بـ {STATE['server']}")
    elif args.no_server:
        STATE["server"] = f"http://127.0.0.1:{STATE['port']}"
        STATE["local_ip"] = "127.0.0.1"
        STATE["public_ip"] = None
        code, _ = http("GET", "/health")
        if code != 200:
            err(f"لا يوجد خادم على {STATE['server']}")
            sys.exit(1)
    else:
        print(f"{C.CY}▶ بدء تشغيل الخادم...{C.X}")
        STATE["local_ip"] = detect_local_ip()
        try:
            STATE["public_ip"] = detect_public_ip()
        except Exception:
            STATE["public_ip"] = None

        try:
            srv = ThreadingHTTPServer(("0.0.0.0", STATE["port"]), API)
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
        except OSError as e:
            if "Address already in use" in str(e) or "10048" in str(e):
                warn(f"المنفذ {STATE['port']} مشغول — سيتم الاتصال بخادم موجود")
            else:
                err(f"فشل تشغيل الخادم: {e}")
                sys.exit(1)

        STATE["server"] = f"http://127.0.0.1:{STATE['port']}"
        time.sleep(0.5)

        print(f"{C.G}✓ الخادم يعمل{C.X}")
        print(f"  {C.D}» Local:{C.X}  {C.G}http://{STATE['local_ip']}:{STATE['port']}{C.X}")
        if STATE["public_ip"]:
            print(
                f"  {C.D}» Public:{C.X} {C.CY}http://{STATE['public_ip']}:{STATE['port']}{C.X} {C.D}(يحتاج port forward){C.X}"
            )
        print(f"  {C.D}شارك الرابط مع أصدقائك، أو استخدم [4] للاتصال بسيرفر آخر{C.X}\n")

    try:
        menu()
    except (KeyboardInterrupt, EOFError):
        print(f"\n{C.D}وداعاً{C.X}")

if __name__ == "__main__":
    main()