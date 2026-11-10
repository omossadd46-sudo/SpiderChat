#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SPIDER DB Server — قاعدة بيانات خفيفة تعمل فوراً
- SQLite + تشفير Fernet (كل شيء مشفر على القرص)
- لا إعداد، لا تثبيت، فقط شغّلها

  python3 db_server.py
  → http://0.0.0.0:8000
"""

import os, re, json, time, base64, hashlib, secrets, sqlite3, mimetypes
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
from cryptography.fernet import Fernet

HOST     = "0.0.0.0"
PORT     = 8000
BASE     = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE, "spider.db")
KEY_PATH = os.path.join(BASE, "spider.key")
BLOB_DIR = os.path.join(BASE, "blobs")
MAX_BODY = 30 * 1024 * 1024
USERNAME_RE = re.compile(r"^[a-z0-9_]{4,20}$")
GROUP_RE    = re.compile(r"^[a-z0-9_\-]{3,32}$")
TOKEN_RE    = re.compile(r"^[A-Za-z0-9_\-]{20,120}$")

os.makedirs(BLOB_DIR, exist_ok=True)

# ============ تشفير ============
def _load_key():
    if not os.path.exists(KEY_PATH):
        with open(KEY_PATH, "wb") as f:
            f.write(secrets.token_bytes(32))
        try: os.chmod(KEY_PATH, 0o600)
        except: pass
    with open(KEY_PATH, "rb") as f:
        return f.read()

MASTER = _load_key()
FERNET = Fernet(base64.urlsafe_b64encode(hashlib.sha256(MASTER).digest()))
def enc(b): return FERNET.encrypt(b)
def dec(b): return FERNET.decrypt(b)
def sha(b): return hashlib.sha256(b).hexdigest()

# ============ DB ============
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
    CREATE INDEX IF NOT EXISTS idx_sess_user ON sessions(username);
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
    CREATE INDEX IF NOT EXISTS idx_dm_pair ON messages_dm(sender, recipient, id);
    CREATE TABLE IF NOT EXISTS messages_group(
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        group_name TEXT NOT NULL,
        sender     TEXT NOT NULL,
        enc        BLOB NOT NULL,
        msg_type   TEXT NOT NULL,
        sent_at    INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_gm_group ON messages_group(group_name, id);
    CREATE TABLE IF NOT EXISTS files(
        file_id    TEXT PRIMARY KEY,
        owner      TEXT NOT NULL,
        name       TEXT NOT NULL,
        mime       TEXT,
        size       INTEGER NOT NULL,
        sha256     TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    """)
    c.commit(); c.close()

init_db()

# ============ Helpers ============
def user_from_token(tok):
    if not tok or not TOKEN_RE.match(tok): return None
    c = db()
    r = c.execute("SELECT username,expires FROM sessions WHERE token=?", (tok,)).fetchone()
    c.close()
    if not r or r["expires"] < int(time.time()): return None
    return r["username"]

def user_exists(u):
    c = db(); r = c.execute("SELECT 1 FROM accounts WHERE username=?", (u,)).fetchone()
    c.close(); return bool(r)

def touch_user(u):
    c = db(); c.execute("UPDATE accounts SET last_seen=? WHERE username=?", (int(time.time()), u))
    c.commit(); c.close()

# ============ HTTP ============
class API(BaseHTTPRequestHandler):
    server_version = "SPIDER-DB/1.0"

    def log_message(self, *a): pass

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
            for k, v in extra.items(): self.send_header(k, v)
        self.end_headers()
        if body: self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode())

    def _body(self, limit=MAX_BODY + 8192):
        n = int(self.headers.get("Content-Length", "0"))
        if n <= 0 or n > limit: return None
        return self.rfile.read(n)

    def _jbody(self):
        raw = self._body()
        if not raw: return None
        try: return json.loads(raw.decode())
        except: return None

    def _tok(self):
        a = self.headers.get("Authorization", "")
        return a[7:].strip() if a.startswith("Bearer ") else None

    def _auth(self):
        u = user_from_token(self._tok())
        if u: touch_user(u)
        return u

    def do_OPTIONS(self): self._send(204)

    # ===================== GET =====================
    def do_GET(self):
        p = urlparse(self.path); path = p.path
        qs = parse_qs(p.query)

        if path == "/health":
            return self._json(200, {"ok": True, "time": int(time.time())})

        # ---------- accounts ----------
        if path == "/accounts/exists":
            u = (qs.get("username") or [""])[0].lower()
            return self._json(200, {"ok": True, "exists": user_exists(u)})

        if path == "/accounts/lookup":
            u = (qs.get("username") or [""])[0].lower()
            c = db()
            r = c.execute("SELECT username,display_name,password_hash FROM accounts WHERE username=?", (u,)).fetchone()
            c.close()
            if not r: return self._json(404, {"ok": False, "msg": "not_found"})
            return self._json(200, {"ok": True, "account": dict(r)})

        if path == "/accounts":
            if not self._auth(): return self._json(401, {"ok": False})
            c = db()
            rows = c.execute("SELECT username,display_name,last_seen FROM accounts ORDER BY username").fetchall()
            c.close()
            now = int(time.time())
            out = []
            for r in rows:
                online = r["last_seen"] and (now - r["last_seen"]) < 300
                out.append({"username": r["username"], "display_name": r["display_name"], "online": bool(online)})
            return self._json(200, {"ok": True, "accounts": out})

        # ---------- messages DM ----------
        if path == "/messages/dm":
            u = self._auth()
            if not u: return self._json(401, {"ok": False})
            peer = (qs.get("with") or [""])[0].lower()
            limit = int((qs.get("limit") or ["200"])[0])
            c = db()
            rows = c.execute("""
                SELECT id,sender,recipient,enc,msg_type,sent_at FROM messages_dm
                WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?)
                ORDER BY id DESC LIMIT ?
            """, (u, peer, peer, u, limit)).fetchall()
            c.close()
            out = []
            for r in rows:
                try: content = json.loads(dec(r["enc"]))["c"]
                except: content = "[!]"
                out.append({"id": r["id"], "from": r["sender"], "to": r["recipient"],
                            "content": content, "type": r["msg_type"], "ts": r["sent_at"]})
            out.reverse()
            return self._json(200, {"ok": True, "messages": out})

        # ---------- messages group ----------
        if path == "/messages/group":
            u = self._auth()
            if not u: return self._json(401, {"ok": False})
            name = (qs.get("name") or [""])[0].lower()
            c = db()
            m = c.execute("SELECT 1 FROM group_members WHERE group_name=? AND username=?", (name, u)).fetchone()
            if not m:
                c.close(); return self._json(403, {"ok": False, "msg": "لست عضواً"})
            rows = c.execute("SELECT id,sender,enc,msg_type,sent_at FROM messages_group WHERE group_name=? ORDER BY id DESC LIMIT 200", (name,)).fetchall()
            c.close()
            out = []
            for r in rows:
                try: content = json.loads(dec(r["enc"]))["c"]
                except: content = "[!]"
                out.append({"id": r["id"], "from": r["sender"], "group": name,
                            "content": content, "type": r["msg_type"], "ts": r["sent_at"]})
            out.reverse()
            return self._json(200, {"ok": True, "messages": out})

        # ---------- groups ----------
        if path == "/groups/mine":
            u = self._auth()
            if not u: return self._json(401, {"ok": False})
            c = db()
            rows = c.execute("""
                SELECT g.name,g.description,g.is_private,
                       (SELECT COUNT(*) FROM group_members WHERE group_name=g.name) as members
                FROM groups g JOIN group_members m ON m.group_name=g.name
                WHERE m.username=? ORDER BY g.name
            """, (u,)).fetchall()
            c.close()
            return self._json(200, {"ok": True, "groups": [
                {"name": r["name"], "description": r["description"] or "",
                 "is_private": bool(r["is_private"]), "members": r["members"]} for r in rows]})

        if path == "/groups/public":
            if not self._auth(): return self._json(401, {"ok": False})
            c = db()
            rows = c.execute("""
                SELECT g.name,g.description,
                       (SELECT COUNT(*) FROM group_members WHERE group_name=g.name) as members
                FROM groups g WHERE g.is_private=0 ORDER BY g.name
            """).fetchall()
            c.close()
            return self._json(200, {"ok": True, "groups": [
                {"name": r["name"], "description": r["description"] or "", "members": r["members"]} for r in rows]})

        if path == "/groups/members":
            u = self._auth()
            if not u: return self._json(401, {"ok": False})
            name = (qs.get("name") or [""])[0].lower()
            c = db()
            m = c.execute("SELECT 1 FROM group_members WHERE group_name=? AND username=?", (name, u)).fetchone()
            if not m:
                c.close(); return self._json(403, {"ok": False})
            rows = c.execute("""
                SELECT gm.username,gm.role,a.display_name FROM group_members gm
                LEFT JOIN accounts a ON a.username=gm.username
                WHERE gm.group_name=? ORDER BY gm.role DESC, gm.username
            """, (name,)).fetchall()
            c.close()
            return self._json(200, {"ok": True, "members": [
                {"username": r["username"], "role": r["role"],
                 "display_name": r["display_name"] or ""} for r in rows]})

        # ---------- search ----------
        if path == "/search/users":
            if not self._auth(): return self._json(401, {"ok": False})
            q = (qs.get("q") or [""])[0].lower()
            c = db()
            rows = c.execute("SELECT username,display_name FROM accounts WHERE username LIKE ? OR LOWER(display_name) LIKE ? ORDER BY username LIMIT 30",
                             (f"%{q}%", f"%{q}%")).fetchall()
            c.close()
            return self._json(200, {"ok": True, "users": [dict(r) for r in rows]})

        if path == "/search/messages":
            u = self._auth()
            if not u: return self._json(401, {"ok": False})
            q = (qs.get("q") or [""])[0].lower()
            c = db()
            rows = c.execute("""
                SELECT id,sender,recipient,enc,msg_type,sent_at FROM messages_dm
                WHERE (sender=? OR recipient=?)
                ORDER BY id DESC LIMIT 500
            """, (u, u)).fetchall()
            c.close()
            out = []
            for r in rows:
                try: content = json.loads(dec(r["enc"]))["c"]
                except: continue
                if q in content.lower():
                    out.append({"id": r["id"], "from": r["sender"], "to": r["recipient"],
                                "content": content, "ts": r["sent_at"], "type_ctx": "dm"})
                    if len(out) >= 30: break
            return self._json(200, {"ok": True, "messages": out})

        # ---------- files ----------
        if path == "/files":
            if not self._auth(): return self._json(401, {"ok": False})
            fid = (qs.get("id") or [""])[0]
            if not re.match(r"^[a-f0-9]{32}$", fid):
                return self._json(400, {"ok": False})
            c = db()
            r = c.execute("SELECT name,mime FROM files WHERE file_id=?", (fid,)).fetchone()
            c.close()
            if not r: return self._json(404, {"ok": False})
            path_disk = os.path.join(BLOB_DIR, fid + ".bin")
            if not os.path.exists(path_disk): return self._json(404, {"ok": False})
            with open(path_disk, "rb") as f: data = dec(f.read())
            return self._send(200, data, r["mime"] or "application/octet-stream",
                              extra={"Content-Disposition": f'attachment; filename="{r["name"]}"'})

        self._send(404, b'{"ok":false}')

    # ===================== POST =====================
    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/accounts":
            b = self._jbody() or {}
            u = (b.get("username") or "").strip().lower()
            disp = (b.get("display_name") or "").strip()[:40]
            ph = b.get("password_hash") or ""
            if not USERNAME_RE.match(u): return self._json(400, {"ok": False, "msg": "username"})
            if not disp or not ph:        return self._json(400, {"ok": False, "msg": "fields"})
            c = db()
            try:
                c.execute("INSERT INTO accounts(username,display_name,password_hash,created_at,last_seen) VALUES(?,?,?,?,?)",
                          (u, disp, ph, int(time.time()), int(time.time())))
                c.commit()
                return self._json(200, {"ok": True})
            except sqlite3.IntegrityError:
                return self._json(409, {"ok": False, "msg": "username_taken"})
            finally: c.close()

        if path == "/sessions":
            b = self._jbody() or {}
            u = (b.get("username") or "").lower()
            tok = b.get("token") or ""
            ttl = int(b.get("ttl") or 604800)
            if not u or not tok: return self._json(400, {"ok": False})
            if not user_exists(u): return self._json(404, {"ok": False})
            c = db()
            c.execute("INSERT OR REPLACE INTO sessions(token,username,expires,created_at) VALUES(?,?,?,?)",
                      (tok, u, int(time.time()) + ttl, int(time.time())))
            c.commit(); c.close()
            return self._json(200, {"ok": True})

        if path == "/sessions/delete":
            tok = self._tok()
            if tok:
                c = db(); c.execute("DELETE FROM sessions WHERE token=?", (tok,)); c.commit(); c.close()
            return self._json(200, {"ok": True})

        # ---------- messages DM ----------
        if path == "/messages/dm":
            u = self._auth()
            if not u: return self._json(401, {"ok": False})
            b = self._jbody() or {}
            to = (b.get("to") or "").lower()
            content = b.get("content") or ""
            mtype = b.get("type") or "text"
            if not USERNAME_RE.match(to): return self._json(400, {"ok": False})
            if not content: return self._json(400, {"ok": False})
            if not user_exists(to): return self._json(404, {"ok": False, "msg": "recipient_not_found"})
            payload = json.dumps({"c": content}, ensure_ascii=False).encode()
            c = db()
            c.execute("INSERT INTO messages_dm(sender,recipient,enc,msg_type,sent_at) VALUES(?,?,?,?,?)",
                      (u, to, enc(payload), mtype, int(time.time())))
            c.commit(); c.close()
            return self._json(200, {"ok": True})

        # ---------- messages group ----------
        if path == "/messages/group":
            u = self._auth()
            if not u: return self._json(401, {"ok": False})
            b = self._jbody() or {}
            name = (b.get("name") or "").lower()
            content = b.get("content") or ""
            mtype = b.get("type") or "text"
            if not content: return self._json(400, {"ok": False})
            c = db()
            m = c.execute("SELECT 1 FROM group_members WHERE group_name=? AND username=?", (name, u)).fetchone()
            if not m:
                c.close(); return self._json(403, {"ok": False, "msg": "لست عضواً"})
            payload = json.dumps({"c": content}, ensure_ascii=False).encode()
            c.execute("INSERT INTO messages_group(group_name,sender,enc,msg_type,sent_at) VALUES(?,?,?,?,?)",
                      (name, u, enc(payload), mtype, int(time.time())))
            c.commit(); c.close()
            return self._json(200, {"ok": True})

        # ---------- groups ----------
        if path == "/groups":
            u = self._auth()
            if not u: return self._json(401, {"ok": False})
            b = self._jbody() or {}
            name = (b.get("name") or "").lower()
            desc = (b.get("description") or "")[:200]
            priv = 1 if b.get("is_private") else 0
            if not GROUP_RE.match(name): return self._json(400, {"ok": False, "msg": "اسم غير صالح"})
            c = db()
            try:
                c.execute("INSERT INTO groups(name,owner,description,is_private,created_at) VALUES(?,?,?,?,?)",
                          (name, u, desc, priv, int(time.time())))
                c.execute("INSERT INTO group_members(group_name,username,role,joined_at) VALUES(?,?,?,?)",
                          (name, u, "admin", int(time.time())))
                c.commit()
                return self._json(200, {"ok": True})
            except sqlite3.IntegrityError:
                return self._json(409, {"ok": False, "msg": "الاسم محجوز"})
            finally: c.close()

        if path == "/groups/join":
            u = self._auth()
            if not u: return self._json(401, {"ok": False})
            b = self._jbody() or {}
            name = (b.get("name") or "").lower()
            c = db()
            g = c.execute("SELECT is_private FROM groups WHERE name=?", (name,)).fetchone()
            if not g:
                c.close(); return self._json(404, {"ok": False, "msg": "غير موجود"})
            if g["is_private"]:
                c.close(); return self._json(403, {"ok": False, "msg": "خاص"})
            try:
                c.execute("INSERT INTO group_members(group_name,username,role,joined_at) VALUES(?,?,?,?)",
                          (name, u, "member", int(time.time())))
                c.commit()
            except sqlite3.IntegrityError:
                pass
            c.close()
            return self._json(200, {"ok": True})

        # ---------- files ----------
        if path == "/files":
            u = self._auth()
            if not u: return self._json(401, {"ok": False})
            raw = self._body()
            if not raw: return self._json(400, {"ok": False})
            name = re.sub(r"[^\w\.\-]", "_", self.headers.get("X-Filename", "file"))[:80] or "file"
            mime = self.headers.get("X-Mime", "application/octet-stream")
            fid = secrets.token_hex(16)
            with open(os.path.join(BLOB_DIR, fid + ".bin"), "wb") as f:
                f.write(enc(raw))
            c = db()
            c.execute("INSERT INTO files(file_id,owner,name,mime,size,sha256,created_at) VALUES(?,?,?,?,?,?,?)",
                      (fid, u, name, mime, len(raw), sha(raw), int(time.time())))
            c.commit(); c.close()
            return self._json(200, {"ok": True, "file_id": fid, "name": name, "size": len(raw)})

        self._send(404, b'{"ok":false}')

def main():
    srv = ThreadingHTTPServer((HOST, PORT), API)
    print(f"\n\033[96m╔══════════════════════════════════════════╗")
    print(f"║  SPIDER DB Server                        ║")
    print(f"║  http://{HOST}:{PORT}                    ║")
    print(f"╚══════════════════════════════════════════╝\033[0m")
    print(f"  DB:   {DB_PATH}")
    print(f"  Key:  {KEY_PATH}")
    print(f"  Blobs: {BLOB_DIR}\n")
    try: srv.serve_forever()
    except KeyboardInterrupt: print("\n[!] إيقاف")

if __name__ == "__main__":
    main()