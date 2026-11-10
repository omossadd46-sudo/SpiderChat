#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    ███████╗██████╗ ██╗██████╗ ███████╗██████╗ 
    ██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗
    ███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝
    ╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗
    ███████║██║     ██║██████╔╝███████╗██║  ██║
    ╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝

SPIDER — أداة تواصل التقنيين
"""

import os, sys, re, json, time, argparse, secrets, mimetypes, getpass
import requests

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
except ImportError:
    print("pip install argon2-cffi"); sys.exit(1)

PH = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=4)

DEFAULT_SERVER = "http://127.0.0.1:8000"
USERNAME_RE = re.compile(r"^[a-z0-9_]{4,20}$")
GROUP_RE    = re.compile(r"^[a-z0-9_\-]{3,32}$")

STATE = {"server": DEFAULT_SERVER, "token": None, "username": None,
         "display": None, "chat": None}

class C:
    R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"; M="\033[95m"
    CY="\033[96m"; W="\033[97m"; D="\033[2m"; BOLD="\033[1m"; X="\033[0m"

def hr(): print(C.D + "─" * 66 + C.X)
def ok(m):   print(f"  {C.G}✓{C.X} {m}")
def err(m):  print(f"  {C.R}✗{C.X} {m}")
def info(m): print(f"  {C.B}ℹ{C.X} {m}")
def warn(m): print(f"  {C.Y}!{C.X} {m}")

SPIDER_ART = f"""{C.M}
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║      ███████╗██████╗ ██╗██████╗ ███████╗██████╗           ║
    ║      ██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗          ║
    ║      ███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝          ║
    ║      ╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗          ║
    ║      ███████║██║     ██║██████╔╝███████╗██║  ██║          ║
    ║      ╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝          ║
    ║                                                           ║
    ║              {C.CY}أداة تواصل التقنيين{C.M}  v2.0                  ║
    ╚═══════════════════════════════════════════════════════════╝{C.X}"""

def banner():
    print(SPIDER_ART)
    print(f"  {C.D}» DB:{C.X} {STATE['server']}")
    if STATE["username"]:
        print(f"  {C.D}» User:{C.X} {C.G}{STATE['display']}{C.X} {C.D}(@{STATE['username']}){C.X}")
        if STATE["chat"]:
            c = STATE["chat"]
            label = f"@{c['id']}" if c["type"] == "dm" else f"#{c['id']}"
            print(f"  {C.D}» Chat:{C.X} {C.CY}{label}{C.X}")
    else:
        print(f"  {C.D}» User:{C.X} {C.Y}(غير مسجل){C.X}")
    hr()

def http(method, path, body=None, headers=None, raw=None, timeout=30):
    url = STATE["server"].rstrip("/") + path
    h = {"User-Agent": "SPIDER/2.0"}
    if STATE["token"]: h["Authorization"] = "Bearer " + STATE["token"]
    if headers: h.update(headers)
    try:
        if raw is not None:
            r = requests.request(method, url, data=raw, headers=h, timeout=timeout)
        elif body is not None:
            h["Content-Type"] = "application/json"
            r = requests.request(method, url, json=body, headers=h, timeout=timeout)
        else:
            r = requests.request(method, url, headers=h, timeout=timeout)
        try: data = r.json()
        except: data = r.content
        return r.status_code, data
    except requests.exceptions.RequestException as e:
        return 0, {"ok": False, "msg": f"فشل الاتصال: {e}"}

# ================= التسجيل والدخول =================
def do_register():
    print(f"\n{C.CY}{C.BOLD}── إنشاء حساب جديد ──{C.X}")
    username = input("  اليوزر (a-z0-9_, 4-20): ").strip().lower()
    if not USERNAME_RE.match(username): return err("الصيغة غير صحيحة")
    code, r = http("GET", "/accounts/exists?username=" + username)
    if code != 200: return err("فشل الاتصال")
    if r.get("exists"): return err("اليوزر محجوز")
    display = input("  الاسم الظاهر: ").strip()[:40]
    if not display: return err("مطلوب")
    pw = getpass.getpass("  كلمة المرور (8+): ")
    pw2 = getpass.getpass("  تأكيد: ")
    if len(pw) < 8: return err("قصيرة")
    if pw != pw2: return err("غير متطابقة")
    code, r = http("POST", "/accounts", {"username": username, "display_name": display,
                                         "password_hash": PH.hash(pw)})
    if code == 200 and r.get("ok"): ok(f"تم إنشاء @{username}")
    elif code == 409: err("محجوز")
    else: err(str(r.get("msg") or r))

def do_login():
    print(f"\n{C.CY}{C.BOLD}── تسجيل الدخول ──{C.X}")
    username = input("  اليوزر: ").strip().lower()
    pw = getpass.getpass("  كلمة المرور: ")
    code, r = http("GET", "/accounts/lookup?username=" + username)
    if code == 404: return err("غير موجود")
    if code != 200: return err("فشل الاتصال")
    acc = r.get("account", {})
    try:
        if not PH.verify(acc["password_hash"], pw): return err("كلمة المرور خاطئة")
    except VerifyMismatchError: return err("كلمة المرور خاطئة")
    except Exception: return err("فشل التحقق")
    token = secrets.token_urlsafe(48)
    code, r2 = http("POST", "/sessions", {"username": username, "token": token, "ttl": 604800})
    if not (code == 200 and r2.get("ok")): return err("فشل إنشاء جلسة")
    STATE["token"] = token; STATE["username"] = username
    STATE["display"] = acc.get("display_name", username)
    ok(f"مرحباً {STATE['display']}")

def do_logout():
    if STATE["token"]: http("POST", "/sessions/delete")
    STATE.update(token=None, username=None, display=None, chat=None)
    ok("خرجت")

# ================= البحث =================
def do_search():
    print(f"\n{C.CY}{C.BOLD}── بحث ──{C.X}")
    q = input("  استعلام: ").strip()
    if not q: return
    code, r = http("GET", "/search/users?q=" + q)
    users = r.get("users", []) if code == 200 else []
    code, r2 = http("GET", "/search/messages?q=" + q)
    msgs = r2.get("messages", []) if code == 200 else []
    print(); hr()
    print(f"  {C.BOLD}المستخدمون ({len(users)}){C.X}"); hr()
    if users:
        for i, u in enumerate(users, 1):
            print(f"  {i:>2}. @{u['username']:<20} {C.D}{u.get('display_name','')}{C.X}")
    else: info("لا نتائج")
    print(); hr()
    print(f"  {C.BOLD}الرسائل ({len(msgs)}){C.X}"); hr()
    if msgs:
        for m in msgs[:20]:
            t = time.strftime("%m-%d %H:%M", time.localtime(m["ts"]))
            print(f"  {C.D}[{t}]{C.X} {C.CY}@{m['from']}→@{m['to']}{C.X}  {m['content'][:80]}")
    else: info("لا نتائج")
    hr()

# ================= المستخدمون =================
def list_users():
    code, r = http("GET", "/accounts")
    if not (code == 200 and r.get("ok")):
        return err("فشل"), []
    users = r["accounts"]
    if not users:
        info("لا مستخدمين"); return [], []
    print(); hr()
    print(f"  {C.BOLD}{'#':<3} {'@username':<22} {'الاسم':<28} الحالة{C.X}"); hr()
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
            if code != 200 or not r.get("ok"): err("فشل"); continue
            groups = r["groups"]
            if not groups: info("لا جروبات"); continue
            hr()
            print(f"  {'#':<3} {'الاسم':<25} {'الأعضاء':<10} {'خاص؟':<5}"); hr()
            for i, g in enumerate(groups, 1):
                priv = "🔒" if g.get("is_private") else "🌐"
                print(f"  {i:<3} #{g['name']:<24} {g['members']:<10} {priv}")
            hr()
            pick = input("  رقم للدخول (Enter لتجاهل): ").strip()
            if pick:
                try:
                    idx = int(pick) - 1
                    if 0 <= idx < len(groups): chat_loop("group", groups[idx]["name"])
                except ValueError: pass
        elif c == "2":
            name = input("  اسم الجروب (a-z0-9_-, 3-32): ").strip().lower()
            if not GROUP_RE.match(name): err("صيغة"); continue
            desc = input("  وصف: ").strip()[:200]
            priv = input("  خاص؟ (y/N): ").strip().lower() == "y"
            code, r = http("POST", "/groups", {"name": name, "description": desc, "is_private": priv})
            if code == 200 and r.get("ok"):
                ok(f"أنشأت #{name}"); chat_loop("group", name)
            else: err(str(r.get("msg") or r))
        elif c == "3":
            code, r = http("GET", "/groups/public")
            if code != 200 or not r.get("ok"): err("فشل"); continue
            groups = r["groups"]
            if not groups: info("لا جروبات عامة"); continue
            hr()
            print(f"  {'#':<3} {'الاسم':<25} {'الأعضاء':<10} الوصف"); hr()
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
                        ok(f"انضممت إلى #{gname}"); chat_loop("group", gname)
                    else: err(str(r.get("msg") or "فشل"))
            except ValueError: pass
        elif c == "b": return
        else: warn("خيار غير صحيح")

# ================= إظهار الرسائل =================
def fetch_messages(chat_type, chat_id):
    if chat_type == "dm":
        code, r = http("GET", "/messages/dm?with=" + chat_id)
    else:
        code, r = http("GET", "/messages/group?name=" + chat_id)
    if not (code == 200 and r.get("ok")): return None
    return r.get("messages", [])

def show_messages(chat_type, chat_id):
    msgs = fetch_messages(chat_type, chat_id)
    if msgs is None: return err("فشل جلب الرسائل")
    label = f"@{chat_id}" if chat_type == "dm" else f"#{chat_id}"
    print(); hr()
    print(f"  {C.CY}{C.BOLD}{label}{C.X}  ({len(msgs)} رسالة)"); hr()
    if not msgs:
        info("لا رسائل — ابدأ الكتابة"); hr(); return
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
            except: pass
        elif kind == "file":
            try:
                d = json.loads(content)
                content = f"{C.M}📎{C.X} {d.get('name','')} id={d.get('file_id','')[:10]}"
            except: pass
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
    if code == 200 and r.get("ok"): return True
    err(str(r.get("msg") or "فشل")); return False

def send_blob(chat_type, chat_id, path, mtype):
    path = path.strip().strip('"').strip("'")
    if not os.path.exists(path): return err("الملف غير موجود")
    size = os.path.getsize(path)
    if size > 25 * 1024 * 1024: return err("> 25MB")
    name = os.path.basename(path)
    mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
    info(f"رفع {name} ({size//1024}KB)...")
    with open(path, "rb") as f: data = f.read()
    code, r = http("POST", "/files", raw=data,
                   headers={"X-Filename": name, "X-Mime": mime,
                            "Content-Type": "application/octet-stream"})
    if not (code == 200 and r.get("ok")): return err("فشل الرفع")
    payload = json.dumps({"file_id": r["file_id"], "name": r["name"], "size": r["size"]},
                        ensure_ascii=False)
    send_message(chat_type, chat_id, payload, mtype)

def download_file(fid):
    fid = fid.strip()
    if not re.match(r"^[a-f0-9]{32}$", fid): return err("id غير صالح")
    info("تنزيل...")
    code, data = http("GET", "/files?id=" + fid)
    if code != 200 or not isinstance(data, (bytes, bytearray)): return err("فشل")
    out = f"spider_{fid[:8]}.bin"
    with open(out, "wb") as f: f.write(data)
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
            print(); STATE["chat"] = None; return
        if not line: continue
        if line in ("/back", "/exit", "/q"):
            STATE["chat"] = None; return
        sent = False
        if line.startswith("/send "):
            sent = send_message(chat_type, chat_id, line[6:])
        elif line.startswith("/link "):
            sent = send_message(chat_type, chat_id, line[6:].strip(), "link")
        elif line.startswith("/image "):
            send_blob(chat_type, chat_id, line[7:], "image"); sent = True
        elif line.startswith("/file "):
            send_blob(chat_type, chat_id, line[6:], "file"); sent = True
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
        if sent: show_messages(chat_type, chat_id)

# ================= القائمة الرئيسية =================
def menu():
    while True:
        banner()
        if not STATE["token"]:
            print(f"  {C.G}[1]{C.X} تسجيل    {C.G}[2]{C.X} دخول    {C.G}[3]{C.X} السيرفر    {C.G}[q]{C.X} خروج")
            c = input(f"\n  {C.CY}>{C.X} ").strip().lower()
            if c == "1": do_register()
            elif c == "2": do_login()
            elif c == "3":
                new = input("  URL (http://ip:8000): ").strip()
                if new:
                    STATE["server"] = new.rstrip("/")
                    code, _ = http("GET", "/health")
                    ok("متصل") if code == 200 else warn("فشل الاتصال")
            elif c == "q": return
        else:
            print(f"  {C.G}[u]{C.X} المستخدمون   {C.G}[c]{C.X} شات   {C.G}[g]{C.X} الجروبات   "
                  f"{C.G}[s]{C.X} بحث   {C.G}[o]{C.X} خروج   {C.G}[q]{C.X} إنهاء")
            c = input(f"\n  {C.CY}>{C.X} ").strip().lower()
            if c == "u":
                users, _ = list_users()
                if users:
                    pick = input("  رقم للشات (Enter للتجاهل): ").strip()
                    if pick:
                        try:
                            idx = int(pick) - 1
                            if 0 <= idx < len(users): chat_loop("dm", users[idx]["username"])
                        except ValueError: pass
            elif c == "c":
                peer = input("  @username: ").strip().lower()
                if USERNAME_RE.match(peer): chat_loop("dm", peer)
                else: err("صيغة غير صحيحة")
            elif c == "g": groups_menu()
            elif c == "s": do_search()
            elif c == "o": do_logout()
            elif c == "q": return
        print()

def main():
    ap = argparse.ArgumentParser(description="SPIDER — أداة تواصل التقنيين")
    ap.add_argument("--server", help="عنوان قاعدة البيانات")
    args = ap.parse_args()
    if args.server: STATE["server"] = args.server.rstrip("/")
    code, _ = http("GET", "/health")
    if code != 200: warn(f"لا يمكن الاتصال بـ {STATE['server']}")
    try: menu()
    except (KeyboardInterrupt, EOFError): print(f"\n{C.D}وداعاً{C.X}")

if __name__ == "__main__":
    main()