#!/usr/bin/env python3
"""
sambapanel — маленькая веб-панель в стиле терминала для управления
пользователями Samba на локальном Linux-сервере.

ВАЖНО:
- Это приложение НИКОГДА не запускается от root.
- Все привилегированные операции идут через `sudo samba-admin-helper.sh`,
  которому разрешено выполняться от root только для этого одного скрипта
  (см. samba-admin.sudoers).
- Приложение должно быть доступно ТОЛЬКО из локальной сети. Никогда не
  выставляй его в интернет без VPN — здесь нет защиты от брутфорса пароля
  сверх простой сессии, и это создаёт пользователей в системе.
"""

import base64
import ipaddress
import os
import re
import secrets
import subprocess
import time
from collections import defaultdict
from datetime import datetime, timezone
from functools import wraps
from threading import Lock

from flask import Flask, render_template, request, redirect, url_for, session, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get("SAMBAPANEL_SECRET") or secrets.token_hex(32)

AUDIT_LOG_PATH = os.environ.get("SAMBAPANEL_AUDIT_LOG", "/var/log/sambapanel/audit.log")
_AUDIT_LOCK = Lock()


def audit_log(action, ok, detail=""):
    """Пишет строку в журнал действий. Никогда не бросает исключение —
    сбой логирования не должен ронять саму операцию."""
    try:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        ip = request.remote_addr or "unknown"
        status = "OK" if ok else "FAIL"
        line = f"{ts} | {ip} | {status:4} | {action}"
        if detail:
            first_line = detail.strip().splitlines()[0] if detail.strip() else ""
            if first_line:
                line += f" | {first_line[:200]}"
        with _AUDIT_LOCK:
            os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
            with open(AUDIT_LOG_PATH, "a") as f:
                f.write(line + "\n")
    except Exception:
        pass

ADMIN_PASSWORD = os.environ.get("SAMBAPANEL_PASSWORD")
if not ADMIN_PASSWORD:
    raise RuntimeError(
        "Задай переменную окружения SAMBAPANEL_PASSWORD перед запуском.\n"
        "Пример: export SAMBAPANEL_PASSWORD='твой-пароль-для-входа-в-панель'"
    )

HELPER = "/usr/local/sbin/samba-admin-helper.sh"
USERNAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
SHARENAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$")
SHAREPATH_RE = re.compile(r"^/[A-Za-z0-9_./-]+$")
RESERVED_SHARE_NAMES = {"global", "homes", "printers", "print$", "netlogon", "profiles"}
HOST_TOKEN_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")
VETO_TOKEN_RE = re.compile(r"^[a-zA-Z0-9]{1,10}$")


def validate_hosts_field(hosts_str):
    """Проверяет список IP/подсетей через запятую, или 'ALL'. Возвращает (ok, normalized)."""
    hosts_str = (hosts_str or "ALL").strip()
    if not hosts_str or hosts_str.upper() == "ALL":
        return True, "ALL"
    tokens = [t.strip() for t in hosts_str.split(",") if t.strip()]
    if not tokens:
        return True, "ALL"
    for t in tokens:
        if not HOST_TOKEN_RE.match(t):
            return False, None
        try:
            ipaddress.ip_network(t, strict=False)
        except ValueError:
            return False, None
    return True, ",".join(tokens)


def validate_veto_field(veto_str):
    """Проверяет список расширений через запятую, или 'NONE'. Возвращает (ok, normalized)."""
    veto_str = (veto_str or "NONE").strip()
    if not veto_str or veto_str.upper() == "NONE":
        return True, "NONE"
    tokens = [t.strip().lstrip(".") for t in veto_str.split(",") if t.strip()]
    if not tokens:
        return True, "NONE"
    for t in tokens:
        if not VETO_TOKEN_RE.match(t):
            return False, None
    return True, ",".join(tokens)


def validate_retention_days(value):
    """0 = хранить вечно, N>0 = дней до автоочистки. Возвращает (ok, normalized_str)."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return False, None
    if n < 0 or n > 9999:
        return False, None
    return True, str(n)


def validate_quota_bytes(value):
    """0 = без лимита. Возвращает (ok, normalized_str). Мониторинговая квота,
    не ограничение файловой системы — см. README."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return False, None
    if n < 0 or n > 10**15:
        return False, None
    return True, str(n)


def validate_backup_flag(value):
    return "yes" if value else "no"


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("authed"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped


# --- Rate-limit на вход в панель ---
# В памяти процесса (панель — один процесс Flask, без нескольких воркеров,
# так что это безопасно и не нужен внешний Redis/файл для такой простой задачи).
# Логика: после каждой неудачной попытки IP получает экспоненциально растущую
# задержку до следующей попытки (2с, 4с, 8с, 16с... до потолка), а не жёсткую
# блокировку на N минут — жёсткая блокировка по IP легко превращается в DoS
# против легитимного пользователя, если атакующий просто знает его IP.
_LOGIN_ATTEMPTS_LOCK = Lock()
_login_attempts = defaultdict(lambda: {"count": 0, "blocked_until": 0.0})
_LOGIN_BASE_DELAY = 2        # секунд задержки после первой ошибки
_LOGIN_MAX_DELAY = 300       # потолок — 5 минут
_LOGIN_RESET_AFTER = 900     # если 15 минут не было попыток — счётчик сбрасывается


def _client_ip():
    return request.remote_addr or "unknown"


def _login_check_blocked(ip):
    """Возвращает секунды до разрешённой следующей попытки (0, если можно пробовать)."""
    with _LOGIN_ATTEMPTS_LOCK:
        rec = _login_attempts[ip]
        remaining = rec["blocked_until"] - time.time()
        return max(0, remaining)


def _login_register_failure(ip):
    with _LOGIN_ATTEMPTS_LOCK:
        rec = _login_attempts[ip]
        now = time.time()
        # если давно не пытались — считаем это новой серией попыток
        if now - rec.get("last_attempt", 0) > _LOGIN_RESET_AFTER:
            rec["count"] = 0
        rec["count"] += 1
        rec["last_attempt"] = now
        delay = min(_LOGIN_BASE_DELAY * (2 ** (rec["count"] - 1)), _LOGIN_MAX_DELAY)
        rec["blocked_until"] = now + delay
        return delay


def _login_register_success(ip):
    with _LOGIN_ATTEMPTS_LOCK:
        _login_attempts.pop(ip, None)


_READONLY_COMMANDS = {"list_users", "list_shares", "active_connections", "disk_usage"}


def run_helper(args, stdin_text=None):
    """Запускает хелпер через sudo. Возвращает (ok, output).

    Пароли никогда не попадают в args (только через stdin_text), поэтому
    весь args можно безопасно писать в журнал действий без редактирования.
    Read-only команды (списки, статус) в журнал не пишутся — иначе он
    захлёбывается обновлениями списков на каждый рефреш страницы, и
    реальные действия (создал/удалил/поменял) тонут в этом шуме.
    """
    try:
        proc = subprocess.run(
            ["sudo", "-n", HELPER] + args,
            input=stdin_text,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        ok = proc.returncode == 0
        output = output.strip()
        if args and args[0] not in _READONLY_COMMANDS:
            audit_log(" ".join(args), ok, output)
        return ok, output
    except subprocess.TimeoutExpired:
        audit_log(" ".join(args), False, "таймаут")
        return False, "ERROR: операция превысила таймаут"
    except FileNotFoundError:
        audit_log(" ".join(args), False, "sudo/хелпер не найден")
        return False, "ERROR: sudo или хелпер-скрипт не найден на сервере"


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    ip = _client_ip()

    if request.method == "POST":
        wait = _login_check_blocked(ip)
        if wait > 0:
            error = f"слишком много неудачных попыток — подожди {int(wait)} сек. и попробуй снова"
        elif request.form.get("password") == ADMIN_PASSWORD:
            _login_register_success(ip)
            audit_log("login", True)
            session["authed"] = True
            return redirect(url_for("index"))
        else:
            delay = _login_register_failure(ip)
            audit_log("login", False, "неверный пароль")
            error = f"неверный пароль (следующая попытка через {int(delay)} сек.)"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    ok, output = run_helper(["list_users"])
    return render_template("index.html", users_output=output)


AD_GROUP_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.-]+(\\[A-Za-z0-9_.-]+)?$")


def validate_share_group_field(group):
    """Разрешает обычное локальное имя группы, 'AD:группа' или
    'ADUSERS:user1,user2'. Возвращает (ok, normalized)."""
    group = (group or "").strip()
    if group.startswith("AD:"):
        adg = group[3:].strip()
        if not adg or not AD_GROUP_TOKEN_RE.match(adg):
            return False, None
        return True, f"AD:{adg}"
    if group.startswith("ADUSERS:"):
        adu = group[8:].strip()
        tokens = [t.strip() for t in adu.split(",") if t.strip()]
        if not tokens:
            return False, None
        for t in tokens:
            if not AD_GROUP_TOKEN_RE.match(t):
                return False, None
        return True, "ADUSERS:" + ",".join(tokens)
    if not USERNAME_RE.match(group):
        return False, None
    return True, group


@app.route("/api/create_share", methods=["POST"])
@login_required
def api_create_share():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    path = (data.get("path") or "").strip()
    group_ok, group = validate_share_group_field(data.get("group") or "sharegroup")
    writable = "yes" if data.get("writable", True) else "no"
    hosts_ok, hosts = validate_hosts_field(data.get("hosts"))
    veto_ok, veto = validate_veto_field(data.get("veto"))
    recycle = "yes" if data.get("recycle", False) else "no"
    retention_ok, retention = validate_retention_days(data.get("retention_days", 0))
    antivirus = "yes" if data.get("antivirus", False) else "no"
    quota_ok, quota = validate_quota_bytes(data.get("quota_bytes", 0))
    backup = validate_backup_flag(data.get("backup", False))
    full_audit = "yes" if data.get("full_audit", False) else "no"

    if not SHARENAME_RE.match(name) or name.lower() in RESERVED_SHARE_NAMES:
        return jsonify(ok=False, output="ERROR: недопустимое или зарезервированное имя шары")
    if not SHAREPATH_RE.match(path) or ".." in path:
        return jsonify(ok=False, output="ERROR: недопустимый путь (нужен абсолютный путь без спецсимволов)")
    if not group_ok:
        return jsonify(ok=False, output="ERROR: недопустимое имя группы/AD-группы/AD-пользователей")
    if not hosts_ok:
        return jsonify(ok=False, output="ERROR: список IP/подсетей некорректен (пример: 192.168.1.0/24,10.0.0.5)")
    if not veto_ok:
        return jsonify(ok=False, output="ERROR: список расширений некорректен (пример: exe,bat,ps1)")
    if not retention_ok:
        return jsonify(ok=False, output="ERROR: срок хранения корзины должен быть числом дней от 0 до 9999")
    if not quota_ok:
        return jsonify(ok=False, output="ERROR: квота должна быть числом байт от 0")

    ok, output = run_helper(["create_share", name, path, group, writable, hosts, veto, recycle, retention, antivirus, quota, backup, full_audit])
    return jsonify(ok=ok, output=output)


@app.route("/api/set_share_group", methods=["POST"])
@login_required
def api_set_share_group():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    group_ok, group = validate_share_group_field(data.get("group") or "")

    if not SHARENAME_RE.match(name):
        return jsonify(ok=False, output="ERROR: недопустимое имя шары")
    if not group_ok:
        return jsonify(ok=False, output="ERROR: недопустимое имя группы/AD-группы/AD-пользователей")

    ok, output = run_helper(["set_share_group", name, group])
    return jsonify(ok=ok, output=output)


@app.route("/api/set_share_full_audit", methods=["POST"])
@login_required
def api_set_share_full_audit():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    full_audit = "yes" if data.get("full_audit", False) else "no"

    if not SHARENAME_RE.match(name):
        return jsonify(ok=False, output="ERROR: недопустимое имя шары")

    ok, output = run_helper(["set_share_full_audit", name, full_audit])
    return jsonify(ok=ok, output=output)


@app.route("/api/file_audit_log")
@login_required
def api_file_audit_log():
    ok, output = run_helper(["file_audit_log"])
    return jsonify(ok=ok, output=output)


@app.route("/api/set_share_quota", methods=["POST"])
@login_required
def api_set_share_quota():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    quota_ok, quota = validate_quota_bytes(data.get("quota_bytes", 0))

    if not SHARENAME_RE.match(name):
        return jsonify(ok=False, output="ERROR: недопустимое имя шары")
    if not quota_ok:
        return jsonify(ok=False, output="ERROR: квота должна быть числом байт от 0")

    ok, output = run_helper(["set_share_quota", name, quota])
    return jsonify(ok=ok, output=output)


@app.route("/api/set_share_backup", methods=["POST"])
@login_required
def api_set_share_backup():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    backup = validate_backup_flag(data.get("backup", False))

    if not SHARENAME_RE.match(name):
        return jsonify(ok=False, output="ERROR: недопустимое имя шары")

    ok, output = run_helper(["set_share_backup", name, backup])
    return jsonify(ok=ok, output=output)


@app.route("/api/set_share_antivirus", methods=["POST"])
@login_required
def api_set_share_antivirus():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    antivirus = "yes" if data.get("antivirus", False) else "no"

    if not SHARENAME_RE.match(name):
        return jsonify(ok=False, output="ERROR: недопустимое имя шары")

    ok, output = run_helper(["set_share_antivirus", name, antivirus])
    return jsonify(ok=ok, output=output)


@app.route("/api/empty_quarantine", methods=["POST"])
@login_required
def api_empty_quarantine():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    if not SHARENAME_RE.match(name):
        return jsonify(ok=False, output="ERROR: недопустимое имя шары")

    ok, output = run_helper(["empty_quarantine", name])
    return jsonify(ok=ok, output=output)


@app.route("/api/set_share_veto", methods=["POST"])
@login_required
def api_set_share_veto():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    veto_ok, veto = validate_veto_field(data.get("veto"))

    if not SHARENAME_RE.match(name):
        return jsonify(ok=False, output="ERROR: недопустимое имя шары")
    if not veto_ok:
        return jsonify(ok=False, output="ERROR: список расширений некорректен (пример: exe,bat,ps1)")

    ok, output = run_helper(["set_share_veto", name, veto])
    return jsonify(ok=ok, output=output)


@app.route("/api/set_share_recycle", methods=["POST"])
@login_required
def api_set_share_recycle():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    recycle = "yes" if data.get("recycle", False) else "no"
    retention_ok, retention = validate_retention_days(data.get("retention_days", 0))

    if not SHARENAME_RE.match(name):
        return jsonify(ok=False, output="ERROR: недопустимое имя шары")
    if not retention_ok:
        return jsonify(ok=False, output="ERROR: срок хранения корзины должен быть числом дней от 0 до 9999")

    ok, output = run_helper(["set_share_recycle", name, recycle, retention])
    return jsonify(ok=ok, output=output)


@app.route("/api/empty_recycle_bin", methods=["POST"])
@login_required
def api_empty_recycle_bin():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    if not SHARENAME_RE.match(name):
        return jsonify(ok=False, output="ERROR: недопустимое имя шары")

    ok, output = run_helper(["empty_recycle_bin", name])
    return jsonify(ok=ok, output=output)


@app.route("/api/list_recycle_bin", methods=["POST"])
@login_required
def api_list_recycle_bin():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    if not SHARENAME_RE.match(name):
        return jsonify(ok=False, output="ERROR: недопустимое имя шары")

    ok, output = run_helper(["list_recycle_bin", name])
    return jsonify(ok=ok, output=output)


@app.route("/api/restore_recycle_file", methods=["POST"])
@login_required
def api_restore_recycle_file():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    relpath_b64 = (data.get("relpath_b64") or "").strip()
    if not SHARENAME_RE.match(name):
        return jsonify(ok=False, output="ERROR: недопустимое имя шары")
    if not relpath_b64:
        return jsonify(ok=False, output="ERROR: не передан файл для восстановления")

    ok, output = run_helper(["restore_recycle_file", name, relpath_b64])
    return jsonify(ok=ok, output=output)


@app.route("/api/set_share_hosts", methods=["POST"])
@login_required
def api_set_share_hosts():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    hosts_ok, hosts = validate_hosts_field(data.get("hosts"))

    if not SHARENAME_RE.match(name):
        return jsonify(ok=False, output="ERROR: недопустимое имя шары")
    if not hosts_ok:
        return jsonify(ok=False, output="ERROR: список IP/подсетей некорректен (пример: 192.168.1.0/24,10.0.0.5)")

    ok, output = run_helper(["set_share_hosts", name, hosts])
    return jsonify(ok=ok, output=output)


@app.route("/api/remove_share", methods=["POST"])
@login_required
def api_remove_share():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    if not SHARENAME_RE.match(name):
        return jsonify(ok=False, output="ERROR: недопустимое имя шары")

    ok, output = run_helper(["remove_share", name])
    return jsonify(ok=ok, output=output)


@app.route("/api/set_share_writable", methods=["POST"])
@login_required
def api_set_share_writable():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    writable = "yes" if data.get("writable", True) else "no"
    if not SHARENAME_RE.match(name):
        return jsonify(ok=False, output="ERROR: недопустимое имя шары")

    ok, output = run_helper(["set_share_writable", name, writable])
    return jsonify(ok=ok, output=output)


@app.route("/api/list_shares")
@login_required
def api_list_shares():
    ok, output = run_helper(["list_shares"])
    return jsonify(ok=ok, output=output)


@app.route("/api/active_connections")
@login_required
def api_active_connections():
    ok, output = run_helper(["active_connections"])
    return jsonify(ok=ok, output=output)


@app.route("/api/disk_usage")
@login_required
def api_disk_usage():
    ok, output = run_helper(["disk_usage"])
    return jsonify(ok=ok, output=output)


@app.route("/api/list_block_devices")
@login_required
def api_list_block_devices():
    ok, output = run_helper(["list_block_devices"])
    return jsonify(ok=ok, output=output)


@app.route("/api/list_directories", methods=["POST"])
@login_required
def api_list_directories():
    data = request.get_json(force=True)
    path = (data.get("path") or "/").strip() or "/"

    if path != "/" and (not SHAREPATH_RE.match(path) or ".." in path):
        return jsonify(ok=False, output="ERROR: недопустимый путь")

    ok, output = run_helper(["list_directories", path])
    return jsonify(ok=ok, output=output)


@app.route("/api/get_notify_config")
@login_required
def api_get_notify_config():
    ok, output = run_helper(["get_notify_config"])
    return jsonify(ok=ok, output=output)


@app.route("/api/set_notify_config", methods=["POST"])
@login_required
def api_set_notify_config():
    data = request.get_json(force=True)
    token = (data.get("telegram_token") or "").strip()
    chat_id = (data.get("telegram_chat_id") or "").strip()
    email = (data.get("notify_email") or "").strip()

    token_b64 = base64.b64encode(token.encode()).decode()
    chatid_b64 = base64.b64encode(chat_id.encode()).decode()
    email_b64 = base64.b64encode(email.encode()).decode()

    ok, output = run_helper(["set_notify_config", token_b64, chatid_b64, email_b64])
    return jsonify(ok=ok, output=output)


@app.route("/api/test_notify", methods=["POST"])
@login_required
def api_test_notify():
    ok, output = run_helper(["test_notify"])
    return jsonify(ok=ok, output=output)


@app.route("/api/get_smtp_config")
@login_required
def api_get_smtp_config():
    ok, output = run_helper(["get_smtp_config"])
    return jsonify(ok=ok, output=output)


@app.route("/api/set_smtp_config", methods=["POST"])
@login_required
def api_set_smtp_config():
    data = request.get_json(force=True)
    host = (data.get("host") or "").strip()
    port = (data.get("port") or "587").strip()
    from_addr = (data.get("from_addr") or "").strip()
    user = (data.get("user") or "").strip()
    password = data.get("password") or ""  # может быть пустым — тогда старый пароль сохранится

    host_b64 = base64.b64encode(host.encode()).decode()
    port_b64 = base64.b64encode(port.encode()).decode()
    from_b64 = base64.b64encode(from_addr.encode()).decode()
    user_b64 = base64.b64encode(user.encode()).decode()
    password_b64 = base64.b64encode(password.encode()).decode()

    ok, output = run_helper(["set_smtp_config", host_b64, port_b64, from_b64, user_b64, password_b64])
    return jsonify(ok=ok, output=output)


@app.route("/api/test_smtp_send", methods=["POST"])
@login_required
def api_test_smtp_send():
    data = request.get_json(force=True)
    email = (data.get("email") or "").strip()
    if not email:
        return jsonify(ok=False, output="ERROR: укажи адрес для теста")

    email_b64 = base64.b64encode(email.encode()).decode()
    ok, output = run_helper(["test_smtp_send", email_b64])
    return jsonify(ok=ok, output=output)


AD_ADMIN_USER_RE = re.compile(r"^[A-Za-z0-9_.@\\-]{1,128}$")


@app.route("/api/ad_status")
@login_required
def api_ad_status():
    ok, output = run_helper(["ad_status"])
    return jsonify(ok=ok, output=output)


@app.route("/api/ad_join", methods=["POST"])
@login_required
def api_ad_join():
    data = request.get_json(force=True)
    workgroup = (data.get("workgroup") or "").strip()
    realm = (data.get("realm") or "").strip()
    range_start = str(data.get("range_start") or "10000").strip()
    range_end = str(data.get("range_end") or "999999").strip()
    admin_user = (data.get("admin_user") or "").strip()
    admin_password = data.get("admin_password") or ""

    if not workgroup or not realm:
        return jsonify(ok=False, output="ERROR: укажи домен (workgroup) и realm")
    if not admin_user or not AD_ADMIN_USER_RE.match(admin_user):
        return jsonify(ok=False, output="ERROR: недопустимое имя администратора домена")
    if not admin_password:
        return jsonify(ok=False, output="ERROR: укажи пароль администратора домена")

    ok, output = run_helper(
        ["ad_join", workgroup, realm, range_start, range_end, admin_user],
        stdin_text=admin_password + "\n",
    )
    return jsonify(ok=ok, output=output)


@app.route("/api/ad_leave", methods=["POST"])
@login_required
def api_ad_leave():
    data = request.get_json(force=True)
    admin_user = (data.get("admin_user") or "").strip()
    admin_password = data.get("admin_password") or ""

    if not admin_user or not AD_ADMIN_USER_RE.match(admin_user):
        return jsonify(ok=False, output="ERROR: недопустимое имя администратора домена")
    if not admin_password:
        return jsonify(ok=False, output="ERROR: укажи пароль администратора домена")

    ok, output = run_helper(["ad_leave", admin_user], stdin_text=admin_password + "\n")
    return jsonify(ok=ok, output=output)


@app.route("/api/ad_test")
@login_required
def api_ad_test():
    ok, output = run_helper(["ad_test"])
    return jsonify(ok=ok, output=output)


@app.route("/api/ad_list_users")
@login_required
def api_ad_list_users():
    ok, output = run_helper(["ad_list_users"])
    return jsonify(ok=ok, output=output)


@app.route("/api/ad_list_groups")
@login_required
def api_ad_list_groups():
    ok, output = run_helper(["ad_list_groups"])
    return jsonify(ok=ok, output=output)


@app.route("/api/disk_smart_summary")
@login_required
def api_disk_smart_summary():
    ok, output = run_helper(["disk_smart_summary"])
    return jsonify(ok=ok, output=output)


@app.route("/api/disk_smart_details", methods=["POST"])
@login_required
def api_disk_smart_details():
    data = request.get_json(force=True)
    device = (data.get("device") or "").strip()
    if not re.match(r"^/dev/[a-zA-Z0-9/_-]+$", device):
        return jsonify(ok=False, output="ERROR: недопустимый путь к устройству")

    ok, output = run_helper(["disk_smart_details", device])
    return jsonify(ok=ok, output=output)


@app.route("/api/mount_disk", methods=["POST"])
@login_required
def api_mount_disk():
    data = request.get_json(force=True)
    device = (data.get("device") or "").strip()
    mountpoint = (data.get("mountpoint") or "").strip()
    persistent = "yes" if data.get("persistent", False) else "no"

    if not re.match(r"^/dev/[a-zA-Z0-9/_-]+$", device):
        return jsonify(ok=False, output="ERROR: недопустимый путь к устройству")
    if not SHAREPATH_RE.match(mountpoint) or ".." in mountpoint:
        return jsonify(ok=False, output="ERROR: недопустимая точка монтирования")

    ok, output = run_helper(["mount_disk", device, mountpoint, persistent])
    return jsonify(ok=ok, output=output)


@app.route("/api/unmount_disk", methods=["POST"])
@login_required
def api_unmount_disk():
    data = request.get_json(force=True)
    mountpoint = (data.get("mountpoint") or "").strip()
    remove_fstab = "yes" if data.get("remove_fstab", False) else "no"

    if not SHAREPATH_RE.match(mountpoint) or ".." in mountpoint:
        return jsonify(ok=False, output="ERROR: недопустимая точка монтирования")

    ok, output = run_helper(["unmount_disk", mountpoint, remove_fstab])
    return jsonify(ok=ok, output=output)


@app.route("/api/audit_log")
@login_required
def api_audit_log():
    try:
        with open(AUDIT_LOG_PATH) as f:
            lines = f.readlines()
        # последние 200 записей, самые новые — сверху
        tail = lines[-200:]
        tail.reverse()
        return jsonify(ok=True, output="".join(tail))
    except FileNotFoundError:
        return jsonify(ok=True, output="(журнал действий пока пуст)")
    except OSError as e:
        return jsonify(ok=False, output=f"ERROR: не удалось прочитать журнал: {e}")


@app.route("/api/create_user", methods=["POST"])
@login_required
def api_create_user():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not USERNAME_RE.match(username):
        return jsonify(ok=False, output="ERROR: недопустимое имя пользователя")
    if len(password) < 8:
        return jsonify(ok=False, output="ERROR: пароль должен быть минимум 8 символов")

    ok, output = run_helper(["create_user", username], stdin_text=password + "\n")
    return jsonify(ok=ok, output=output)


@app.route("/api/remove_user", methods=["POST"])
@login_required
def api_remove_user():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    if not USERNAME_RE.match(username):
        return jsonify(ok=False, output="ERROR: недопустимое имя пользователя")

    ok, output = run_helper(["remove_user", username])
    return jsonify(ok=ok, output=output)


@app.route("/api/set_password", methods=["POST"])
@login_required
def api_set_password():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not USERNAME_RE.match(username):
        return jsonify(ok=False, output="ERROR: недопустимое имя пользователя")
    if len(password) < 8:
        return jsonify(ok=False, output="ERROR: пароль должен быть минимум 8 символов")

    ok, output = run_helper(["set_samba_password", username], stdin_text=password + "\n")
    return jsonify(ok=ok, output=output)


@app.route("/api/toggle_access", methods=["POST"])
@login_required
def api_toggle_access():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    action = (data.get("action") or "").strip()

    if not USERNAME_RE.match(username):
        return jsonify(ok=False, output="ERROR: недопустимое имя пользователя")
    if action not in ("on", "off"):
        return jsonify(ok=False, output="ERROR: действие должно быть on/off")

    ok, output = run_helper(["toggle_share_access", username, action])
    return jsonify(ok=ok, output=output)


@app.route("/api/list_users")
@login_required
def api_list_users():
    ok, output = run_helper(["list_users"])
    return jsonify(ok=ok, output=output)


if __name__ == "__main__":
    # По умолчанию слушаем только localhost — снаружи панель доступна ТОЛЬКО
    # через nginx на 443 (HTTPS), см. install.sh и README. Прямой доступ к
    # Flask на 5000 в открытом виде намеренно закрыт: без этого пароль при
    # входе шёл бы по сети в открытом виде даже в пределах LAN.
    bind_host = os.environ.get("SAMBAPANEL_BIND_HOST", "127.0.0.1")
    app.run(host=bind_host, port=5000, debug=False)
