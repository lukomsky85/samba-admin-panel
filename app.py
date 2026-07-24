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
import json
import os
import re
import secrets
import shutil
import subprocess
import time
import uuid
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


def run_helper(args, stdin_text=None, timeout=30):
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
            timeout=timeout,
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
    """Разрешает 'GUEST' (гостевой доступ без пароля), обычное локальное имя
    группы, 'AD:группа' или 'ADUSERS:user1,user2'. Возвращает (ok, normalized)."""
    group = (group or "").strip()
    if group == "GUEST":
        return True, "GUEST"
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


UPDATE_TAG_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
UPDATE_LOG_PATH = "/var/log/sambapanel/update.log"


@app.route("/api/check_update")
@login_required
def api_check_update():
    ok, output = run_helper(["check_update"])
    return jsonify(ok=ok, output=output)


@app.route("/api/apply_update", methods=["POST"])
@login_required
def api_apply_update():
    # Обновление запускается АСИНХРОННО (Popen, не subprocess.run) и
    # намеренно "отвязано" от текущего запроса (start_new_session=True).
    # Полная переустановка через install.sh (пакеты, systemd) может идти
    # несколько минут — синхронно дождаться этого в рамках одного HTTP-
    # запроса означало бы упереться сразу в несколько таймаутов подряд
    # (nginx proxy_read_timeout, gunicorn --timeout), и раздувать их до
    # неприличных величин ради одной редкой операции не хочется. Хуже
    # того: и install.sh, и сам apply_update (после него, отдельно и
    # гарантированно) делают `systemctl restart sambapanel` — если бы
    # обновление шло синхронно внутри текущего процесса панели, этот самый
    # рестарт оборвал бы его самого на середине. Отвязанный процесс
    # переживает это спокойно.
    data = request.get_json(force=True)
    tag = (data.get("tag") or "").strip()
    if not tag or not UPDATE_TAG_RE.match(tag):
        return jsonify(ok=False, output="ERROR: некорректный номер версии")

    try:
        os.makedirs(os.path.dirname(UPDATE_LOG_PATH), exist_ok=True)
        log_f = open(UPDATE_LOG_PATH, "a")
        log_f.write(
            f"\n\n=== Запуск обновления до {tag}, "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} ===\n"
        )
        log_f.flush()
        subprocess.Popen(
            ["sudo", "-n", HELPER, "apply_update", tag],
            stdout=log_f,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError as e:
        return jsonify(ok=False, output=f"ERROR: не удалось запустить обновление: {e}")

    audit_log(f"apply_update {tag}", True, "запущено в фоне")
    return jsonify(
        ok=True,
        output=(
            f"Обновление до {tag} запущено в фоне. Это может занять несколько минут "
            f"(установка пакетов и т.п.) — панель может ненадолго перезапуститься "
            f"посреди процесса, это ожидаемо. Смотри прогресс в журнале обновления ниже."
        ),
    )


@app.route("/api/update_log")
@login_required
def api_update_log():
    try:
        with open(UPDATE_LOG_PATH) as f:
            lines = f.readlines()
        tail = lines[-200:]
        return jsonify(ok=True, output="".join(tail))
    except FileNotFoundError:
        return jsonify(ok=True, output="(лога обновлений пока нет — обновление ещё не запускалось)")
    except OSError as e:
        return jsonify(ok=False, output=f"ERROR: не удалось прочитать лог обновления: {e}")


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


@app.route("/api/list_iso_files", methods=["POST"])
@login_required
def api_list_iso_files():
    data = request.get_json(force=True)
    path = (data.get("path") or "/srv").strip() or "/srv"

    if path != "/" and (not SHAREPATH_RE.match(path) or ".." in path):
        return jsonify(ok=False, output="ERROR: недопустимый путь")

    ok, output = run_helper(["list_iso_files", path])
    return jsonify(ok=ok, output=output)


@app.route("/api/mount_iso", methods=["POST"])
@login_required
def api_mount_iso():
    data = request.get_json(force=True)
    iso_path = (data.get("iso_path") or "").strip()
    mountpoint = (data.get("mountpoint") or "").strip()

    if not iso_path or ".." in iso_path or not SHAREPATH_RE.match(iso_path) or not iso_path.lower().endswith(".iso"):
        return jsonify(ok=False, output="ERROR: недопустимый путь к ISO-файлу")
    if not SHAREPATH_RE.match(mountpoint) or ".." in mountpoint:
        return jsonify(ok=False, output="ERROR: недопустимая точка монтирования")

    ok, output = run_helper(["mount_iso", iso_path, mountpoint])
    return jsonify(ok=ok, output=output)


@app.route("/api/delete_iso_file", methods=["POST"])
@login_required
def api_delete_iso_file():
    data = request.get_json(force=True)
    iso_path = (data.get("iso_path") or "").strip()

    if not iso_path or ".." in iso_path or not SHAREPATH_RE.match(iso_path) or not iso_path.lower().endswith(".iso"):
        return jsonify(ok=False, output="ERROR: недопустимый путь к ISO-файлу")

    ok, output = run_helper(["delete_iso_file", iso_path])
    return jsonify(ok=ok, output=output)


@app.route("/api/create_iso_directory", methods=["POST"])
@login_required
def api_create_iso_directory():
    data = request.get_json(force=True)
    path = (data.get("path") or "").strip()

    if not path or ".." in path or not SHAREPATH_RE.match(path):
        return jsonify(ok=False, output="ERROR: недопустимый путь")

    ok, output = run_helper(["create_iso_directory", path])
    return jsonify(ok=ok, output=output)


# --- Загрузка больших ISO-образов через браузер (кусками, с докачкой) ---
#
# Обычная форма с одним запросом на весь файл не подходит: образы могут
# быть на сотни ГБ, а таймаут воркера gunicorn (120с) и вообще надёжность
# передачи по сети такого объёма за один запрос не гарантированы — любой
# обрыв соединения означал бы начинать заново. Вместо этого JS режет файл
# на куски (~10 МБ), каждый кусок — отдельный запрос по смещению в байтах
# (идемпотентно: повторная отправка того же куска ничего не портит, просто
# перезаписывает те же байты по тому же месту). Сессия сохраняется в JSON
# рядом — переживает даже перезапуск самой панели, докачку можно продолжить.

UPLOAD_STAGING_DIR = "/opt/sambapanel/uploads"
ISO_FILENAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,200}\.iso$", re.IGNORECASE)


def _upload_meta_path(session_id):
    # session_id уже проверен на безопасный алфавит (uuid4 hex) до вызова —
    # но на всякий случай не подставляем его в путь без базовой проверки.
    safe_id = re.sub(r"[^a-f0-9]", "", session_id.lower())
    return os.path.join(UPLOAD_STAGING_DIR, f"{safe_id}.json")


def _load_upload_meta(session_id):
    path = _upload_meta_path(session_id)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _save_upload_meta(session_id, meta):
    with open(_upload_meta_path(session_id), "w", encoding="utf-8") as f:
        json.dump(meta, f)


def _remove_upload_meta(session_id):
    try:
        os.remove(_upload_meta_path(session_id))
    except OSError:
        pass


@app.route("/api/iso_upload_find_resumable", methods=["POST"])
@login_required
def api_iso_upload_find_resumable():
    """Ищет уже начатую, но не завершённую сессию для того же файла (по
    имени+размеру+папке назначения) — чтобы после перезагрузки страницы или
    обрыва связи докачка продолжилась, а не началась с нуля."""
    data = request.get_json(force=True)
    filename = (data.get("filename") or "").strip()
    dest_dir = (data.get("dest_dir") or "").strip()
    try:
        total_size = int(data.get("total_size") or 0)
    except (TypeError, ValueError):
        total_size = 0

    try:
        entries = os.listdir(UPLOAD_STAGING_DIR)
    except OSError:
        entries = []

    for entry in entries:
        if not entry.endswith(".json"):
            continue
        session_id = entry[:-5]
        meta = _load_upload_meta(session_id)
        if not meta:
            continue
        if (meta.get("filename") == filename and meta.get("dest_dir") == dest_dir
                and meta.get("total_size") == total_size):
            part_path = meta.get("part_path", "")
            bytes_received = os.path.getsize(part_path) if os.path.isfile(part_path) else 0
            return jsonify(ok=True, session_id=session_id, bytes_received=bytes_received)

    return jsonify(ok=True, session_id=None, bytes_received=0)


@app.route("/api/iso_upload_init", methods=["POST"])
@login_required
def api_iso_upload_init():
    data = request.get_json(force=True)
    filename = (data.get("filename") or "").strip()
    dest_dir = (data.get("dest_dir") or "").strip()
    try:
        total_size = int(data.get("total_size") or 0)
    except (TypeError, ValueError):
        total_size = 0

    if not ISO_FILENAME_RE.match(filename):
        return jsonify(ok=False, output="ERROR: имя файла должно оканчиваться на .iso, без путей")
    if not SHAREPATH_RE.match(dest_dir) or ".." in dest_dir:
        return jsonify(ok=False, output="ERROR: недопустимая папка назначения")
    if total_size <= 0:
        return jsonify(ok=False, output="ERROR: некорректный размер файла")

    # Пишем сразу в папку назначения, если панель туда может писать напрямую
    # — тогда финализация будет мгновенным переименованием на месте, без
    # второй копии байт и без необходимости в root. Если нет (например,
    # папка шары с правами под конкретную Unix-группу, в которую www-panel
    # не входит) — используем общую staging-папку, а перенос в конце делает
    # root-хелпер (при этом временно нужно места в ДВУХ местах сразу).
    direct_write_ok = os.path.isdir(dest_dir) and os.access(dest_dir, os.W_OK)
    staging_dir = dest_dir if direct_write_ok else UPLOAD_STAGING_DIR

    try:
        usage = shutil.disk_usage(staging_dir)
    except OSError as e:
        return jsonify(ok=False, output=f"ERROR: не удалось проверить свободное место в {staging_dir}: {e}")

    gb = 1024 ** 3
    if usage.free < total_size:
        return jsonify(ok=False, output=(
            f"ERROR: недостаточно места в {staging_dir} — свободно "
            f"{usage.free / gb:.1f} ГБ, нужно {total_size / gb:.1f} ГБ"
        ))

    if not direct_write_ok:
        dest_check_path = dest_dir if os.path.isdir(dest_dir) else (os.path.dirname(dest_dir.rstrip("/")) or "/")
        try:
            dest_usage = shutil.disk_usage(dest_check_path)
        except OSError as e:
            return jsonify(ok=False, output=f"ERROR: не удалось проверить свободное место в {dest_dir}: {e}")
        if dest_usage.free < total_size:
            return jsonify(ok=False, output=(
                f"ERROR: недостаточно места в конечной папке {dest_dir} — свободно "
                f"{dest_usage.free / gb:.1f} ГБ, нужно {total_size / gb:.1f} ГБ "
                f"(панель не может писать туда напрямую, придётся делать отдельную копию)"
            ))

    session_id = uuid.uuid4().hex
    part_path = os.path.join(staging_dir, f".uploading-{session_id}.part")

    try:
        os.makedirs(staging_dir, exist_ok=True)
        with open(part_path, "wb"):
            pass
    except OSError as e:
        return jsonify(ok=False, output=f"ERROR: не удалось создать временный файл в {staging_dir}: {e}")

    meta = {
        "filename": filename,
        "dest_dir": dest_dir,
        "dest_filename": filename,
        "total_size": total_size,
        "part_path": part_path,
        "direct_write": direct_write_ok,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_upload_meta(session_id, meta)

    return jsonify(ok=True, session_id=session_id, direct_write=direct_write_ok)


@app.route("/api/iso_upload_chunk", methods=["POST"])
@login_required
def api_iso_upload_chunk():
    session_id = request.args.get("session_id", "")
    try:
        offset = int(request.args.get("offset", "-1"))
    except ValueError:
        offset = -1

    if not re.match(r"^[a-f0-9]{32}$", session_id) or offset < 0:
        return jsonify(ok=False, output="ERROR: некорректные параметры куска"), 400

    meta = _load_upload_meta(session_id)
    if not meta:
        return jsonify(ok=False, output="ERROR: сессия загрузки не найдена (истекла или отменена)"), 404

    chunk_data = request.get_data()
    if not chunk_data:
        return jsonify(ok=False, output="ERROR: пустой кусок данных"), 400

    part_path = meta["part_path"]
    try:
        # r+b, а не ab — пишем ИМЕННО по смещению, а не всегда в конец файла.
        # Это делает повторную отправку того же куска (после обрыва связи,
        # когда клиент не дождался ответа, хотя запись уже прошла) полностью
        # безопасной: те же самые байты просто лягут на то же самое место
        # ещё раз, файл не удвоится и не испортится.
        with open(part_path, "r+b") as f:
            f.seek(offset)
            f.write(chunk_data)
    except OSError as e:
        return jsonify(ok=False, output=f"ERROR: не удалось записать кусок: {e}"), 500

    bytes_received = os.path.getsize(part_path)
    return jsonify(ok=True, bytes_received=bytes_received)


@app.route("/api/iso_upload_finish", methods=["POST"])
@login_required
def api_iso_upload_finish():
    data = request.get_json(force=True)
    session_id = (data.get("session_id") or "").strip()

    meta = _load_upload_meta(session_id)
    if not meta:
        return jsonify(ok=False, output="ERROR: сессия загрузки не найдена")

    part_path = meta["part_path"]
    total_size = meta["total_size"]
    dest_dir = meta["dest_dir"]
    dest_filename = meta["dest_filename"]

    if not os.path.isfile(part_path):
        return jsonify(ok=False, output="ERROR: временный файл пропал — сессия испорчена, начни загрузку заново")

    actual_size = os.path.getsize(part_path)
    if actual_size != total_size:
        return jsonify(ok=False, output=(
            f"ERROR: получено {actual_size} из {total_size} байт — загрузка ещё не завершена полностью"
        ))

    if meta.get("direct_write"):
        final_path = os.path.join(dest_dir, dest_filename)
        if os.path.exists(final_path):
            return jsonify(ok=False, output=f"ERROR: файл '{final_path}' уже существует")
        try:
            os.rename(part_path, final_path)
        except OSError as e:
            return jsonify(ok=False, output=f"ERROR: не удалось переименовать файл: {e}")
        _remove_upload_meta(session_id)
        return jsonify(ok=True, output=f"OK: файл сохранён в {final_path}")

    ok, output = run_helper(["iso_finalize_upload", part_path, dest_dir, dest_filename])
    if ok:
        _remove_upload_meta(session_id)
    return jsonify(ok=ok, output=output)


@app.route("/api/iso_upload_cancel", methods=["POST"])
@login_required
def api_iso_upload_cancel():
    data = request.get_json(force=True)
    session_id = (data.get("session_id") or "").strip()

    meta = _load_upload_meta(session_id)
    if meta:
        part_path = meta.get("part_path", "")
        if part_path and os.path.isfile(part_path):
            try:
                os.remove(part_path)
            except OSError:
                pass
    _remove_upload_meta(session_id)
    return jsonify(ok=True, output="Загрузка отменена, временные файлы убраны")


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
