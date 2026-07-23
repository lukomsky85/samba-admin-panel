#!/usr/bin/env bash
#
# install.sh — установщик samba-admin panel для Ubuntu.
#
# Запускать из корня проекта (там, где лежат app.py, templates/, и т.д.):
#   sudo ./install.sh
#
# Скрипт идемпотентен — можно запускать повторно, ничего не поломает.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PANEL_DIR="/opt/sambapanel"
PANEL_USER="www-panel"
SHAREGROUP="sharegroup"
DEFAULT_SHARE="/srv/share"
HELPER_SRC="$SCRIPT_DIR/samba-admin-helper.sh"
HELPER_DST="/usr/local/sbin/samba-admin-helper.sh"
SUDOERS_DST="/etc/sudoers.d/samba-admin"
SERVICE_DST="/etc/systemd/system/sambapanel.service"
BACKUP_CONF_PATH="/etc/sambapanel/backup.conf"
PANEL_PORT="5000"

c_green="\033[0;32m"; c_amber="\033[0;33m"; c_red="\033[0;31m"; c_reset="\033[0m"

step()  { echo -e "${c_green}==>${c_reset} $*"; }
warn()  { echo -e "${c_amber}!! ${c_reset} $*"; }
fail()  { echo -e "${c_red}FATAL:${c_reset} $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 0. Проверки
# ---------------------------------------------------------------------------

if [[ "$EUID" -ne 0 ]]; then
    fail "запусти скрипт через sudo: sudo ./install.sh"
fi

if ! command -v apt &>/dev/null; then
    fail "этот установщик рассчитан на Ubuntu/Debian (apt не найден)"
fi

for f in app.py samba-admin-helper.sh templates/index.html templates/login.html sambapanel.service samba-recycle-cleanup.sh samba-recycle-cleanup.service samba-recycle-cleanup.timer samba-backup.sh samba-backup.service samba-backup.timer samba-restore.sh logrotate-sambapanel.conf logrotate-full-audit.conf samba-notify-failure.sh samba-notify@.service notify.conf.example; do
    [[ -f "$SCRIPT_DIR/$f" ]] || fail "не найден файл '$f' — запускай install.sh из корня проекта"
done

echo
echo "  samba-admin panel — установщик"
echo "  ---------------------------------"
echo

# ---------------------------------------------------------------------------
# 1. Пакеты
# ---------------------------------------------------------------------------

step "устанавливаю системные пакеты (samba, avahi, python3-venv, ufw, nginx, clamav, rsyslog, smartmontools)"
apt update -qq
apt install -y -qq \
    samba samba-vfs-modules avahi-daemon python3-venv ufw \
    nginx openssl \
    clamav-daemon clamav-freshclam \
    rsyslog \
    smartmontools util-linux \
    >/dev/null

# ---------------------------------------------------------------------------
# 2. Группа и базовая шара
# ---------------------------------------------------------------------------

step "создаю группу '$SHAREGROUP' и папку по умолчанию '$DEFAULT_SHARE'"
groupadd -f "$SHAREGROUP"
mkdir -p "$DEFAULT_SHARE"
chown root:"$SHAREGROUP" "$DEFAULT_SHARE"
chmod 2775 "$DEFAULT_SHARE"

# ---------------------------------------------------------------------------
# 2.1 ClamAV — сокет должен быть доступен ЛЮБОМУ Samba-пользователю
# ---------------------------------------------------------------------------
# smbd при подключении к шаре работает от имени залогиненного пользователя
# (ivan, maria, ...), а не от root и не от www-panel. Пользователей панель
# создаёт динамически, поэтому заранее нельзя добавить их всех в группу
# clamav — вместо этого делаем сокет доступным всем локальным процессам
# (LocalSocketMode 666). Сам ClamAV ничего не отдаёт наружу кроме вердикта
# "заражён/не заражён", так что это приемлемый компромисс на локальном сервере.

step "настраиваю ClamAV (сокет доступен всем локальным пользователям для сканирования)"
CLAMD_CONF="/etc/clamav/clamd.conf"
if [[ -f "$CLAMD_CONF" ]]; then
    if grep -q "^LocalSocketMode" "$CLAMD_CONF"; then
        sed -i 's/^LocalSocketMode.*/LocalSocketMode 666/' "$CLAMD_CONF"
    else
        echo "LocalSocketMode 666" >> "$CLAMD_CONF"
    fi
else
    warn "$CLAMD_CONF не найден — clamav-daemon мог установиться нестандартно, проверь руками"
fi

systemctl enable --now clamav-freshclam >/dev/null 2>&1 || true
step "запускаю первое обновление баз ClamAV (freshclam) — может занять пару минут"
freshclam --quiet 2>/dev/null || warn "freshclam не смог обновиться сразу — clamav-freshclam.service подхватит это в фоне"
systemctl enable --now clamav-daemon >/dev/null 2>&1 || true

# ждём появления сокета — clamd стартует не мгновенно после первого запуска
for i in $(seq 1 30); do
    [[ -S /var/run/clamav/clamd.ctl ]] && break
    sleep 1
done
if [[ -S /var/run/clamav/clamd.ctl ]]; then
    step "ClamAV запущен, сокет на месте"
else
    warn "clamd ещё не поднял сокет — включение антивируса на шарах может не сработать сразу. Проверь: systemctl status clamav-daemon"
fi

# ---------------------------------------------------------------------------
# 2.2 rsyslog — маршрутизация полного аудита файловых операций (vfs_full_audit)
# ---------------------------------------------------------------------------
# Samba пишет full_audit-сообщения через syslog(3) на facility LOCAL5.
# Без отдельного правила они уйдут в общий /var/log/syslog вперемешку со
# всем остальным — тут настраиваем rsyslog, чтобы складывать их отдельно
# и НЕ дублировать в общий лог (& stop останавливает дальнейшую обработку
# именно для сообщений с этой facility).
#
# ВАЖНО: НЕ используем /var/log/samba для этого — та папка root:adm с
# правами rwxr-x--- (только чтение для группы), а rsyslog (пользователь
# syslog, состоит в группе adm) должен именно СОЗДАТЬ файл — для этого
# нужны права на запись в саму папку, которых там нет. Отдельная папка
# ниже принадлежит syslog напрямую, так что этой проблемы не возникает.

step "настраиваю rsyslog для лога файлового аудита (vfs_full_audit)"
mkdir -p /var/log/samba-full-audit
chown syslog:adm /var/log/samba-full-audit
chmod 750 /var/log/samba-full-audit
cat > /etc/rsyslog.d/49-samba-full-audit.conf <<'EOF'
# Создано установщиком samba-admin panel — маршрутизирует сообщения
# vfs_full_audit (facility LOCAL5) в отдельный файл вместо общего syslog.
local5.*    -/var/log/samba-full-audit/full-audit.log
& stop
EOF
systemctl restart rsyslog 2>/dev/null || warn "не удалось перезапустить rsyslog — проверь руками: systemctl status rsyslog"

# ---------------------------------------------------------------------------
# 2.3 Ротация логов (logrotate) — без этого оба лога растут бесконечно
# ---------------------------------------------------------------------------
# audit.log панели ротируется просто (Flask открывает файл заново на каждую
# запись, поэтому переименования достаточно). full-audit.log пишет rsyslog,
# который держит файл открытым постоянно — там обязателен postrotate,
# сообщающий демону переоткрыть файлы (иначе после ротации rsyslog продолжит
# писать в старый, уже переименованный файл, и логи будут "невидимыми").

step "настраиваю ротацию логов (logrotate)"
install -m 644 -o root -g root "$SCRIPT_DIR/logrotate-sambapanel.conf" /etc/logrotate.d/sambapanel
install -m 644 -o root -g root "$SCRIPT_DIR/logrotate-full-audit.conf" /etc/logrotate.d/samba-full-audit
logrotate -d /etc/logrotate.d/sambapanel &>/dev/null || warn "logrotate конфиг панели не прошёл проверку (logrotate -d) — проверь /etc/logrotate.d/sambapanel руками"
logrotate -d /etc/logrotate.d/samba-full-audit &>/dev/null || warn "logrotate конфиг full-audit не прошёл проверку — проверь /etc/logrotate.d/samba-full-audit руками"

# ---------------------------------------------------------------------------
# 3. Подключить include для шар, управляемых панелью
# ---------------------------------------------------------------------------

step "подключаю /etc/samba/panel-shares.conf к smb.conf"
mkdir -p /etc/sambapanel
touch /etc/samba/panel-shares.conf

if ! grep -q "panel-shares.conf" /etc/samba/smb.conf 2>/dev/null; then
    echo "include = /etc/samba/panel-shares.conf" >> /etc/samba/smb.conf
else
    warn "include уже прописан в smb.conf, пропускаю"
fi

if ! testparm -s /etc/samba/smb.conf &>/dev/null; then
    fail "smb.conf не проходит testparm — проверь конфиг руками перед повторным запуском"
fi

# ---------------------------------------------------------------------------
# 4. Хелпер-скрипт + sudoers
# ---------------------------------------------------------------------------

step "устанавливаю хелпер-скрипт в $HELPER_DST"
install -m 750 -o root -g root "$HELPER_SRC" "$HELPER_DST"

step "устанавливаю автоочистку корзины (для шар с ограниченным сроком хранения)"
install -m 750 -o root -g root "$SCRIPT_DIR/samba-recycle-cleanup.sh" /usr/local/sbin/samba-recycle-cleanup.sh
install -m 644 -o root -g root "$SCRIPT_DIR/samba-recycle-cleanup.service" /etc/systemd/system/samba-recycle-cleanup.service
install -m 644 -o root -g root "$SCRIPT_DIR/samba-recycle-cleanup.timer" /etc/systemd/system/samba-recycle-cleanup.timer
systemctl daemon-reload
systemctl enable --now samba-recycle-cleanup.timer

# ---------------------------------------------------------------------------
# 4.1 Бэкап шар (tar.gz с ротацией по расписанию)
# ---------------------------------------------------------------------------
# Спрашиваем путь назначения. Это может быть что угодно смонтированное:
# внешний диск, сетевая папка, облачный mount (rclone/s3fs) — скрипт просто
# кладёт туда tar.gz файлы, ему всё равно, что физически находится по этому пути.
# Если путь не задан — бэкап просто не настраивается, ничего не ломается.

step "устанавливаю скрипт бэкапа шар"
install -m 750 -o root -g root "$SCRIPT_DIR/samba-backup.sh" /usr/local/sbin/samba-backup.sh
install -m 644 -o root -g root "$SCRIPT_DIR/samba-backup.service" /etc/systemd/system/samba-backup.service
install -m 644 -o root -g root "$SCRIPT_DIR/samba-backup.timer" /etc/systemd/system/samba-backup.timer
install -m 750 -o root -g root "$SCRIPT_DIR/samba-restore.sh" /usr/local/sbin/samba-restore.sh

mkdir -p /etc/sambapanel
if [[ -f "$BACKUP_CONF_PATH" ]]; then
    warn "$BACKUP_CONF_PATH уже существует, не трогаю — если нужно поменять путь, редактируй его руками"
elif [[ -t 0 ]]; then
    echo
    read -r -p "Путь для бэкапов шар (Enter — пропустить настройку бэкапа): " BACKUP_DEST_INPUT || true
    if [[ -n "${BACKUP_DEST_INPUT:-}" ]]; then
        if [[ ! -d "$BACKUP_DEST_INPUT" ]]; then
            warn "путь '$BACKUP_DEST_INPUT' не существует — создаю"
            mkdir -p "$BACKUP_DEST_INPUT" || { warn "не удалось создать, бэкап не настроен"; BACKUP_DEST_INPUT=""; }
        fi
    fi
    if [[ -n "${BACKUP_DEST_INPUT:-}" ]]; then
        printf 'BACKUP_DEST="%s"\nRETAIN_COUNT=7\n' "$BACKUP_DEST_INPUT" > "$BACKUP_CONF_PATH"
        step "бэкап настроен: $BACKUP_DEST_INPUT (хранить 7 последних архивов на шару)"
    else
        warn "бэкап не настроен — включишь позже, создав $BACKUP_CONF_PATH руками (см. README) и включив бэкап на нужных шарах в панели"
    fi
else
    warn "неинтерактивный запуск — бэкап не настроен, создай $BACKUP_CONF_PATH руками при необходимости"
fi

systemctl daemon-reload
systemctl enable --now samba-backup.timer 2>/dev/null || true

step "прописываю sudoers-правило ($SUDOERS_DST)"
echo "${PANEL_USER} ALL=(root) NOPASSWD: ${HELPER_DST} *" > "$SUDOERS_DST"
chmod 440 "$SUDOERS_DST"
visudo -c -f "$SUDOERS_DST" >/dev/null || fail "sudoers-правило получилось невалидным"

# ---------------------------------------------------------------------------
# 5. Системный пользователь для сервиса
# ---------------------------------------------------------------------------

if id "$PANEL_USER" &>/dev/null; then
    warn "пользователь '$PANEL_USER' уже существует, пропускаю создание"
else
    step "создаю системного пользователя '$PANEL_USER' (без прав входа в shell)"
    useradd -r -m -d "$PANEL_DIR" -s /usr/sbin/nologin "$PANEL_USER"
fi

# ---------------------------------------------------------------------------
# 6. Копирование проекта и venv
# ---------------------------------------------------------------------------

step "создаю папку для журнала действий /var/log/sambapanel"
mkdir -p /var/log/sambapanel
chown "$PANEL_USER":"$PANEL_USER" /var/log/sambapanel
chmod 750 /var/log/sambapanel

step "копирую проект в $PANEL_DIR"
mkdir -p "$PANEL_DIR"
cp -r "$SCRIPT_DIR/app.py" "$SCRIPT_DIR/templates" "$PANEL_DIR/"
[[ -d "$SCRIPT_DIR/static" ]] && cp -r "$SCRIPT_DIR/static" "$PANEL_DIR/"
chown -R "$PANEL_USER":"$PANEL_USER" "$PANEL_DIR"

step "создаю python venv и ставлю flask + gunicorn (может занять минуту)"
if [[ ! -x "$PANEL_DIR/venv/bin/python3" ]]; then
    sudo -u "$PANEL_USER" python3 -m venv "$PANEL_DIR/venv"
fi
sudo -u "$PANEL_USER" "$PANEL_DIR/venv/bin/pip" install --quiet --upgrade pip
sudo -u "$PANEL_USER" "$PANEL_DIR/venv/bin/pip" install --quiet flask gunicorn

# ---------------------------------------------------------------------------
# 7. Пароль панели
# ---------------------------------------------------------------------------

gen_password() {
    # НЕ используем `tr ... | head -c N` — head закрывает пайп раньше, чем tr
    # дочитает /dev/urandom, tr получает SIGPIPE, и под `set -o pipefail`
    # это валит весь скрипт молча. python3 надёжнее и уже гарантированно
    # установлен на этом шаге (подтянулся вместе с python3-venv).
    python3 -c 'import secrets; print(secrets.token_urlsafe(15))'
}

if [[ -n "${SAMBAPANEL_PASSWORD:-}" ]]; then
    PANEL_PASSWORD="$SAMBAPANEL_PASSWORD"
    step "использую пароль из переменной окружения SAMBAPANEL_PASSWORD"
elif [[ -t 0 ]]; then
    echo
    read -r -s -p "Задай пароль для входа в панель (Enter — сгенерировать случайный): " PANEL_PASSWORD || true
    echo
    if [[ -z "$PANEL_PASSWORD" ]]; then
        PANEL_PASSWORD="$(gen_password)"
        warn "сгенерирован случайный пароль (см. в конце вывода)"
    fi
else
    PANEL_PASSWORD="$(gen_password)"
    warn "неинтерактивный запуск — сгенерирован случайный пароль (см. в конце вывода)"
fi

# Отдельный секрет для подписи сессионных cookie. ВАЖНО генерировать его ОДИН
# РАЗ и класть в systemd unit явно — если оставить это на волю Flask
# (secrets.token_hex() при каждом старте), то при переходе на несколько
# воркеров gunicorn у каждого воркера будет свой секрет, и один и тот же
# залогиненный пользователь будет рандомно вылетать из сессии в зависимости
# от того, какой воркер обработал его следующий запрос.
if [[ -f "$SERVICE_DST" ]] && grep -q "SAMBAPANEL_SECRET=" "$SERVICE_DST" 2>/dev/null; then
    PANEL_SECRET="$(grep -oP '(?<=SAMBAPANEL_SECRET=)[^"]*' "$SERVICE_DST")"
    step "переиспользую уже существующий SAMBAPANEL_SECRET (сессии не сбросятся)"
else
    PANEL_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
fi

# ---------------------------------------------------------------------------
# 8. systemd unit
# ---------------------------------------------------------------------------

step "устанавливаю systemd unit"
sed \
    -e "s#CHANGE_ME_SECRET#${PANEL_SECRET}#" \
    -e "s#CHANGE_ME#${PANEL_PASSWORD}#" \
    -e "s#/opt/sambapanel#${PANEL_DIR}#g" \
    "$SCRIPT_DIR/sambapanel.service" > "$SERVICE_DST"
chmod 600 "$SERVICE_DST"   # там пароль в plaintext — закрываем от чужих глаз

systemctl daemon-reload
systemctl enable --now smbd >/dev/null
systemctl enable --now sambapanel

sleep 1
if ! systemctl is-active --quiet sambapanel; then
    warn "сервис sambapanel не поднялся, смотри логи: journalctl -u sambapanel -n 50"
else
    step "сервис sambapanel запущен"
fi

# ---------------------------------------------------------------------------
# 8.1 HTTPS через nginx (самоподписанный сертификат)
# ---------------------------------------------------------------------------
# Flask слушает только 127.0.0.1:5000 (см. app.py) — снаружи панель доступна
# ТОЛЬКО через nginx на 443. Без этого пароль при входе шёл бы по сети в
# открытом виде даже в пределах локальной сети.

CERT_DIR="/etc/ssl/sambapanel"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"

step "готовлю самоподписанный TLS-сертификат"
mkdir -p "$CERT_DIR"
if [[ ! -f "$CERT_FILE" || ! -f "$KEY_FILE" ]]; then
    SERVER_IP_FOR_CERT="$(hostname -I 2>/dev/null | awk '{print $1}')"
    openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
        -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -subj "/CN=${SERVER_IP_FOR_CERT:-sambapanel}" \
        -addext "subjectAltName=IP:${SERVER_IP_FOR_CERT:-127.0.0.1},DNS:sambapanel,DNS:localhost" \
        2>/dev/null || fail "не удалось сгенерировать TLS-сертификат"
    chmod 600 "$KEY_FILE"
else
    warn "сертификат в $CERT_DIR уже существует, не пересоздаю"
fi

step "настраиваю nginx (HTTPS-проксирование на панель)"
cat > /etc/nginx/sites-available/sambapanel <<EOF
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name _;

    ssl_certificate     $CERT_FILE;
    ssl_certificate_key $KEY_FILE;
    ssl_protocols TLSv1.2 TLSv1.3;

    client_max_body_size 0;

    location / {
        proxy_pass http://127.0.0.1:$PANEL_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300;
    }
}
EOF

ln -sf /etc/nginx/sites-available/sambapanel /etc/nginx/sites-enabled/sambapanel
# дефолтный сайт nginx слушает :80 и может путать при диагностике — отключаем,
# планировщик HTTPS у нас единственный сайт на этом сервере
rm -f /etc/nginx/sites-enabled/default

if nginx -t &>/dev/null; then
    systemctl enable --now nginx >/dev/null 2>&1 || true
    systemctl restart nginx
    step "nginx настроен и запущен на 443 (HTTPS)"
else
    fail "конфиг nginx не прошёл проверку (nginx -t) — установка остановлена, панель НЕ доступна снаружи. Проверь /etc/nginx/sites-available/sambapanel"
fi

# ---------------------------------------------------------------------------
# 9. Файрвол
# ---------------------------------------------------------------------------
# ВАЖНО: если ufw уже был активен раньше (например, с уже разрешённым SSH),
# просто добавляем правила, ничего больше не трогая. Но если ufw сейчас
# ВЫКЛЮЧЕН, включать его вслепую опасно — можно случайно заблокировать себе
# же SSH-доступ к серверу и потерять управление им удалённо. Поэтому:
#   1. Правила добавляются всегда (это безопасно само по себе — правило
#      без включённого ufw просто не действует, ничего не блокирует).
#   2. Перед возможным включением ufw ВСЕГДА добавляем разрешение для SSH.
#   3. Включаем ufw только по явному подтверждению, никогда не молча.
#   4. Если в итоге ufw остался выключен — говорим об этом ГРОМКО, а не
#      тихо мимо: правила есть, а толку от них ноль, пока ufw неактивен.

if command -v ufw &>/dev/null; then
    echo
    if [[ -t 0 ]]; then
        read -r -p "Открыть 443 (панель, HTTPS) и 445 (Samba) только для локальной подсети (например 192.168.1.0/24)? Введи подсеть или Enter, чтобы пропустить: " LAN_SUBNET || true
    else
        LAN_SUBNET=""
    fi
    if [[ -n "${LAN_SUBNET:-}" ]]; then
        ufw allow from "$LAN_SUBNET" to any port 443 proto tcp
        ufw allow from "$LAN_SUBNET" to any port 445 proto tcp
        step "ufw: разрешён доступ с $LAN_SUBNET к портам 443 (панель) и 445 (Samba)"
    else
        warn "правило файрвола не добавлено — добавь его руками, панель НЕ должна смотреть в интернет:"
        echo "    sudo ufw allow from ТВОЯ_ПОДСЕТЬ to any port 443 proto tcp"
    fi

    ufw_status="$(ufw status | head -1)"
    if [[ "$ufw_status" == *"inactive"* ]]; then
        echo
        warn "ufw СЕЙЧАС ВЫКЛЮЧЕН — все правила выше добавлены, но реально ничего не блокируют и не разрешают, пока ufw неактивен."
        # разрешаем SSH ВСЕГДА перед тем, как предложить включение — иначе
        # можно отрезать себе удалённый доступ к серверу этим же шагом
        ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp >/dev/null 2>&1 || true
        if [[ -t 0 ]]; then
            read -r -p "Включить ufw сейчас? SSH (порт 22) уже разрешён отдельно, чтобы не потерять доступ к серверу. Другие сервисы, не прописанные в правилах, окажутся заблокированы. [y/N] " ENABLE_UFW || true
            if [[ "${ENABLE_UFW,,}" == "y" ]]; then
                ufw --force enable
                step "ufw включён"
            else
                warn "ufw оставлен выключенным по твоему выбору — включи вручную, когда будешь готов: sudo ufw enable"
            fi
        else
            warn "неинтерактивный запуск — ufw НЕ включён автоматически (это должно быть осознанное решение). Включи вручную: sudo ufw enable"
        fi
    else
        step "ufw уже активен (status: $ufw_status)"
    fi
fi

# ---------------------------------------------------------------------------
# 10. Автообновления безопасности (unattended-upgrades)
# ---------------------------------------------------------------------------
# Это настройка всей системы, а не только Samba/панели — спрашиваем явно,
# а не включаем молча. Автообновления ставят только пакеты из origin
# "security" (и origin release-updates для LTS, в зависимости от того, что
# уже прописано в стандартном конфиге пакета unattended-upgrades на Ubuntu) —
# не полное `apt upgrade` всего подряд, это осознанно консервативный набор.

echo
if [[ -t 0 ]]; then
    read -r -p "Включить автообновления безопасности системы (unattended-upgrades)? [Y/n] " ENABLE_UNATTENDED || true
else
    ENABLE_UNATTENDED="y"
fi

if [[ "${ENABLE_UNATTENDED,,}" != "n" ]]; then
    step "устанавливаю и включаю unattended-upgrades"
    apt install -y -qq unattended-upgrades >/dev/null

    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
    step "unattended-upgrades включён (список источников обновлений — стандартный из /etc/apt/apt.conf.d/50unattended-upgrades)"
else
    warn "автообновления безопасности пропущены по твоему выбору — включить позже: sudo dpkg-reconfigure -plow unattended-upgrades"
fi

# ---------------------------------------------------------------------------
# 11. Уведомления о падении сервисов (Telegram/почта)
# ---------------------------------------------------------------------------
# Без заполненного /etc/sambapanel/notify.conf уведомления просто не
# отправляются (скрипт тихо пишет в journal и ничего не падает) — поэтому
# этот шаг безопасно ставить всегда, настройку каналов делаешь отдельно,
# когда будет время/желание, отредактировав notify.conf.

step "устанавливаю уведомления о падении сервисов (Telegram/почта — настраиваются отдельно)"
install -m 750 -o root -g root "$SCRIPT_DIR/samba-notify-failure.sh" /usr/local/sbin/samba-notify-failure.sh
install -m 644 -o root -g root "$SCRIPT_DIR/samba-notify@.service" /etc/systemd/system/samba-notify@.service

mkdir -p /etc/sambapanel
if [[ ! -f /etc/sambapanel/notify.conf ]]; then
    install -m 640 -o root -g root "$SCRIPT_DIR/notify.conf.example" /etc/sambapanel/notify.conf
    step "создан шаблон /etc/sambapanel/notify.conf — заполни его, чтобы уведомления реально отправлялись (см. README)"
else
    warn "/etc/sambapanel/notify.conf уже существует, не трогаю"
fi

# Подключаем OnFailure= к нашим собственным юнитам напрямую...
for unit in sambapanel.service samba-backup.service samba-recycle-cleanup.service; do
    unit_path="/etc/systemd/system/${unit}"
    if [[ -f "$unit_path" ]] && ! grep -q "OnFailure=" "$unit_path"; then
        sed -i "/^\[Unit\]/a OnFailure=samba-notify@%n.service" "$unit_path"
    fi
done

# ...а для системных юнитов (не наших — их файлы нельзя редактировать
# напрямую, apt-обновление пакета перезапишет правку) — через drop-in override.
for unit in smbd.service clamav-daemon.service nginx.service; do
    override_dir="/etc/systemd/system/${unit}.d"
    mkdir -p "$override_dir"
    cat > "${override_dir}/samba-notify-override.conf" <<EOF
[Unit]
OnFailure=samba-notify@%n.service
EOF
done

systemctl daemon-reload
step "уведомления подключены к: sambapanel, samba-backup, samba-recycle-cleanup, smbd, clamav-daemon, nginx"

# ---------------------------------------------------------------------------
# Готово
# ---------------------------------------------------------------------------

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
echo -e "${c_green}========================================================${c_reset}"
echo "  Установка завершена."
echo
echo "  Панель:   https://${IP:-<IP-сервера>}"
echo "  Пароль:   ${PANEL_PASSWORD}"
echo
echo "  Браузер покажет предупреждение о сертификате — сертификат"
echo "  самоподписанный, это ожидаемо для локального сервера. Прими"
echo "  риск и продолжи (в Chrome: 'Advanced' -> 'Proceed anyway')."
echo
echo "  Базовая шара уже создана: $DEFAULT_SHARE (группа $SHAREGROUP)"
echo "  Новые шары и пользователей создавай прямо из панели."
echo "  Антивирус (ClamAV) и корзина включаются по кнопке для каждой шары."
echo
echo "  Логи панели:   journalctl -u sambapanel -f"
echo "  Логи nginx:    journalctl -u nginx -f"
echo "  Статус Samba:  systemctl status smbd"
echo "  Статус ClamAV: systemctl status clamav-daemon"
echo -e "${c_green}========================================================${c_reset}"
echo
