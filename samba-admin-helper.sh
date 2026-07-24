#!/usr/bin/env bash
# samba-admin-helper.sh
# Единственный скрипт, которому разрешено выполняться от root через sudoers.
# Flask-приложение НИКОГДА не запускается от root — оно зовёт этот скрипт
# через `sudo /usr/local/sbin/samba-admin-helper.sh <command> <args>`.
#
# Пароли передаются через stdin, а не через argv, чтобы не светиться в `ps aux`.

set -euo pipefail

SHAREGROUP="sharegroup"
USERNAME_RE='^[a-z][a-z0-9_-]{0,31}$'
SHARENAME_RE='^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$'
SHAREPATH_RE='^/[A-Za-z0-9_./-]+$'
RESERVED_SHARE_NAMES="global homes printers print\$ netlogon profiles"
# один токен списка hosts: IPv4 или IPv4/маска. Список токенов через запятую, либо слово ALL.
HOSTTOKEN_RE='^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$'
# один токен списка veto: расширение файла без точки, буквы/цифры, до 10 символов. Через запятую, либо NONE.
VETOTOKEN_RE='^[a-zA-Z0-9]{1,10}$'
RETENTIONDAYS_RE='^[0-9]{1,4}$'
QUOTABYTES_RE='^[0-9]{1,15}$'
CLAMD_SOCKET="/var/run/clamav/clamd.ctl"
BACKUP_CONF="/etc/sambapanel/backup.conf"
FILE_AUDIT_LOG="/var/log/samba-full-audit/full-audit.log"
# устройство: /dev/ + буквы/цифры (sdb1, nvme0n1p1, mapper/vg-lv и т.п.)
DEVICE_RE='^/dev/[a-zA-Z0-9/_-]+$'
# точка монтирования: как путь шары, но отдельный список запрещённых системных путей
MOUNTPATH_RE='^/[A-Za-z0-9_./-]+$'
# NetBIOS-имя домена и realm: буквы/цифры/дефис/точка (realm обычно ВЕРХНИЙ РЕГИСТР)
WORKGROUP_RE='^[A-Za-z0-9-]{1,15}$'
REALM_RE='^[A-Za-z0-9.-]{1,255}$'
SMB_CONF="/etc/samba/smb.conf"
UPDATE_REPO="lukomsky85/samba-admin-panel"
VERSION_FILE="/opt/sambapanel/VERSION"
TAG_RE='^[A-Za-z0-9_.-]{1,64}$'
AD_MARKER_BEGIN="# --- BEGIN AD INTEGRATION (managed by samba-admin panel, do not edit between markers) ---"
AD_MARKER_END="# --- END AD INTEGRATION ---"

FORBIDDEN_PATHS="/ /etc /root /boot /bin /sbin /usr /var /home /proc /sys /dev /lib /lib64"

SHARES_DB="/etc/sambapanel/shares.db"
PANEL_CONF="/etc/samba/panel-shares.conf"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

validate_username() {
    local u="$1"
    if [[ ! "$u" =~ $USERNAME_RE ]]; then
        echo "ERROR: недопустимое имя пользователя '$u' (только a-z, 0-9, -, _, старт с буквы, максимум 32 символа)" >&2
        exit 1
    fi
}

validate_share_name() {
    local n="$1"
    if [[ ! "$n" =~ $SHARENAME_RE ]]; then
        echo "ERROR: недопустимое имя шары '$n' (буквы, цифры, -, _, старт с буквы, максимум 32 символа)" >&2
        exit 1
    fi
    for r in $RESERVED_SHARE_NAMES; do
        if [[ "${n,,}" == "${r,,}" ]]; then
            echo "ERROR: имя шары '$n' зарезервировано Samba, выбери другое" >&2
            exit 1
        fi
    done
}

validate_share_path() {
    local p="$1"
    if [[ ! "$p" =~ $SHAREPATH_RE ]]; then
        echo "ERROR: путь должен быть абсолютным и содержать только буквы/цифры/-/_/. (получено: '$p')" >&2
        exit 1
    fi
    if [[ "$p" == *".."* ]]; then
        echo "ERROR: путь не может содержать '..'" >&2
        exit 1
    fi
    for f in $FORBIDDEN_PATHS; do
        if [[ "$p" == "$f" ]]; then
            echo "ERROR: путь '$p' — системная директория, её расшарить нельзя" >&2
            exit 1
        fi
    done
}

validate_share_group() {
    # Четыре варианта значения:
    #  - "GUEST" -> гостевой доступ без пароля (см. предупреждения в create_share)
    #  - обычное имя  -> локальная Unix-группа (как раньше)
    #  - "AD:группа" или "AD:ДОМЕН\группа" -> группа Active Directory
    #    (резолвится через winbind/NSS, не создаётся через groupadd)
    #  - "ADUSERS:user1,user2,..." -> конкретные пользователи AD напрямую,
    #    без общей группы (валидны 'user' или 'ДОМЕН\user' для каждого)
    # Пробелы в AD-именах намеренно не поддерживаются — избегаем возни с
    # кавычками в smb.conf для строк с пробелами.
    local g="$1"
    if [[ "$g" == "GUEST" ]]; then
        : # валидно как есть, никаких дополнительных проверок не требуется
    elif [[ "$g" == AD:* ]]; then
        local adg="${g#AD:}"
        if [[ -z "$adg" || ! "$adg" =~ ^[A-Za-z0-9_.-]+(\\[A-Za-z0-9_.-]+)?$ ]]; then
            echo "ERROR: некорректное имя AD-группы (без пробелов; допустимо 'группа' или 'ДОМЕН\\группа')" >&2
            exit 1
        fi
    elif [[ "$g" == ADUSERS:* ]]; then
        local adu="${g#ADUSERS:}"
        if [[ -z "$adu" ]]; then
            echo "ERROR: не указан ни один AD-пользователь" >&2
            exit 1
        fi
        local u
        IFS=',' read -ra _ad_users_check <<< "$adu"
        for u in "${_ad_users_check[@]}"; do
            u="$(echo "$u" | xargs)"
            if [[ -z "$u" || ! "$u" =~ ^[A-Za-z0-9_.-]+(\\[A-Za-z0-9_.-]+)?$ ]]; then
                echo "ERROR: некорректное имя AD-пользователя '$u' (без пробелов)" >&2
                exit 1
            fi
        done
    else
        if [[ ! "$g" =~ $USERNAME_RE ]]; then
            echo "ERROR: некорректное имя локальной группы (получено: '$g')" >&2
            exit 1
        fi
    fi
    echo "$g"
}

validate_device() {
    local d="$1"
    if [[ ! "$d" =~ $DEVICE_RE ]]; then
        echo "ERROR: некорректный путь к устройству (получено: '$d')" >&2
        exit 1
    fi
    if [[ ! -b "$d" ]]; then
        echo "ERROR: '$d' не является блочным устройством (диском/разделом)" >&2
        exit 1
    fi
}

validate_mount_path() {
    local p="$1"
    if [[ ! "$p" =~ $MOUNTPATH_RE ]]; then
        echo "ERROR: путь монтирования должен быть абсолютным и содержать только буквы/цифры/-/_/. (получено: '$p')" >&2
        exit 1
    fi
    if [[ "$p" == *".."* ]]; then
        echo "ERROR: путь не может содержать '..'" >&2
        exit 1
    fi
    for f in $FORBIDDEN_PATHS; do
        if [[ "$p" == "$f" ]]; then
            echo "ERROR: '$p' — системная директория, монтировать туда нельзя" >&2
            exit 1
        fi
    done
}

validate_hosts() {
    # Принимает строку через запятую или "ALL". Пустая строка трактуется как ALL.
    local h="${1:-ALL}"
    [[ -z "$h" ]] && h="ALL"
    if [[ "${h^^}" == "ALL" ]]; then
        echo "ALL"
        return 0
    fi
    local token
    IFS=',' read -ra tokens <<< "$h"
    for token in "${tokens[@]}"; do
        token="$(echo "$token" | xargs)"  # trim пробелов
        if [[ ! "$token" =~ $HOSTTOKEN_RE ]]; then
            echo "ERROR: '$token' не похож на IP или подсеть (пример: 192.168.1.0/24 или 10.0.0.5)" >&2
            exit 1
        fi
    done
    echo "$h"
}

validate_veto() {
    # Принимает список расширений через запятую (без точек) или "NONE". Пустая строка = NONE.
    local v="${1:-NONE}"
    [[ -z "$v" ]] && v="NONE"
    if [[ "${v^^}" == "NONE" ]]; then
        echo "NONE"
        return 0
    fi
    local token clean=""
    IFS=',' read -ra tokens <<< "$v"
    for token in "${tokens[@]}"; do
        token="$(echo "$token" | xargs)"
        token="${token#.}"   # если ввели ".exe" — просто срезаем точку
        if [[ ! "$token" =~ $VETOTOKEN_RE ]]; then
            echo "ERROR: '$token' не похоже на расширение файла (пример: exe, bat, ps1)" >&2
            exit 1
        fi
        clean="${clean:+$clean,}$token"
    done
    echo "$clean"
}

validate_recycle() {
    local r="${1:-no}"
    [[ -z "$r" ]] && r="no"
    r="${r,,}"
    if [[ "$r" != "yes" && "$r" != "no" ]]; then
        echo "ERROR: recycle должен быть 'yes' или 'no'" >&2
        exit 1
    fi
    echo "$r"
}

validate_antivirus() {
    local a="${1:-no}"
    [[ -z "$a" ]] && a="no"
    a="${a,,}"
    if [[ "$a" != "yes" && "$a" != "no" ]]; then
        echo "ERROR: antivirus должен быть 'yes' или 'no'" >&2
        exit 1
    fi
    echo "$a"
}

validate_retention_days() {
    # 0 = хранить вечно (только ручная очистка), N>0 = автоочистка старше N дней
    local d="${1:-0}"
    [[ -z "$d" ]] && d="0"
    if [[ ! "$d" =~ $RETENTIONDAYS_RE ]]; then
        echo "ERROR: срок хранения должен быть целым числом дней (0 = хранить вечно)" >&2
        exit 1
    fi
    echo "$d"
}

validate_quota_bytes() {
    # 0 = без лимита. N>0 = лимит в байтах (мониторинговый, НЕ enforced на уровне ФС).
    local q="${1:-0}"
    [[ -z "$q" ]] && q="0"
    if [[ ! "$q" =~ $QUOTABYTES_RE ]]; then
        echo "ERROR: квота должна быть целым числом байт (0 = без лимита)" >&2
        exit 1
    fi
    echo "$q"
}

validate_backup() {
    local b="${1:-no}"
    [[ -z "$b" ]] && b="no"
    b="${b,,}"
    if [[ "$b" != "yes" && "$b" != "no" ]]; then
        echo "ERROR: backup должен быть 'yes' или 'no'" >&2
        exit 1
    fi
    echo "$b"
}

validate_full_audit() {
    local a="${1:-no}"
    [[ -z "$a" ]] && a="no"
    a="${a,,}"
    if [[ "$a" != "yes" && "$a" != "no" ]]; then
        echo "ERROR: full_audit должен быть 'yes' или 'no'" >&2
        exit 1
    fi
    echo "$a"
}

ensure_db() {
    mkdir -p "$(dirname "$SHARES_DB")"
    touch "$SHARES_DB"
}

regenerate_conf() {
    ensure_db
    {
        echo "# АВТОГЕНЕРИРУЕТСЯ samba-admin-helper.sh — руками не редактировать,"
        echo "# правки будут потеряны при следующем изменении через панель."
        echo
        while IFS='|' read -r s_name s_path s_group s_writable s_hosts s_veto s_recycle s_retention s_av s_quota s_backup s_audit; do
            [[ -z "$s_name" ]] && continue
            s_hosts="${s_hosts:-ALL}"
            s_veto="${s_veto:-NONE}"
            s_recycle="${s_recycle:-no}"
            s_retention="${s_retention:-0}"
            s_av="${s_av:-no}"
            s_quota="${s_quota:-0}"
            s_backup="${s_backup:-no}"
            s_audit="${s_audit:-no}"
            echo "[$s_name]"
            echo "   path = $s_path"
            echo "   browseable = yes"
            echo "   writable = $s_writable"
            # Тип доступа закодирован в значении поля группы:
            # "GUEST" — гостевой доступ без пароля (см. предупреждение ниже),
            # "AD:группа" — группа Active Directory (резолвится через winbind),
            # "ADUSERS:user1,user2" — конкретные пользователи AD без общей группы,
            # без префикса — обычная локальная Unix-группа (как было раньше).
            if [[ "$s_group" == "GUEST" ]]; then
                # Гостевой доступ — сознательно БЕЗ "valid users"/"force group":
                # весь смысл гостевой шары в том, что подключиться может кто
                # угодно без учётной записи. Комбинировать guest ok с valid
                # users бессмысленно и вводит в заблуждение (гостевая сессия
                # не проходит проверку по группе всё равно).
                echo "   guest ok = yes"
            elif [[ "$s_group" == AD:* ]]; then
                ad_group="${s_group#AD:}"
                echo "   guest ok = no"
                echo "   valid users = @${ad_group}"
                echo "   force group = ${ad_group}"
            elif [[ "$s_group" == ADUSERS:* ]]; then
                ad_users="${s_group#ADUSERS:}"
                echo "   guest ok = no"
                echo "   valid users = ${ad_users//,/, }"
            else
                echo "   guest ok = no"
                echo "   valid users = @$s_group"
                echo "   force group = $s_group"
            fi
            echo "   create mask = 0664"
            echo "   directory mask = 2775"
            if [[ "${s_hosts^^}" != "ALL" ]]; then
                echo "   hosts allow = $s_hosts"
                echo "   hosts deny = ALL"
            fi
            if [[ "${s_veto^^}" != "NONE" ]]; then
                veto_pattern="/"
                IFS=',' read -ra veto_exts <<< "$s_veto"
                for ext in "${veto_exts[@]}"; do
                    veto_pattern="${veto_pattern}*.${ext}/"
                done
                echo "   veto files = $veto_pattern"
                echo "   delete veto files = no"
            fi
            # recycle, virusfilter и full_audit все навешиваются через
            # "vfs objects" — если включено несколько, их нужно перечислить
            # в ОДНОЙ строке, а не в нескольких "vfs objects = ..." (следующая
            # строка бы просто перезаписала предыдущую в конфиге Samba).
            # Порядок важен: full_audit — первым (внешний слой, видит запрос
            # клиента как есть), затем virusfilter (сканирует ДО того, как
            # recycle решит, что делать при удалении), recycle — последним.
            vfs_list=""
            [[ "$s_audit" == "yes" ]] && vfs_list="full_audit"
            [[ "$s_av" == "yes" ]] && vfs_list="${vfs_list:+$vfs_list }virusfilter"
            [[ "$s_recycle" == "yes" ]] && vfs_list="${vfs_list:+$vfs_list }recycle"
            if [[ -n "$vfs_list" ]]; then
                echo "   vfs objects = $vfs_list"
            fi
            if [[ "$s_audit" == "yes" ]]; then
                # "all" — самый надёжный вариант: официально задокументирован
                # и гарантированно работает на любой версии Samba, в отличие
                # от конкретных имён операций (renameat/rename и т.п.),
                # которые могут отличаться между версиями. Да, это шумно —
                # это и есть "полный" аудит, как и просили.
                echo "   full_audit:prefix = %u|%I|%S"
                echo "   full_audit:success = all"
                echo "   full_audit:failure = all"
                echo "   full_audit:facility = LOCAL5"
                echo "   full_audit:priority = NOTICE"
            fi
            if [[ "$s_av" == "yes" ]]; then
                # scan on open — ловит уже заражённые файлы при попытке их открыть/скачать
                # (защита от файлов, которые попали в шару до включения антивируса).
                # scan on close — ловит вирус сразу при завершении записи/загрузки файла.
                # Нужны оба для полного покрытия.
                echo "   virusfilter:scanner = clamav"
                echo "   virusfilter:socket path = $CLAMD_SOCKET"
                echo "   virusfilter:scan on open = yes"
                echo "   virusfilter:scan on close = yes"
                echo "   virusfilter:max file size = 104857600"
                echo "   virusfilter:infected file action = quarantine"
                echo "   virusfilter:quarantine directory = $s_path/.quarantine"
                echo "   virusfilter:quarantine prefix = virus."
                echo "   virusfilter:quarantine suffix = .infected"
                echo "   virusfilter:quarantine keep tree = yes"
                echo "   virusfilter:rename prefix = virus."
            fi
            if [[ "$s_recycle" == "yes" ]]; then
                echo "   recycle:repository = .recycle"
                echo "   recycle:keeptree = yes"
                echo "   recycle:versions = yes"
                echo "   recycle:touch = yes"
                echo "   recycle:directory_mode = 0775"
                echo "   recycle:subdir_mode = 0775"
            fi
            echo
        done < "$SHARES_DB"
    } > "$PANEL_CONF.tmp"
    mv "$PANEL_CONF.tmp" "$PANEL_CONF"

    if ! testparm -s /etc/samba/smb.conf &>/dev/null; then
        echo "ERROR: сгенерированный конфиг не прошёл testparm — изменения НЕ применены к smbd" >&2
        exit 1
    fi

    # ВАЖНО: используем restart, а не reload. reload посылает SIGHUP, но
    # уже открытые соединения могут продолжать жить со старыми правами
    # (в частности, старый hosts allow/deny) до тех пор, пока клиент не
    # переподключится сам. restart разом сбрасывает все текущие SMB-сессии,
    # так что новые ограничения по IP и права применяются немедленно и без
    # путаницы «а почему старое подключение всё ещё работает».
    log "systemctl restart smbd (сбрасывает текущие SMB-сессии, новые правила применяются сразу)"
    systemctl restart smbd 2>/dev/null || true
}

cmd="${1:-}"
case "$cmd" in

  create_user)
    # Использование: create_user <username>
    # Пароль (unix + samba) читается из stdin, одна строка.
    username="${2:-}"
    validate_username "$username"

    if id "$username" &>/dev/null; then
        echo "ERROR: пользователь '$username' уже существует" >&2
        exit 1
    fi

    read -r password
    if [[ -z "$password" || ${#password} -lt 8 ]]; then
        echo "ERROR: пароль должен быть минимум 8 символов" >&2
        exit 1
    fi

    log "useradd -m -s /bin/bash $username"
    useradd -m -s /bin/bash "$username"

    log "установка unix-пароля"
    echo "${username}:${password}" | chpasswd

    log "добавление в группу $SHAREGROUP"
    groupadd -f "$SHAREGROUP"
    usermod -aG "$SHAREGROUP" "$username"

    log "установка samba-пароля"
    printf '%s\n%s\n' "$password" "$password" | smbpasswd -s -a "$username"

    log "OK: пользователь '$username' создан и подключен к Samba"
    ;;

  remove_user)
    # Использование: remove_user <username>
    username="${2:-}"
    validate_username "$username"

    if ! id "$username" &>/dev/null; then
        echo "ERROR: пользователь '$username' не найден" >&2
        exit 1
    fi

    log "smbpasswd -x $username"
    smbpasswd -x "$username" 2>/dev/null || true

    log "userdel -r $username"
    userdel -r "$username" 2>/dev/null || userdel "$username"

    log "OK: пользователь '$username' удалён"
    ;;

  set_samba_password)
    # Использование: set_samba_password <username>  (пароль из stdin)
    username="${2:-}"
    validate_username "$username"

    if ! id "$username" &>/dev/null; then
        echo "ERROR: пользователь '$username' не найден" >&2
        exit 1
    fi

    read -r password
    if [[ -z "$password" || ${#password} -lt 8 ]]; then
        echo "ERROR: пароль должен быть минимум 8 символов" >&2
        exit 1
    fi

    printf '%s\n%s\n' "$password" "$password" | smbpasswd -s -a "$username"
    log "OK: samba-пароль для '$username' обновлён"
    ;;

  toggle_share_access)
    # Использование: toggle_share_access <username> <on|off>
    username="${2:-}"
    action="${3:-}"
    validate_username "$username"

    if ! id "$username" &>/dev/null; then
        echo "ERROR: пользователь '$username' не найден" >&2
        exit 1
    fi

    case "$action" in
      on)
        usermod -aG "$SHAREGROUP" "$username"
        log "OK: '$username' добавлен в $SHAREGROUP (доступ к шаре включён)"
        ;;
      off)
        gpasswd -d "$username" "$SHAREGROUP" 2>/dev/null || true
        log "OK: '$username' удалён из $SHAREGROUP (доступ к шаре выключён)"
        ;;
      *)
        echo "ERROR: действие должно быть 'on' или 'off'" >&2
        exit 1
        ;;
    esac
    ;;

  create_share)
    # Использование: create_share <name> <path> [group] [writable] [hosts] [veto] [recycle] [retention_days] [antivirus] [quota_bytes] [backup] [full_audit: yes/no]
    name="${2:-}"; path="${3:-}"; group="${4:-$SHAREGROUP}"; writable="${5:-yes}"; hosts_raw="${6:-ALL}"; veto_raw="${7:-NONE}"; recycle_raw="${8:-no}"; retention_raw="${9:-0}"; av_raw="${10:-no}"; quota_raw="${11:-0}"; backup_raw="${12:-no}"; audit_raw="${13:-no}"
    validate_share_name "$name"
    validate_share_path "$path"
    group="$(validate_share_group "$group")"
    hosts="$(validate_hosts "$hosts_raw")"
    veto="$(validate_veto "$veto_raw")"
    recycle="$(validate_recycle "$recycle_raw")"
    retention="$(validate_retention_days "$retention_raw")"
    antivirus="$(validate_antivirus "$av_raw")"
    quota="$(validate_quota_bytes "$quota_raw")"
    backup="$(validate_backup "$backup_raw")"
    full_audit="$(validate_full_audit "$audit_raw")"

    if [[ "$antivirus" == "yes" && ! -S "$CLAMD_SOCKET" ]]; then
        echo "ERROR: ClamAV не запущен (нет сокета $CLAMD_SOCKET) — установи и включи clamav-daemon перед включением антивируса" >&2
        exit 1
    fi

    ensure_db
    if grep -q "^${name}|" "$SHARES_DB" 2>/dev/null; then
        echo "ERROR: шара с именем '$name' уже существует" >&2
        exit 1
    fi
    if [[ "$writable" != "yes" && "$writable" != "no" ]]; then
        echo "ERROR: writable должен быть 'yes' или 'no'" >&2
        exit 1
    fi

    # Определяем, чем владеть папке шары: локальная Unix-группа (создаём
    # через groupadd, как раньше), AD-группа (резолвится через NSS/winbind,
    # НЕ создаётся локально), набор конкретных AD-пользователей (тогда
    # владение группой не имеет смысла — доступ регулируется только через
    # valid users, папка остаётся под root:root), или гостевой доступ (папка
    # должна быть доступна на запись анонимному пользователю, за которого
    # Samba выдаёт себя при guest-подключении — обычно это системный "nobody").
    chmod_mode="2775"
    if [[ "$group" == "GUEST" ]]; then
        chown_target="nogroup"
        chmod_mode="2777"
        chown_note=" (ГОСТЕВОЙ доступ — папка открыта на запись ВСЕМ локальным процессам, не только Samba; это ожидаемо для guest-шары, но не для чувствительных данных)"
    elif [[ "$group" == AD:* ]]; then
        ad_group_name="${group#AD:}"
        if ! command -v getent &>/dev/null || ! getent group "$ad_group_name" &>/dev/null; then
            echo "ERROR: AD-группа '$ad_group_name' не резолвится через NSS — сервер точно присоединён к домену и winbind запущен? Проверь вкладку Active Directory" >&2
            exit 1
        fi
        chown_target="$(getent group "$ad_group_name" | cut -d: -f3)"
        chown_note=" (AD-группа $ad_group_name, gid $chown_target)"
    elif [[ "$group" == ADUSERS:* ]]; then
        chown_target="root"
        chown_note=" (доступ по конкретным AD-пользователям, без общей группы)"
    else
        groupadd -f "$group"
        chown_target="$group"
        chown_note=""
    fi

    log "mkdir -p $path"
    mkdir -p "$path"

    log "chown root:$chown_target $path$chown_note && chmod $chmod_mode $path"
    chown root:"$chown_target" "$path"
    chmod "$chmod_mode" "$path"

    if [[ "$recycle" == "yes" ]]; then
        mkdir -p "$path/.recycle"
        chown root:"$chown_target" "$path/.recycle"
        chmod 2775 "$path/.recycle"
    fi

    if [[ "$antivirus" == "yes" ]]; then
        mkdir -p "$path/.quarantine"
        chown root:"$chown_target" "$path/.quarantine"
        chmod 2775 "$path/.quarantine"
    fi

    echo "${name}|${path}|${group}|${writable}|${hosts}|${veto}|${recycle}|${retention}|${antivirus}|${quota}|${backup}|${full_audit}" >> "$SHARES_DB"
    regenerate_conf

    extra=""
    [[ "$hosts" != "ALL" ]] && extra="$extra, доступ только с: $hosts"
    [[ "$veto" != "NONE" ]] && extra="$extra, запрещены файлы: $veto"
    if [[ "$recycle" == "yes" ]]; then
        if [[ "$retention" == "0" ]]; then
            extra="$extra, корзина включена (хранить навсегда)"
        else
            extra="$extra, корзина включена (автоочистка старше $retention дней)"
        fi
    fi
    [[ "$antivirus" == "yes" ]] && extra="$extra, антивирус включён"
    [[ "$quota" != "0" ]] && extra="$extra, квота: $quota байт (мониторинг)"
    [[ "$backup" == "yes" ]] && extra="$extra, бэкап включён"
    [[ "$full_audit" == "yes" ]] && extra="$extra, полный аудит файловых операций включён"
    log "OK: шара '$name' создана -> $path (группа $group, writable=$writable$extra)"
    ;;

  remove_share)
    # Использование: remove_share <name>
    # Папку и файлы НЕ удаляет — только убирает шару из конфига Samba.
    name="${2:-}"
    validate_share_name "$name"

    ensure_db
    if ! grep -q "^${name}|" "$SHARES_DB" 2>/dev/null; then
        echo "ERROR: шара '$name' не найдена" >&2
        exit 1
    fi

    grep -v "^${name}|" "$SHARES_DB" > "$SHARES_DB.tmp" || true
    mv "$SHARES_DB.tmp" "$SHARES_DB"
    regenerate_conf

    log "OK: шара '$name' удалена из конфига (данные на диске НЕ тронуты)"
    ;;

  set_share_writable)
    # Использование: set_share_writable <name> <yes|no>
    name="${2:-}"; writable="${3:-}"
    validate_share_name "$name"
    if [[ "$writable" != "yes" && "$writable" != "no" ]]; then
        echo "ERROR: writable должен быть 'yes' или 'no'" >&2
        exit 1
    fi

    ensure_db
    if ! grep -q "^${name}|" "$SHARES_DB" 2>/dev/null; then
        echo "ERROR: шара '$name' не найдена" >&2
        exit 1
    fi

    line="$(grep "^${name}|" "$SHARES_DB")"
    IFS='|' read -r n p g _ h v rc rd av q b a <<< "$line"
    grep -v "^${name}|" "$SHARES_DB" > "$SHARES_DB.tmp" || true
    echo "${n}|${p}|${g}|${writable}|${h:-ALL}|${v:-NONE}|${rc:-no}|${rd:-0}|${av:-no}|${q:-0}|${b:-no}|${a:-no}" >> "$SHARES_DB.tmp"
    mv "$SHARES_DB.tmp" "$SHARES_DB"
    regenerate_conf

    log "OK: шара '$name' теперь writable=$writable"
    ;;

  set_share_hosts)
    # Использование: set_share_hosts <name> <"ALL" или список IP/подсетей через запятую>
    name="${2:-}"; hosts_raw="${3:-ALL}"
    validate_share_name "$name"
    hosts="$(validate_hosts "$hosts_raw")"

    ensure_db
    if ! grep -q "^${name}|" "$SHARES_DB" 2>/dev/null; then
        echo "ERROR: шара '$name' не найдена" >&2
        exit 1
    fi

    line="$(grep "^${name}|" "$SHARES_DB")"
    IFS='|' read -r n p g w _ v rc rd av q b a <<< "$line"
    grep -v "^${name}|" "$SHARES_DB" > "$SHARES_DB.tmp" || true
    echo "${n}|${p}|${g}|${w}|${hosts}|${v:-NONE}|${rc:-no}|${rd:-0}|${av:-no}|${q:-0}|${b:-no}|${a:-no}" >> "$SHARES_DB.tmp"
    mv "$SHARES_DB.tmp" "$SHARES_DB"
    regenerate_conf

    if [[ "$hosts" == "ALL" ]]; then
        log "OK: шара '$name' — ограничение по IP снято (доступ без ограничений)"
    else
        log "OK: шара '$name' — доступ теперь разрешён только с: $hosts"
    fi
    ;;

  set_share_veto)
    # Использование: set_share_veto <name> <"NONE" или список расширений через запятую>
    name="${2:-}"; veto_raw="${3:-NONE}"
    validate_share_name "$name"
    veto="$(validate_veto "$veto_raw")"

    ensure_db
    if ! grep -q "^${name}|" "$SHARES_DB" 2>/dev/null; then
        echo "ERROR: шара '$name' не найдена" >&2
        exit 1
    fi

    line="$(grep "^${name}|" "$SHARES_DB")"
    IFS='|' read -r n p g w h _ rc rd av q b a <<< "$line"
    grep -v "^${name}|" "$SHARES_DB" > "$SHARES_DB.tmp" || true
    echo "${n}|${p}|${g}|${w}|${h:-ALL}|${veto}|${rc:-no}|${rd:-0}|${av:-no}|${q:-0}|${b:-no}|${a:-no}" >> "$SHARES_DB.tmp"
    mv "$SHARES_DB.tmp" "$SHARES_DB"
    regenerate_conf

    if [[ "$veto" == "NONE" ]]; then
        log "OK: шара '$name' — ограничение на типы файлов снято"
    else
        log "OK: шара '$name' — запрещена запись файлов с расширениями: $veto"
    fi
    ;;

  set_share_recycle)
    # Использование: set_share_recycle <name> <yes|no> [retention_days: 0=навсегда]
    name="${2:-}"; recycle_raw="${3:-no}"; retention_raw="${4:-0}"
    validate_share_name "$name"
    recycle="$(validate_recycle "$recycle_raw")"
    retention="$(validate_retention_days "$retention_raw")"

    ensure_db
    if ! grep -q "^${name}|" "$SHARES_DB" 2>/dev/null; then
        echo "ERROR: шара '$name' не найдена" >&2
        exit 1
    fi

    line="$(grep "^${name}|" "$SHARES_DB")"
    IFS='|' read -r n p g w h v _ _ av q b a <<< "$line"
    grep -v "^${name}|" "$SHARES_DB" > "$SHARES_DB.tmp" || true
    echo "${n}|${p}|${g}|${w}|${h:-ALL}|${v:-NONE}|${recycle}|${retention}|${av:-no}|${q:-0}|${b:-no}|${a:-no}" >> "$SHARES_DB.tmp"
    mv "$SHARES_DB.tmp" "$SHARES_DB"

    if [[ "$recycle" == "yes" ]]; then
        mkdir -p "$p/.recycle"
        chown root:"$g" "$p/.recycle"
        chmod 2775 "$p/.recycle"
    fi

    regenerate_conf

    if [[ "$recycle" == "no" ]]; then
        log "OK: шара '$name' — корзина выключена (файлы будут удаляться безвозвратно)"
    elif [[ "$retention" == "0" ]]; then
        log "OK: шара '$name' — корзина включена, хранить навсегда (только ручная очистка)"
    else
        log "OK: шара '$name' — корзина включена, автоочистка старше $retention дней"
    fi
    ;;

  set_share_antivirus)
    # Использование: set_share_antivirus <name> <yes|no>
    name="${2:-}"; av_raw="${3:-no}"
    validate_share_name "$name"
    antivirus="$(validate_antivirus "$av_raw")"

    if [[ "$antivirus" == "yes" && ! -S "$CLAMD_SOCKET" ]]; then
        echo "ERROR: ClamAV не запущен (нет сокета $CLAMD_SOCKET) — установи и включи clamav-daemon перед включением антивируса" >&2
        exit 1
    fi

    ensure_db
    if ! grep -q "^${name}|" "$SHARES_DB" 2>/dev/null; then
        echo "ERROR: шара '$name' не найдена" >&2
        exit 1
    fi

    line="$(grep "^${name}|" "$SHARES_DB")"
    IFS='|' read -r n p g w h v rc rd _ q b a <<< "$line"
    grep -v "^${name}|" "$SHARES_DB" > "$SHARES_DB.tmp" || true
    echo "${n}|${p}|${g}|${w}|${h:-ALL}|${v:-NONE}|${rc:-no}|${rd:-0}|${antivirus}|${q:-0}|${b:-no}|${a:-no}" >> "$SHARES_DB.tmp"
    mv "$SHARES_DB.tmp" "$SHARES_DB"

    if [[ "$antivirus" == "yes" ]]; then
        mkdir -p "$p/.quarantine"
        chown root:"$g" "$p/.quarantine"
        chmod 2775 "$p/.quarantine"
    fi

    regenerate_conf

    if [[ "$antivirus" == "yes" ]]; then
        log "OK: шара '$name' — антивирус включён (ClamAV, сканирование при записи и открытии файлов)"
    else
        log "OK: шара '$name' — антивирус выключен"
    fi
    ;;

  set_share_quota)
    # Использование: set_share_quota <name> <quota_bytes: 0=без лимита>
    # ВНИМАНИЕ: это МОНИТОРИНГОВАЯ квота, не enforced на уровне файловой
    # системы. Панель подсвечивает превышение в "Место на диске", но
    # физически ничто не мешает записать больше — Samba не умеет ограничивать
    # запись по объёму без реальных ФС-квот (XFS project quota и т.п.).
    name="${2:-}"; quota_raw="${3:-0}"
    validate_share_name "$name"
    quota="$(validate_quota_bytes "$quota_raw")"

    ensure_db
    if ! grep -q "^${name}|" "$SHARES_DB" 2>/dev/null; then
        echo "ERROR: шара '$name' не найдена" >&2
        exit 1
    fi

    line="$(grep "^${name}|" "$SHARES_DB")"
    IFS='|' read -r n p g w h v rc rd av _ b a <<< "$line"
    grep -v "^${name}|" "$SHARES_DB" > "$SHARES_DB.tmp" || true
    echo "${n}|${p}|${g}|${w}|${h:-ALL}|${v:-NONE}|${rc:-no}|${rd:-0}|${av:-no}|${quota}|${b:-no}|${a:-no}" >> "$SHARES_DB.tmp"
    mv "$SHARES_DB.tmp" "$SHARES_DB"

    if [[ "$quota" == "0" ]]; then
        log "OK: шара '$name' — квота снята"
    else
        log "OK: шара '$name' — квота (мониторинговая) установлена: $quota байт"
    fi
    ;;

  set_share_group)
    # Использование: set_share_group <name> <new_group>
    # new_group — то же самое кодирование, что и при создании шары:
    # обычное имя (локальная группа), "AD:группа" (группа Active Directory),
    # или "ADUSERS:user1,user2" (конкретные пользователи AD без общей группы).
    name="${2:-}"; new_group_raw="${3:-}"
    validate_share_name "$name"
    new_group="$(validate_share_group "$new_group_raw")"

    ensure_db
    if ! grep -q "^${name}|" "$SHARES_DB" 2>/dev/null; then
        echo "ERROR: шара '$name' не найдена" >&2
        exit 1
    fi

    line="$(grep "^${name}|" "$SHARES_DB")"
    IFS='|' read -r n p g w h v rc rd av q b a <<< "$line"

    chmod_mode="2775"
    if [[ "$new_group" == "GUEST" ]]; then
        chown_target="nogroup"
        chmod_mode="2777"
    elif [[ "$new_group" == AD:* ]]; then
        ad_group_name="${new_group#AD:}"
        if ! getent group "$ad_group_name" &>/dev/null; then
            echo "ERROR: AD-группа '$ad_group_name' не резолвится через NSS — сервер присоединён к домену и winbind запущен?" >&2
            exit 1
        fi
        chown_target="$(getent group "$ad_group_name" | cut -d: -f3)"
    elif [[ "$new_group" == ADUSERS:* ]]; then
        chown_target="root"
    else
        groupadd -f "$new_group"
        chown_target="$new_group"
    fi

    chown root:"$chown_target" "$p" 2>/dev/null || true
    chmod "$chmod_mode" "$p" 2>/dev/null || true
    [[ -d "$p/.recycle" ]] && { chown root:"$chown_target" "$p/.recycle" 2>/dev/null || true; }
    [[ -d "$p/.quarantine" ]] && { chown root:"$chown_target" "$p/.quarantine" 2>/dev/null || true; }

    grep -v "^${name}|" "$SHARES_DB" > "$SHARES_DB.tmp" || true
    echo "${n}|${p}|${new_group}|${w}|${h:-ALL}|${v:-NONE}|${rc:-no}|${rd:-0}|${av:-no}|${q:-0}|${b:-no}|${a:-no}" >> "$SHARES_DB.tmp"
    mv "$SHARES_DB.tmp" "$SHARES_DB"
    regenerate_conf

    log "OK: шара '$name' — группа доступа изменена на '$new_group'"
    ;;

  set_share_backup)
    # Использование: set_share_backup <name> <yes|no>
    name="${2:-}"; backup_raw="${3:-no}"
    validate_share_name "$name"
    backup="$(validate_backup "$backup_raw")"

    ensure_db
    if ! grep -q "^${name}|" "$SHARES_DB" 2>/dev/null; then
        echo "ERROR: шара '$name' не найдена" >&2
        exit 1
    fi

    if [[ "$backup" == "yes" ]]; then
        if [[ ! -f "$BACKUP_CONF" ]]; then
            echo "ERROR: бэкап не настроен на сервере (нет $BACKUP_CONF) — задай BACKUP_DEST при установке или создай файл руками" >&2
            exit 1
        fi
        source "$BACKUP_CONF" 2>/dev/null || true
        if [[ -z "${BACKUP_DEST:-}" ]]; then
            echo "ERROR: в $BACKUP_CONF не задан BACKUP_DEST" >&2
            exit 1
        fi
        if [[ ! -d "$BACKUP_DEST" ]]; then
            echo "ERROR: папка назначения бэкапов '$BACKUP_DEST' не существует" >&2
            exit 1
        fi
    fi

    line="$(grep "^${name}|" "$SHARES_DB")"
    IFS='|' read -r n p g w h v rc rd av q _ a <<< "$line"
    grep -v "^${name}|" "$SHARES_DB" > "$SHARES_DB.tmp" || true
    echo "${n}|${p}|${g}|${w}|${h:-ALL}|${v:-NONE}|${rc:-no}|${rd:-0}|${av:-no}|${q:-0}|${backup}|${a:-no}" >> "$SHARES_DB.tmp"
    mv "$SHARES_DB.tmp" "$SHARES_DB"

    if [[ "$backup" == "yes" ]]; then
        log "OK: шара '$name' — бэкап включён (следующий запуск таймера подхватит её)"
    else
        log "OK: шара '$name' — бэкап выключен (старые архивы на месте, новые создаваться не будут)"
    fi
    ;;

  empty_recycle_bin)
    # Использование: empty_recycle_bin <name>
    # Безвозвратно удаляет ВСЁ содержимое .recycle для этой шары.
    name="${2:-}"
    validate_share_name "$name"

    ensure_db
    if ! grep -q "^${name}|" "$SHARES_DB" 2>/dev/null; then
        echo "ERROR: шара '$name' не найдена" >&2
        exit 1
    fi

    line="$(grep "^${name}|" "$SHARES_DB")"
    IFS='|' read -r n p g w h v rc rd av q b a <<< "$line"

    recycle_dir="$p/.recycle"
    if [[ ! -d "$recycle_dir" ]]; then
        log "OK: у шары '$name' корзина пуста или не создана — ничего удалять не нужно"
    else
        count="$(find "$recycle_dir" -type f 2>/dev/null | wc -l)"
        log "rm -rf $recycle_dir/* (файлов: $count)"
        find "$recycle_dir" -mindepth 1 -delete 2>/dev/null || true
        log "OK: корзина шары '$name' очищена ($count файлов удалено безвозвратно)"
    fi
    ;;

  list_recycle_bin)
    # Использование: list_recycle_bin <name>
    # Выводит файлы в корзине с относительным путём (в base64, чтобы имена
    # с пробелами/спецсимволами не ломали протокол '|'), размером и датой.
    name="${2:-}"
    validate_share_name "$name"

    ensure_db
    if ! grep -q "^${name}|" "$SHARES_DB" 2>/dev/null; then
        echo "ERROR: шара '$name' не найдена" >&2
        exit 1
    fi

    line="$(grep "^${name}|" "$SHARES_DB")"
    IFS='|' read -r n p g w h v rc rd av q b a <<< "$line"

    recycle_dir="$p/.recycle"
    if [[ ! -d "$recycle_dir" ]]; then
        echo "  (корзина пуста)"
    else
        find "$recycle_dir" -type f 2>/dev/null | while read -r f; do
            relpath="${f#"$recycle_dir"/}"
            relpath_b64="$(printf '%s' "$relpath" | base64 -w0)"
            size="$(stat -c %s "$f" 2>/dev/null || echo 0)"
            mtime="$(stat -c %Y "$f" 2>/dev/null || echo 0)"
            echo "RECYCLEFILE|${relpath_b64}|${size}|${mtime}"
        done
    fi
    ;;

  restore_recycle_file)
    # Использование: restore_recycle_file <name> <base64(relative_path)>
    # Возвращает конкретный файл из корзины обратно в шару. Если по этому
    # пути в шаре уже что-то есть — не перезаписывает, а добавляет
    # суффикс ".restored-<timestamp>", чтобы ничего не потерять молча.
    name="${2:-}"; relpath_b64="${3:-}"
    validate_share_name "$name"

    if [[ -z "$relpath_b64" ]]; then
        echo "ERROR: не передан путь к файлу в корзине" >&2
        exit 1
    fi

    ensure_db
    if ! grep -q "^${name}|" "$SHARES_DB" 2>/dev/null; then
        echo "ERROR: шара '$name' не найдена" >&2
        exit 1
    fi

    line="$(grep "^${name}|" "$SHARES_DB")"
    IFS='|' read -r n p g w h v rc rd av q b a <<< "$line"

    relpath="$(printf '%s' "$relpath_b64" | base64 -d 2>/dev/null)"
    if [[ -z "$relpath" || "$relpath" == *".."* ]]; then
        echo "ERROR: некорректный путь к файлу" >&2
        exit 1
    fi

    recycle_dir="$p/.recycle"
    source_file="$recycle_dir/$relpath"
    dest_file="$p/$relpath"

    if [[ ! -f "$source_file" ]]; then
        echo "ERROR: файл '$relpath' не найден в корзине (возможно, уже восстановлен или удалён)" >&2
        exit 1
    fi

    if [[ -e "$dest_file" ]]; then
        dest_file="${dest_file}.restored-$(date +%s)"
        log "по исходному пути уже что-то есть — восстанавливаю как '$(basename "$dest_file")', чтобы не перезаписать"
    fi

    mkdir -p "$(dirname "$dest_file")"
    mv "$source_file" "$dest_file"
    chown :"$g" "$dest_file" 2>/dev/null || true

    log "OK: файл восстановлен из корзины шары '$name' -> $dest_file"
    ;;

  empty_quarantine)
    # Использование: empty_quarantine <name>
    # Безвозвратно удаляет ВСЁ содержимое .quarantine (заражённые файлы) для этой шары.
    name="${2:-}"
    validate_share_name "$name"

    ensure_db
    if ! grep -q "^${name}|" "$SHARES_DB" 2>/dev/null; then
        echo "ERROR: шара '$name' не найдена" >&2
        exit 1
    fi

    line="$(grep "^${name}|" "$SHARES_DB")"
    IFS='|' read -r n p g w h v rc rd av q b a <<< "$line"

    quarantine_dir="$p/.quarantine"
    if [[ ! -d "$quarantine_dir" ]]; then
        log "OK: у шары '$name' карантин пуст или не создан — ничего удалять не нужно"
    else
        count="$(find "$quarantine_dir" -type f 2>/dev/null | wc -l)"
        log "rm -rf $quarantine_dir/* (заражённых файлов: $count)"
        find "$quarantine_dir" -mindepth 1 -delete 2>/dev/null || true
        log "OK: карантин шары '$name' очищен ($count файлов удалено безвозвратно)"
    fi
    ;;

  set_share_full_audit)
    # Использование: set_share_full_audit <name> <yes|no>
    # Включает vfs_full_audit — полный лог файловых операций (кто, что,
    # когда) в /var/log/sambapanel/file-audit.log через syslog/rsyslog.
    # Требует, чтобы install.sh (или ручная настройка) уже прописал правило
    # маршрутизации LOCAL5 в rsyslog — иначе сообщения уйдут в общий syslog.
    name="${2:-}"; audit_raw="${3:-no}"
    validate_share_name "$name"
    full_audit="$(validate_full_audit "$audit_raw")"

    ensure_db
    if ! grep -q "^${name}|" "$SHARES_DB" 2>/dev/null; then
        echo "ERROR: шара '$name' не найдена" >&2
        exit 1
    fi

    line="$(grep "^${name}|" "$SHARES_DB")"
    IFS='|' read -r n p g w h v rc rd av q b _ <<< "$line"
    grep -v "^${name}|" "$SHARES_DB" > "$SHARES_DB.tmp" || true
    echo "${n}|${p}|${g}|${w}|${h:-ALL}|${v:-NONE}|${rc:-no}|${rd:-0}|${av:-no}|${q:-0}|${b:-no}|${full_audit}" >> "$SHARES_DB.tmp"
    mv "$SHARES_DB.tmp" "$SHARES_DB"
    regenerate_conf

    if [[ "$full_audit" == "yes" ]]; then
        log "OK: шара '$name' — полный аудит файловых операций включён (это ШУМНО — логируется каждая операция, см. /var/log/sambapanel/file-audit.log)"
    else
        log "OK: шара '$name' — полный аудит файловых операций выключен"
    fi
    ;;

  file_audit_log)
    # Показывает последние строки лога файловых операций (не журнал действий
    # администратора — это отдельная вещь, см. list_users/create_share и т.п.)
    if [[ ! -f "$FILE_AUDIT_LOG" ]]; then
        echo "(лога файловых операций пока нет — либо ни на одной шаре не включён полный аудит, либо ещё не было ни одной операции)"
    else
        tail -n 200 "$FILE_AUDIT_LOG"
    fi
    ;;

  list_shares)
    ensure_db
    backup_dest=""
    [[ -f "$BACKUP_CONF" ]] && source "$BACKUP_CONF" 2>/dev/null
    backup_dest="${BACKUP_DEST:-}"
    if [[ ! -s "$SHARES_DB" ]]; then
        echo "  (шар пока нет)"
    else
        while IFS='|' read -r s_name s_path s_group s_writable s_hosts s_veto s_recycle s_retention s_av s_quota s_backup s_audit; do
            [[ -z "$s_name" ]] && continue
            s_hosts="${s_hosts:-ALL}"
            s_veto="${s_veto:-NONE}"
            s_recycle="${s_recycle:-no}"
            s_retention="${s_retention:-0}"
            s_av="${s_av:-no}"
            s_quota="${s_quota:-0}"
            s_backup="${s_backup:-no}"
            s_audit="${s_audit:-no}"
            exists="есть"
            [[ -d "$s_path" ]] || exists="ПАПКА НЕ НАЙДЕНА"
            recycle_count="0"
            if [[ "$s_recycle" == "yes" && -d "$s_path/.recycle" ]]; then
                recycle_count="$(find "$s_path/.recycle" -type f 2>/dev/null | wc -l)"
            fi
            quarantine_count="0"
            if [[ "$s_av" == "yes" && -d "$s_path/.quarantine" ]]; then
                quarantine_count="$(find "$s_path/.quarantine" -type f 2>/dev/null | wc -l)"
            fi
            last_backup="0"
            if [[ "$s_backup" == "yes" && -n "$backup_dest" ]]; then
                latest_file="$(ls -t "${backup_dest}/${s_name}-"*.tar.gz 2>/dev/null | head -1 || true)"
                [[ -n "$latest_file" ]] && last_backup="$(stat -c %Y "$latest_file" 2>/dev/null || echo 0)"
            fi
            echo "SHARE|${s_name}|${s_path}|${s_group}|${s_writable}|${s_hosts}|${s_veto}|${s_recycle}|${s_retention}|${recycle_count}|${s_av}|${quarantine_count}|${s_quota}|${s_backup}|${last_backup}|${s_audit}|${exists}"
        done < "$SHARES_DB"
    fi
    ;;

  list_users)
    echo "пользователи системы (uid >= 1000) и их доступ к шаре:" >&2
    members="$(getent group "$SHAREGROUP" 2>/dev/null | cut -d: -f4 || true)"
    awk -F: '$3>=1000 && $3<60000 {print $1}' /etc/passwd | sort | while read -r u; do
        if echo ",$members," | grep -q ",$u,"; then
            echo "on|$u"
        else
            echo "off|$u"
        fi
    done
    ;;

  active_connections)
    # Полный вывод smbstatus: кто подключён, с какого IP, к какой шаре.
    # Выполняется от root (через sudo), поэтому видит все сессии, а не только свои.
    if ! command -v smbstatus &>/dev/null; then
        echo "ERROR: smbstatus не найден (обычно идёт в пакете samba-common-bin)" >&2
        exit 1
    fi
    smbstatus
    ;;

  disk_usage)
    # Для каждой шары: сколько занято именно этой шарой (du) и сколько
    # свободно на разделе, где она лежит (df). Это два разных числа —
    # "занято шарой" не равно "занято на разделе", если на разделе есть
    # что-то ещё кроме шар.
    ensure_db
    if [[ ! -s "$SHARES_DB" ]]; then
        echo "  (шар пока нет)"
    else
        while IFS='|' read -r s_name s_path s_group s_writable s_hosts s_veto s_recycle s_retention s_av s_quota s_backup s_audit; do
            [[ -z "$s_name" ]] && continue
            s_quota="${s_quota:-0}"
            if [[ ! -d "$s_path" ]]; then
                echo "DISK|${s_name}|0|0|0|0|${s_quota}|ПАПКА НЕ НАЙДЕНА"
                continue
            fi
            used="$(du -sb "$s_path" 2>/dev/null | awk '{print $1}')"
            used="${used:-0}"
            df_line="$(df -B1 --output=size,avail,pcent "$s_path" 2>/dev/null | tail -1)"
            fs_size="$(echo "$df_line" | awk '{print $1}')"
            fs_avail="$(echo "$df_line" | awk '{print $2}')"
            fs_pct="$(echo "$df_line" | awk '{print $3}' | tr -d '%')"
            echo "DISK|${s_name}|${used}|${fs_size:-0}|${fs_avail:-0}|${fs_pct:-0}|${s_quota}|есть"
        done < "$SHARES_DB"
    fi
    ;;

  list_block_devices)
    # Список дисков и разделов: путь, размер, ФС, куда смонтирован, модель.
    # Только чтение — ничего не меняет. PATH (а не NAME) используется
    # намеренно: для LVM/mapper устройств NAME даёт "vg-lv", а реальный путь
    # для монтирования — /dev/mapper/vg-lv, и только колонка PATH даёт его
    # правильно для всех типов устройств сразу.
    if ! command -v lsblk &>/dev/null; then
        echo "ERROR: lsblk не найден (обычно есть из коробки на любом Linux)" >&2
        exit 1
    fi
    lsblk -P -o PATH,SIZE,FSTYPE,MOUNTPOINT,TYPE,MODEL 2>/dev/null | while IFS= read -r line; do
        dpath="$(echo "$line" | grep -oP '(?<=PATH=")[^"]*')"
        size="$(echo "$line" | grep -oP '(?<=SIZE=")[^"]*')"
        fstype="$(echo "$line" | grep -oP '(?<=FSTYPE=")[^"]*')"
        mountpoint="$(echo "$line" | grep -oP '(?<=MOUNTPOINT=")[^"]*')"
        dtype="$(echo "$line" | grep -oP '(?<=TYPE=")[^"]*')"
        model="$(echo "$line" | grep -oP '(?<=MODEL=")[^"]*')"
        [[ "$dtype" != "disk" && "$dtype" != "part" && "$dtype" != "lvm" && "$dtype" != "loop" ]] && continue
        model_b64="$(printf '%s' "$model" | base64 -w0)"
        mount_b64="$(printf '%s' "$mountpoint" | base64 -w0)"
        echo "BLOCKDEV|${dpath}|${size}|${fstype:-none}|${mount_b64}|${dtype}|${model_b64}"
    done
    ;;

  disk_smart_summary)
    # Быстрая сводка здоровья по каждому физическому диску: PASSED/FAILED + температура.
    if ! command -v smartctl &>/dev/null; then
        echo "ERROR: smartctl не найден — установи пакет smartmontools" >&2
        exit 1
    fi
    lsblk -P -o PATH,TYPE 2>/dev/null | grep 'TYPE="disk"' | while IFS= read -r line; do
        dpath="$(echo "$line" | grep -oP '(?<=PATH=")[^"]*')"
        [[ -z "$dpath" ]] && continue
        smart_out="$(smartctl -H -A "$dpath" 2>/dev/null)"
        if [[ -z "$smart_out" ]]; then
            echo "SMART|${dpath}|UNSUPPORTED|0"
            continue
        fi
        health="UNKNOWN"
        echo "$smart_out" | grep -qi "PASSED" && health="PASSED"
        echo "$smart_out" | grep -qi "FAILED" && health="FAILED"
        temp="$(echo "$smart_out" | grep -i "Temperature_Celsius\|Temperature:" | grep -oP '\d+' | head -1)"
        echo "SMART|${dpath}|${health}|${temp:-0}"
    done
    ;;

  disk_smart_details)
    # Использование: disk_smart_details <device>
    # Полный вывод smartctl -a для конкретного диска (сырой текст).
    device="${2:-}"
    validate_device "$device"
    if ! command -v smartctl &>/dev/null; then
        echo "ERROR: smartctl не найден — установи пакет smartmontools" >&2
        exit 1
    fi
    smartctl -a "$device" 2>&1
    ;;

  list_directories)
    # Использование: list_directories <path>
    # Только чтение: список ПОДПАПОК внутри указанного пути — для браузера
    # папок в форме создания шары (чтобы новичок не гадал путь вслепую,
    # а выбирал мышкой из того, что реально есть на сервере).
    path="${2:-/}"
    [[ -z "$path" ]] && path="/"

    if [[ "$path" != "/" ]]; then
        if [[ ! "$path" =~ $SHAREPATH_RE ]]; then
            echo "ERROR: некорректный путь" >&2
            exit 1
        fi
        if [[ "$path" == *".."* ]]; then
            echo "ERROR: путь не может содержать '..'" >&2
            exit 1
        fi
    fi
    if [[ ! -d "$path" ]]; then
        echo "ERROR: папка '$path' не существует" >&2
        exit 1
    fi

    find "$path" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | while read -r d; do
        name_b64="$(printf '%s' "$(basename "$d")" | base64 -w0)"
        echo "DIR|${name_b64}"
    done
    ;;

  get_notify_config)
    # Читает текущие настройки уведомлений (для отображения в панели).
    # Значения гоняются в base64, чтобы спецсимволы в токене/адресе не
    # ломали протокол '|'.
    NOTIFY_CONF_PATH="/etc/sambapanel/notify.conf"
    TELEGRAM_BOT_TOKEN=""
    TELEGRAM_CHAT_ID=""
    NOTIFY_EMAIL=""
    if [[ -f "$NOTIFY_CONF_PATH" ]]; then
        # shellcheck source=/dev/null
        source "$NOTIFY_CONF_PATH"
    fi
    token_b64="$(printf '%s' "${TELEGRAM_BOT_TOKEN:-}" | base64 -w0)"
    chatid_b64="$(printf '%s' "${TELEGRAM_CHAT_ID:-}" | base64 -w0)"
    email_b64="$(printf '%s' "${NOTIFY_EMAIL:-}" | base64 -w0)"
    echo "NOTIFYCONF|${token_b64}|${chatid_b64}|${email_b64}"
    ;;

  set_notify_config)
    # Использование: set_notify_config <bot_token_b64> <chat_id_b64> <email_b64>
    # Любое из полей можно оставить пустым (пустая база64 строка) — тогда
    # соответствующий канал уведомлений просто не настроен.
    NOTIFY_CONF_PATH="/etc/sambapanel/notify.conf"
    token_b64="${2:-}"; chatid_b64="${3:-}"; email_b64="${4:-}"

    token="$(printf '%s' "$token_b64" | base64 -d 2>/dev/null || true)"
    chatid="$(printf '%s' "$chatid_b64" | base64 -d 2>/dev/null || true)"
    email="$(printf '%s' "$email_b64" | base64 -d 2>/dev/null || true)"

    if [[ -n "$token" && ! "$token" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]]; then
        echo "ERROR: токен Telegram-бота выглядит некорректно (обычно вида 123456789:AAExampleToken...)" >&2
        exit 1
    fi
    if [[ -n "$chatid" && ! "$chatid" =~ ^-?[0-9]+$ ]]; then
        echo "ERROR: chat_id должен быть числом (может быть отрицательным — это ID группы)" >&2
        exit 1
    fi
    if [[ -n "$email" && ! "$email" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; then
        echo "ERROR: email выглядит некорректно" >&2
        exit 1
    fi

    mkdir -p /etc/sambapanel
    cat > "$NOTIFY_CONF_PATH" <<EOF
TELEGRAM_BOT_TOKEN="${token}"
TELEGRAM_CHAT_ID="${chatid}"
NOTIFY_EMAIL="${email}"
EOF
    chmod 640 "$NOTIFY_CONF_PATH"
    chown root:root "$NOTIFY_CONF_PATH"

    extra=""
    [[ -n "$token" && -n "$chatid" ]] && extra="$extra Telegram настроен."
    [[ -n "$email" ]] && extra="$extra почта настроена ($email)."
    [[ -z "$extra" ]] && extra=" оба канала пустые — уведомления отправляться не будут (это ок, если так и задумано)."
    log "OK: настройки уведомлений сохранены.$extra"
    ;;

  test_notify)
    # Прогоняет реальную тестовую отправку прямо сейчас, без ожидания
    # настоящего падения сервиса.
    if [[ ! -x /usr/local/sbin/samba-notify-failure.sh ]]; then
        echo "ERROR: /usr/local/sbin/samba-notify-failure.sh не установлен (переустанови панель через install.sh)" >&2
        exit 1
    fi
    result="$(/usr/local/sbin/samba-notify-failure.sh "тестовое-уведомление-из-панели" 2>&1)"
    echo "$result" | grep -v "^STATUS|" || true
    if echo "$result" | grep -q "^STATUS|SENT|"; then
        echo "OK: тестовое уведомление отправлено — проверь Telegram/почту"
    else
        echo "ERROR: уведомление НЕ отправлено — проверь, что хотя бы один канал заполнен и данные верные" >&2
        exit 1
    fi
    ;;

  ad_status)
    # Показывает, настроена ли AD-интеграция и присоединён ли сервер к домену.
    if grep -q "$AD_MARKER_BEGIN" "$SMB_CONF" 2>/dev/null; then
        configured="yes"
        wg="$(awk -F'=' '/^[[:space:]]*workgroup[[:space:]]*=/{gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit}' "$SMB_CONF")"
        rl="$(awk -F'=' '/^[[:space:]]*realm[[:space:]]*=/{gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit}' "$SMB_CONF")"
    else
        configured="no"; wg=""; rl=""
    fi

    joined="no"
    if [[ "$configured" == "yes" ]] && command -v net &>/dev/null; then
        if net ads testjoin 2>&1 | grep -qi "join is OK"; then
            joined="yes"
        fi
    fi

    wg_b64="$(printf '%s' "$wg" | base64 -w0)"
    rl_b64="$(printf '%s' "$rl" | base64 -w0)"
    echo "ADSTATUS|${configured}|${joined}|${wg_b64}|${rl_b64}"
    ;;

  ad_join)
    # Использование: ad_join <workgroup> <realm> <idmap_range_start> <idmap_range_end> <admin_user>
    # Пароль администратора домена читается из stdin (не через argv — не
    # должен светиться в `ps aux`).
    workgroup="${2:-}"; realm="${3:-}"; range_start="${4:-10000}"; range_end="${5:-999999}"; admin_user="${6:-}"

    if [[ ! "$workgroup" =~ $WORKGROUP_RE ]]; then
        echo "ERROR: некорректное имя домена (workgroup/NetBIOS) — только буквы/цифры/дефис, до 15 символов" >&2
        exit 1
    fi
    if [[ ! "$realm" =~ $REALM_RE ]]; then
        echo "ERROR: некорректный realm (обычно вида EXAMPLE.COM)" >&2
        exit 1
    fi
    if [[ ! "$range_start" =~ ^[0-9]+$ || ! "$range_end" =~ ^[0-9]+$ || "$range_start" -ge "$range_end" ]]; then
        echo "ERROR: диапазон idmap некорректен (начало должно быть меньше конца, оба — числа)" >&2
        exit 1
    fi
    if [[ -z "$admin_user" ]]; then
        echo "ERROR: не указан администратор домена для присоединения" >&2
        exit 1
    fi

    read -r admin_password

    if grep -q "$AD_MARKER_BEGIN" "$SMB_CONF" 2>/dev/null; then
        echo "ERROR: AD-интеграция уже настроена в smb.conf — сначала 'выйти из домена', если нужно перенастроить с нуля" >&2
        exit 1
    fi

    log "устанавливаю пакеты winbind/libnss-winbind/libpam-winbind/krb5-user (если ещё не установлены)"
    if ! dpkg -s winbind &>/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq winbind libnss-winbind libpam-winbind krb5-user >/dev/null 2>&1 || {
            echo "ERROR: не удалось установить пакеты для AD — проверь интернет/apt руками" >&2
            exit 1
        }
    fi

    log "настраиваю /etc/krb5.conf"
    if [[ -f /etc/krb5.conf && ! -f /etc/krb5.conf.pre-ad-bak ]]; then
        cp /etc/krb5.conf /etc/krb5.conf.pre-ad-bak
    fi
    cat > /etc/krb5.conf <<EOF
[libdefaults]
    default_realm = ${realm^^}
    dns_lookup_realm = false
    dns_lookup_kdc = true
EOF

    log "добавляю winbind в /etc/nsswitch.conf (если ещё не добавлен)"
    if ! grep -q "^passwd:.*winbind" /etc/nsswitch.conf; then
        sed -i 's/^passwd:\(.*\)$/passwd:\1 winbind/' /etc/nsswitch.conf
    fi
    if ! grep -q "^group:.*winbind" /etc/nsswitch.conf; then
        sed -i 's/^group:\(.*\)$/group:\1 winbind/' /etc/nsswitch.conf
    fi

    log "добавляю AD-конфигурацию в /etc/samba/smb.conf (секция [global])"
    cp "$SMB_CONF" "${SMB_CONF}.pre-ad-bak"
    ad_block_file="$(mktemp)"
    cat > "$ad_block_file" <<EOF
$AD_MARKER_BEGIN
   workgroup = ${workgroup}
   realm = ${realm^^}
   security = ads
   idmap config * : backend = tdb
   idmap config * : range = 3000-9999
   idmap config ${workgroup} : backend = rid
   idmap config ${workgroup} : range = ${range_start}-${range_end}
   winbind use default domain = yes
   winbind offline logon = yes
   winbind refresh tickets = yes
   winbind enum users = no
   winbind enum groups = no
   template shell = /bin/bash
   template homedir = /home/%D/%U
   kerberos method = secrets and keytab
$AD_MARKER_END
EOF
    # ВАЖНО: вставляем в КОНЕЦ секции [global], а не в начало. Стандартный
    # smb.conf на Ubuntu уже содержит свою строку "workgroup = WORKGROUP"
    # внутри [global] — Samba при повторении параметра берёт ПОСЛЕДНЕЕ
    # значение в секции. Если вставить наш блок в начало (сразу после
    # заголовка [global]), собственная штатная строка "workgroup = WORKGROUP",
    # стоящая ниже, окажется последней и победит нашу — сервер продолжит
    # считать себя в домене "WORKGROUP", а не в реальном домене. Поэтому
    # вставляем перед СЛЕДУЮЩИМ заголовком секции (или в конец файла, если
    # [global] — последняя секция), чтобы наши значения были последними.
    smb_conf_tmp="$(mktemp)"
    awk -v block_file="$ad_block_file" '
        BEGIN { in_global = 0; inserted = 0 }
        {
            if ($0 ~ /^\[global\]/) { in_global = 1; print; next }
            if (in_global && $0 ~ /^\[/ && !inserted) {
                while ((getline line < block_file) > 0) print line
                close(block_file)
                inserted = 1
                in_global = 0
            }
            print
        }
        END {
            if (in_global && !inserted) {
                while ((getline line < block_file) > 0) print line
                close(block_file)
            }
        }
    ' "$SMB_CONF" > "$smb_conf_tmp"
    mv "$smb_conf_tmp" "$SMB_CONF"
    rm -f "$ad_block_file"

    if ! testparm -s "$SMB_CONF" &>/dev/null; then
        echo "ERROR: конфиг после добавления AD-блока не прошёл testparm — откатываю smb.conf" >&2
        cp "${SMB_CONF}.pre-ad-bak" "$SMB_CONF"
        exit 1
    fi

    log "выполняю net ads join -U $admin_user (может занять несколько секунд)"
    join_output="$(printf '%s\n' "$admin_password" | net ads join -U "$admin_user" 2>&1)" || true
    echo "$join_output"

    # Не доверяем ТОЛЬКО тексту вывода net ads join — Samba может напечатать
    # обнадёживающую строку про создание учётки в AD, а затем всё равно
    # упасть на более позднем шаге (например, получении machine credentials
    # из-за нехватки прав) — именно так уже случалось на практике: вывод
    # содержал слово "Joined", а реального join не произошло. Поэтому
    # финальная проверка — обязательно ЖИВОЙ net ads testjoin, а не парсинг текста.
    sleep 1
    testjoin_output="$(net ads testjoin 2>&1)" || true
    if ! echo "$testjoin_output" | grep -qi "join is OK"; then
        echo "$testjoin_output" >&2
        echo "ERROR: net ads join выполнился, но testjoin НЕ подтверждает реальное присоединение — откатываю smb.conf. Обычно причина — недостаточно прав у администратора домена на создание/изменение компьютерного объекта, рассинхронизация времени с контроллером домена, или проблемы с DNS" >&2
        cp "${SMB_CONF}.pre-ad-bak" "$SMB_CONF"
        exit 1
    fi

    systemctl restart winbind 2>/dev/null || systemctl restart winbind.service 2>/dev/null || true
    systemctl restart smbd 2>/dev/null || true

    log "OK: сервер присоединён к домену ${realm^^} (workgroup ${workgroup}), testjoin подтверждён"
    ;;

  ad_leave)
    # Использование: ad_leave <admin_user>
    # Пароль администратора домена читается из stdin.
    admin_user="${2:-}"
    if [[ -z "$admin_user" ]]; then
        echo "ERROR: не указан администратор домена" >&2
        exit 1
    fi
    read -r admin_password

    if command -v net &>/dev/null; then
        leave_output="$(printf '%s\n' "$admin_password" | net ads leave -U "$admin_user" 2>&1)" || true
        echo "$leave_output"
        if ! echo "$leave_output" | grep -qi "Left the domain\|Successfully"; then
            log "предупреждение: net ads leave вернул ошибку (см. вывод выше) — компьютерный объект в AD, возможно, придётся удалить вручную на контроллере домена. Но локальную конфигурацию (smb.conf) всё равно уберу ниже, чтобы сервер точно вернулся в обычный режим"
        fi
    fi

    if grep -q "$AD_MARKER_BEGIN" "$SMB_CONF" 2>/dev/null; then
        sed -i "/$AD_MARKER_BEGIN/,/$AD_MARKER_END/d" "$SMB_CONF"
        log "AD-блок убран из smb.conf"
    fi

    if ! testparm -s "$SMB_CONF" &>/dev/null; then
        echo "ERROR: конфиг после удаления AD-блока не прошёл testparm — проверь $SMB_CONF руками" >&2
        exit 1
    fi

    systemctl restart smbd 2>/dev/null || true

    log "OK: сервер вышел из домена. ВНИМАНИЕ: /etc/krb5.conf и запись 'winbind' в /etc/nsswitch.conf НЕ откатываются автоматически (безопаснее оставить как есть, чем агрессивно чистить системные файлы) — если нужно убрать полностью, сделай это руками"
    ;;

  ad_test)
    # Проверка живого статуса присоединения (без изменений).
    if ! command -v wbinfo &>/dev/null; then
        echo "ERROR: wbinfo не найден — winbind не установлен (сервер ещё не присоединялся к AD)" >&2
        exit 1
    fi
    echo "--- net ads testjoin ---"
    net ads testjoin 2>&1 || true
    echo "--- wbinfo -t (проверка доверенного секрета) ---"
    wbinfo -t 2>&1 || true
    echo "--- wbinfo -p (проверка связи с DC) ---"
    wbinfo -p 2>&1 || true
    ;;

  ad_list_users)
    # Список пользователей AD (первые 200) — для помощи при настройке доступа к шарам.
    if ! command -v wbinfo &>/dev/null; then
        echo "ERROR: winbind не установлен" >&2
        exit 1
    fi
    wbinfo -u 2>/dev/null | head -200 | while read -r u; do
        u_b64="$(printf '%s' "$u" | base64 -w0)"
        echo "ADUSER|${u_b64}"
    done || true
    ;;

  ad_list_groups)
    # Список групп AD (первые 200) — для выбора группы доступа к шаре.
    if ! command -v wbinfo &>/dev/null; then
        echo "ERROR: winbind не установлен" >&2
        exit 1
    fi
    wbinfo -g 2>/dev/null | head -200 | while read -r g; do
        g_b64="$(printf '%s' "$g" | base64 -w0)"
        echo "ADGROUP|${g_b64}"
    done || true
    ;;

  check_update)
    # Только чтение — сверяет текущую версию с последним релизом на GitHub,
    # ничего не скачивает и не меняет.
    current_version="неизвестно"
    [[ -f "$VERSION_FILE" ]] && current_version="$(cat "$VERSION_FILE" 2>/dev/null | tr -d '[:space:]')"
    [[ -z "$current_version" ]] && current_version="неизвестно"

    if ! command -v curl &>/dev/null; then
        echo "ERROR: curl не найден — не могу проверить обновления" >&2
        exit 1
    fi

    api_response="$(curl -s -m 15 "https://api.github.com/repos/${UPDATE_REPO}/releases/latest" 2>/dev/null || true)"
    if [[ -z "$api_response" ]]; then
        echo "ERROR: не удалось связаться с GitHub API (нет интернета на сервере?)" >&2
        exit 1
    fi

    # GitHub отдаёт {"message": "..."} и в случае rate-limit, и если релизов
    # ещё вообще нет ни одного — оба случая нужно показать по-человечески,
    # а не как загадочную ошибку парсинга.
    if echo "$api_response" | grep -q '"message"[[:space:]]*:'; then
        msg="$(echo "$api_response" | grep -oP '"message"\s*:\s*"\K[^"]+' | head -1)"
        echo "UPDATECHECK|error|${current_version}||${msg:-неизвестная ошибка GitHub API}"
        exit 0
    fi

    latest_tag="$(echo "$api_response" | grep -oP '"tag_name"\s*:\s*"\K[^"]+' | head -1)"
    release_url="$(echo "$api_response" | grep -oP '"html_url"\s*:\s*"\K[^"]+' | head -1)"

    if [[ -z "$latest_tag" ]]; then
        echo "ERROR: не удалось разобрать ответ GitHub API" >&2
        exit 1
    fi

    if [[ "$latest_tag" == "$current_version" ]]; then
        echo "UPDATECHECK|uptodate|${current_version}|${latest_tag}|${release_url}"
    else
        echo "UPDATECHECK|available|${current_version}|${latest_tag}|${release_url}"
    fi
    ;;

  apply_update)
    # Использование: apply_update <tag>
    # Скачивает конкретный релиз с GitHub и запускает ЕГО СОБСТВЕННЫЙ
    # install.sh — тот же самый идемпотентный установщик, что и при первой
    # установке. Осознанный выбор: не копируем файлы вручную (отдельный,
    # непроверенный путь для апдейта), а переиспользуем install.sh, который
    # уже полностью отлажен и умеет безопасно накатываться поверх существующей
    # установки (проверяет наличие пакетов/юнитов/паролей перед созданием
    # заново, не трогает шары и локальных пользователей).
    tag="${2:-}"
    if [[ -z "$tag" || ! "$tag" =~ $TAG_RE ]]; then
        echo "ERROR: некорректный номер версии для обновления" >&2
        exit 1
    fi

    tmp_dir="$(mktemp -d)"
    archive_url="https://github.com/${UPDATE_REPO}/archive/refs/tags/${tag}.tar.gz"

    log "скачиваю релиз $tag с GitHub"
    if ! curl -sfL -m 60 -o "$tmp_dir/release.tar.gz" "$archive_url"; then
        echo "ERROR: не удалось скачать $archive_url — убедись, что релиз '$tag' реально существует в репозитории (https://github.com/${UPDATE_REPO}/releases)" >&2
        rm -rf "$tmp_dir"
        exit 1
    fi
    if [[ ! -s "$tmp_dir/release.tar.gz" ]]; then
        echo "ERROR: скачанный файл пустой — убедись, что тег '$tag' реально существует в репозитории" >&2
        rm -rf "$tmp_dir"
        exit 1
    fi

    log "распаковываю"
    if ! tar xzf "$tmp_dir/release.tar.gz" -C "$tmp_dir" 2>/dev/null; then
        echo "ERROR: не удалось распаковать скачанный архив" >&2
        rm -rf "$tmp_dir"
        exit 1
    fi

    extracted_dir="$(find "$tmp_dir" -mindepth 1 -maxdepth 1 -type d | head -1)"
    if [[ -z "$extracted_dir" || ! -f "$extracted_dir/install.sh" ]]; then
        echo "ERROR: в скачанном релизе не найден install.sh — структура релиза не соответствует ожидаемой" >&2
        rm -rf "$tmp_dir"
        exit 1
    fi

    # сохраняем текущий пароль панели, чтобы install.sh не сгенерировал новый
    current_password=""
    if [[ -f /etc/systemd/system/sambapanel.service ]]; then
        current_password="$(grep -oP '(?<=SAMBAPANEL_PASSWORD=)[^"]*' /etc/systemd/system/sambapanel.service 2>/dev/null || true)"
    fi

    log "запускаю install.sh из версии $tag (неинтерактивно, текущий пароль панели сохраняется)"
    chmod +x "$extracted_dir/install.sh"
    ( cd "$extracted_dir" && SAMBAPANEL_PASSWORD="$current_password" bash ./install.sh < /dev/null 2>&1 )
    install_exit=$?

    if [[ "$install_exit" -ne 0 ]]; then
        rm -rf "$tmp_dir"
        echo "ERROR: install.sh завершился с ошибкой (код $install_exit) — панель могла обновиться не до конца, смотри вывод выше" >&2
        exit 1
    fi

    mkdir -p /opt/sambapanel
    echo "$tag" > "$VERSION_FILE" 2>/dev/null || true
    rm -rf "$tmp_dir"

    log "OK: панель обновлена до версии $tag"
    ;;

  get_smtp_config)
    # Читает текущие настройки SMTP (/etc/msmtprc) для отображения в панели.
    # Пароль НИКОГДА не возвращается обратно в браузер — только флаг
    # "задан/не задан" (has_password), это стандартная практика для секретов.
    MSMTPRC="/etc/msmtprc"
    smtp_host=""; smtp_port="587"; smtp_from=""; smtp_user=""; has_password="no"
    if [[ -f "$MSMTPRC" ]]; then
        smtp_host="$(awk '$1=="host"{print $2; exit}' "$MSMTPRC" 2>/dev/null || true)"
        smtp_port="$(awk '$1=="port"{print $2; exit}' "$MSMTPRC" 2>/dev/null || true)"
        smtp_from="$(awk '$1=="from"{print $2; exit}' "$MSMTPRC" 2>/dev/null || true)"
        smtp_user="$(awk '$1=="user"{print $2; exit}' "$MSMTPRC" 2>/dev/null || true)"
        if awk '$1=="password"{f=1} END{exit !f}' "$MSMTPRC" 2>/dev/null; then
            has_password="yes"
        fi
    fi
    host_b64="$(printf '%s' "$smtp_host" | base64 -w0)"
    port_b64="$(printf '%s' "${smtp_port:-587}" | base64 -w0)"
    from_b64="$(printf '%s' "$smtp_from" | base64 -w0)"
    user_b64="$(printf '%s' "$smtp_user" | base64 -w0)"
    echo "SMTPCONF|${host_b64}|${port_b64}|${from_b64}|${user_b64}|${has_password}"
    ;;

  set_smtp_config)
    # Использование: set_smtp_config <host_b64> <port_b64> <from_b64> <user_b64> <password_b64>
    # password_b64 может быть пустым — тогда СУЩЕСТВУЮЩИЙ сохранённый пароль
    # (если есть) остаётся как есть, а не стирается пустотой. Это позволяет
    # поправить, например, только адрес отправителя, не вводя пароль заново.
    MSMTPRC="/etc/msmtprc"
    host_b64="${2:-}"; port_b64="${3:-}"; from_b64="${4:-}"; user_b64="${5:-}"; password_b64="${6:-}"

    host="$(printf '%s' "$host_b64" | base64 -d 2>/dev/null || true)"
    port="$(printf '%s' "$port_b64" | base64 -d 2>/dev/null || true)"
    from_addr="$(printf '%s' "$from_b64" | base64 -d 2>/dev/null || true)"
    user="$(printf '%s' "$user_b64" | base64 -d 2>/dev/null || true)"
    password="$(printf '%s' "$password_b64" | base64 -d 2>/dev/null || true)"

    if [[ -z "$host" ]]; then
        echo "ERROR: не указан SMTP-сервер (host)" >&2
        exit 1
    fi
    port="${port:-587}"
    if [[ ! "$port" =~ ^[0-9]{1,5}$ ]]; then
        echo "ERROR: порт должен быть числом" >&2
        exit 1
    fi
    if [[ -z "$from_addr" || ! "$from_addr" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; then
        echo "ERROR: адрес отправителя (from) должен быть похож на email" >&2
        exit 1
    fi
    user="${user:-$from_addr}"

    if [[ -z "$password" && -f "$MSMTPRC" ]]; then
        password="$(awk '$1=="password"{print $2; exit}' "$MSMTPRC" 2>/dev/null || true)"
    fi
    if [[ -z "$password" ]]; then
        echo "ERROR: пароль не указан и не найден ранее сохранённый — заполни поле пароля хотя бы один раз" >&2
        exit 1
    fi

    cat > "$MSMTPRC" <<EOF
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        /var/log/msmtp.log

account        default
host           ${host}
port           ${port}
from           ${from_addr}
user           ${user}
password       ${password}
EOF
    # msmtp категорически отказывается работать, если конфиг читаем кем-то
    # кроме владельца, — 600 тут не просто "хорошая практика", а обязательное
    # требование самой программы, иначе она откажется отправлять письма вообще.
    chmod 600 "$MSMTPRC"
    chown root:root "$MSMTPRC"

    log "OK: SMTP-настройки сохранены (${host}:${port}, from=${from_addr})"
    ;;

  test_smtp_send)
    # Использование: test_smtp_send <email_b64>
    # Отправляет реальное тестовое письмо на указанный адрес прямо сейчас.
    email_b64="${2:-}"
    email="$(printf '%s' "$email_b64" | base64 -d 2>/dev/null || true)"

    if [[ -z "$email" ]]; then
        echo "ERROR: не указан адрес для теста" >&2
        exit 1
    fi
    if [[ ! -f /etc/msmtprc ]]; then
        echo "ERROR: SMTP ещё не настроен (нет /etc/msmtprc) — сначала сохрани настройки выше" >&2
        exit 1
    fi
    if ! command -v mail &>/dev/null; then
        echo "ERROR: команда 'mail' не установлена — установи пакет mailutils" >&2
        exit 1
    fi

    if echo "Тестовое письмо от samba-admin panel, отправлено $(date '+%Y-%m-%d %H:%M:%S')" \
        | mail -s "samba-admin panel: тестовое письмо" "$email" 2>&1; then
        echo "OK: письмо отправлено на $email — проверь входящие (и папку спам, для нового отправителя это обычно)"
    else
        echo "ERROR: mail завершился с ошибкой — подробности в /var/log/msmtp.log" >&2
        exit 1
    fi
    ;;

  mount_disk)
    # Использование: mount_disk <device> <mountpoint> <persistent: yes/no>
    # persistent=yes добавляет запись в /etc/fstab по UUID (переживает перезагрузку).
    device="${2:-}"; mountpoint="${3:-}"; persistent="${4:-no}"
    validate_device "$device"
    validate_mount_path "$mountpoint"

    if mount | grep -q "^${device} "; then
        echo "ERROR: устройство '$device' уже смонтировано (см. список дисков)" >&2
        exit 1
    fi
    if mountpoint -q "$mountpoint" 2>/dev/null; then
        echo "ERROR: '$mountpoint' уже является точкой монтирования другого устройства" >&2
        exit 1
    fi

    fstype="$(lsblk -no FSTYPE "$device" 2>/dev/null | head -1)"
    if [[ -z "$fstype" ]]; then
        echo "ERROR: на '$device' не найдено файловой системы — сначала отформатируй его (панель это не делает, см. README)" >&2
        exit 1
    fi

    log "mkdir -p $mountpoint"
    mkdir -p "$mountpoint"

    log "mount $device $mountpoint"
    if ! mount "$device" "$mountpoint"; then
        echo "ERROR: mount завершился с ошибкой — см. вывод выше" >&2
        exit 1
    fi

    if [[ "$persistent" == "yes" ]]; then
        uuid="$(blkid -s UUID -o value "$device" 2>/dev/null)"
        if [[ -z "$uuid" ]]; then
            log "WARNING: не удалось получить UUID устройства — запись в fstab не добавлена, монтирование НЕ переживёт перезагрузку"
        elif grep -q "UUID=$uuid" /etc/fstab 2>/dev/null; then
            log "запись для этого UUID в /etc/fstab уже есть — не дублирую"
        else
            echo "UUID=$uuid $mountpoint $fstype defaults,nofail 0 2" >> /etc/fstab
            log "добавлена запись в /etc/fstab (по UUID $uuid, с nofail — сервер не откажется загружаться, если диск вдруг отсутствует)"
        fi
    fi

    log "OK: '$device' смонтирован в '$mountpoint'$([ "$persistent" == "yes" ] && echo ', переживёт перезагрузку' || echo ', ТОЛЬКО до перезагрузки')"
    ;;

  unmount_disk)
    # Использование: unmount_disk <mountpoint> <remove_fstab: yes/no>
    # Отказывает, если под этой точкой монтирования лежит путь ХОТЯ БЫ одной
    # существующей шары — иначе шара тихо превратится в путь в никуда.
    mountpoint="${2:-}"; remove_fstab="${3:-no}"
    validate_mount_path "$mountpoint"

    if ! mountpoint -q "$mountpoint" 2>/dev/null; then
        echo "ERROR: '$mountpoint' не является точкой монтирования (ничего не смонтировано)" >&2
        exit 1
    fi

    ensure_db
    conflicting=""
    if [[ -s "$SHARES_DB" ]]; then
        while IFS='|' read -r s_name s_path _rest; do
            [[ -z "$s_name" ]] && continue
            if [[ "$s_path" == "$mountpoint" || "$s_path" == "$mountpoint"/* ]]; then
                conflicting="${conflicting:+$conflicting, }$s_name"
            fi
        done < "$SHARES_DB"
    fi
    if [[ -n "$conflicting" ]]; then
        echo "ERROR: под этой точкой монтирования есть активные шары ($conflicting) — сначала убери их (кнопка «убрать шару») или перенеси на другой путь, иначе шара превратится в путь в никуда" >&2
        exit 1
    fi

    log "umount $mountpoint"
    if ! umount "$mountpoint"; then
        echo "ERROR: umount завершился с ошибкой (диск занят? lsof/fuser покажет кем) — не смонтирован" >&2
        exit 1
    fi

    if [[ "$remove_fstab" == "yes" ]]; then
        if grep -q " $mountpoint " /etc/fstab 2>/dev/null; then
            sed -i "\\# $mountpoint #d" /etc/fstab
            log "запись для '$mountpoint' убрана из /etc/fstab"
        fi
    fi

    log "OK: '$mountpoint' отмонтирован"
    ;;

  list_iso_files)
    # Использование: list_iso_files <path>
    # Только чтение: ищет .iso файлы внутри указанной папки (не рекурсивно
    # глубже пары уровней — иначе поиск по всему /srv может быть небыстрым).
    path="${2:-/srv}"
    [[ -z "$path" ]] && path="/srv"

    if [[ "$path" != "/" ]]; then
        if [[ ! "$path" =~ $SHAREPATH_RE ]]; then
            echo "ERROR: некорректный путь" >&2
            exit 1
        fi
        if [[ "$path" == *".."* ]]; then
            echo "ERROR: путь не может содержать '..'" >&2
            exit 1
        fi
    fi
    if [[ ! -d "$path" ]]; then
        echo "ERROR: папка '$path' не существует" >&2
        exit 1
    fi

    find "$path" -maxdepth 3 -iname "*.iso" -type f 2>/dev/null | sort | while read -r f; do
        f_b64="$(printf '%s' "$f" | base64 -w0)"
        size="$(stat -c %s "$f" 2>/dev/null || echo 0)"
        echo "ISOFILE|${f_b64}|${size}"
    done || true
    ;;

  mount_iso)
    # Использование: mount_iso <iso_path> <mountpoint>
    # ISO-образы монтируются ТОЛЬКО для чтения (loop-устройство) — это не
    # ограничение панели, а физическое свойство формата ISO9660, в него
    # физически нельзя писать после создания образа.
    iso_path="${2:-}"; mountpoint="${3:-}"

    if [[ -z "$iso_path" || ! -f "$iso_path" ]]; then
        echo "ERROR: файл '$iso_path' не найден" >&2
        exit 1
    fi
    if [[ "${iso_path,,}" != *.iso ]]; then
        echo "ERROR: файл должен иметь расширение .iso" >&2
        exit 1
    fi
    if [[ "$iso_path" == *".."* ]]; then
        echo "ERROR: путь не может содержать '..'" >&2
        exit 1
    fi
    validate_mount_path "$mountpoint"

    if mountpoint -q "$mountpoint" 2>/dev/null; then
        echo "ERROR: '$mountpoint' уже занята другим монтированием" >&2
        exit 1
    fi

    log "mkdir -p $mountpoint"
    mkdir -p "$mountpoint"

    log "mount -o loop,ro $iso_path $mountpoint"
    if ! mount -o loop,ro "$iso_path" "$mountpoint"; then
        echo "ERROR: не удалось смонтировать ISO — проверь, что файл не повреждён и это реально образ ISO9660" >&2
        exit 1
    fi

    log "OK: ISO '$iso_path' смонтирован в '$mountpoint' (только чтение)"
    ;;

  *)
    echo "ERROR: неизвестная команда '$cmd'" >&2
    echo "Доступные команды: create_user, remove_user, set_samba_password, toggle_share_access, list_users," >&2
    echo "                   create_share, remove_share, set_share_writable, set_share_hosts, set_share_veto," >&2
    echo "                   set_share_recycle, empty_recycle_bin, list_recycle_bin, restore_recycle_file," >&2
    echo "                   set_share_antivirus, empty_quarantine, list_shares, set_share_group," >&2
    echo "                   set_share_quota, set_share_backup, set_share_full_audit, file_audit_log," >&2
    echo "                   active_connections, disk_usage, list_block_devices, disk_smart_summary," >&2
    echo "                   disk_smart_details, mount_disk, unmount_disk, list_directories," >&2
    echo "                   list_iso_files, mount_iso (группа шары также может быть 'GUEST' — без пароля)," >&2
    echo "                   get_notify_config, set_notify_config, test_notify," >&2
    echo "                   get_smtp_config, set_smtp_config, test_smtp_send," >&2
    echo "                   ad_status, ad_join, ad_leave, ad_test, ad_list_users, ad_list_groups," >&2
    echo "                   check_update, apply_update" >&2
    exit 1
    ;;
esac
