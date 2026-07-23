#!/usr/bin/env bash
#
# samba-backup.sh — запускается по таймеру (см. systemd unit) от root.
# Делает tar.gz каждой шары с backup=yes в BACKUP_DEST, затем удаляет
# старые архивы этой шары, оставляя только RETAIN_COUNT самых новых.
#
# Настройки — в /etc/sambapanel/backup.conf:
#   BACKUP_DEST="/mnt/backup"   # куда класть архивы (любой смонтированный путь —
#                                 # внешний диск, сетевая папка, облачный mount)
#   RETAIN_COUNT=7               # сколько последних архивов хранить на шару

set -uo pipefail
# ВАЖНО: без -e. Если бэкап одной шары упадёт (например, диск с BACKUP_DEST
# отвалился), это не должно тихо остановить бэкап всех ОСТАЛЬНЫХ шар —
# каждая шара бэкапится независимо, ошибка одной логируется и скрипт идёт дальше.

SHARES_DB="/etc/sambapanel/shares.db"
BACKUP_CONF="/etc/sambapanel/backup.conf"
LOG_TAG="samba-backup"

log() { echo "[$LOG_TAG] $*"; }

if [[ ! -f "$BACKUP_CONF" ]]; then
    log "нет $BACKUP_CONF — бэкап не настроен, выхожу"
    exit 0
fi
source "$BACKUP_CONF"

if [[ -z "${BACKUP_DEST:-}" ]]; then
    log "BACKUP_DEST не задан в $BACKUP_CONF — выхожу"
    exit 0
fi
if [[ ! -d "$BACKUP_DEST" ]]; then
    log "ERROR: папка назначения '$BACKUP_DEST' не существует или не смонтирована — пропускаю все бэкапы в этот раз"
    exit 1
fi

RETAIN_COUNT="${RETAIN_COUNT:-7}"

if [[ ! -f "$SHARES_DB" ]]; then
    log "нет $SHARES_DB — шар пока нет, выхожу"
    exit 0
fi

ok_count=0
fail_count=0

while IFS='|' read -r name path group writable hosts veto recycle retention av quota backup; do
    [[ -z "$name" ]] && continue
    [[ "${backup:-no}" != "yes" ]] && continue

    if [[ ! -d "$path" ]]; then
        log "ERROR: шара '$name' — папка '$path' не найдена, пропускаю"
        fail_count=$((fail_count + 1))
        continue
    fi

    ts="$(date '+%Y%m%d-%H%M%S')"
    archive="${BACKUP_DEST}/${name}-${ts}.tar.gz"
    tmp_archive="${archive}.tmp"

    log "шара '$name': архивирую $path -> $archive"
    # исключаем служебные папки самой панели (корзина, карантин) — бэкапим
    # реальные данные пользователя, а не наш собственный служебный мусор
    if tar czf "$tmp_archive" \
        --exclude="./.recycle" --exclude="./.quarantine" \
        -C "$path" . 2>/var/log/sambapanel/backup-${name}.err; then
        mv "$tmp_archive" "$archive"
        size="$(du -h "$archive" 2>/dev/null | cut -f1)"
        log "шара '$name': OK, архив создан (${size:-?})"
        ok_count=$((ok_count + 1))
    else
        rm -f "$tmp_archive"
        log "ERROR: шара '$name' — tar завершился с ошибкой, см. /var/log/sambapanel/backup-${name}.err"
        fail_count=$((fail_count + 1))
        continue
    fi

    # ротация: оставляем только RETAIN_COUNT самых новых архивов этой шары
    mapfile -t old_archives < <(ls -t "${BACKUP_DEST}/${name}-"*.tar.gz 2>/dev/null | tail -n +$((RETAIN_COUNT + 1)))
    if [[ "${#old_archives[@]}" -gt 0 ]]; then
        log "шара '$name': ротация — удаляю ${#old_archives[@]} старых архивов (оставляю $RETAIN_COUNT)"
        rm -f "${old_archives[@]}"
    fi
done < "$SHARES_DB"

log "готово: успешно $ok_count, с ошибкой $fail_count"
[[ "$fail_count" -gt 0 ]] && exit 1
exit 0
