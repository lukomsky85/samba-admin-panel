#!/usr/bin/env bash
#
# samba-shadow.sh — запускается по таймеру (см. samba-shadow.timer) от root.
# Для каждой шары с включёнными "теневыми копиями" (см. /etc/sambapanel/
# shadow_shares.db) делает снапшот через rsync --link-dest: копия дерева
# файлов внутри самой шары (.snapshots/@GMT-<время>/...), где неизменившиеся
# файлы — обычные хардлинки на предыдущий снапшот (место на диске тратится
# только на реально изменившиеся/новые файлы), затем удаляет снапшоты сверх
# заданного количества хранения.
#
# Формат каталогов (@GMT-%Y.%m.%d-%H.%M.%S) и сама Samba-обвязка
# (vfs objects = shadow_copy2) — в regenerate_conf() внутри
# samba-admin-helper.sh. Отсюда Windows-клиент видит обычные "Volume Shadow
# Copies" и "Восстановить предыдущую версию" в свойствах файла — хотя
# на самом деле под капотом это не настоящий снапшот ФС (шары лежат на
# обычном ext4, не на ZFS/Btrfs), а дерево хардлинков.
#
# Настройки — в /etc/sambapanel/shadow_shares.db, формат: имя_шары|retention

set -uo pipefail
# ВАЖНО: без -e, по тем же причинам, что и в samba-backup.sh — ошибка
# снапшота одной шары не должна останавливать снапшоты остальных.

SHARES_DB="/etc/sambapanel/shares.db"
SHADOW_DB="/etc/sambapanel/shadow_shares.db"
LOG_TAG="samba-shadow"

log() { echo "[$LOG_TAG] $*"; }

if [[ ! -f "$SHADOW_DB" || ! -s "$SHADOW_DB" ]]; then
    log "нет включённых шар с теневыми копиями ($SHADOW_DB пуст или не существует) — выхожу"
    exit 0
fi
if [[ ! -f "$SHARES_DB" ]]; then
    log "нет $SHARES_DB — шар пока нет, выхожу"
    exit 0
fi

ok_count=0
fail_count=0

while IFS='|' read -r name retention; do
    [[ -z "$name" ]] && continue
    retention="${retention:-7}"

    path="$(grep "^${name}|" "$SHARES_DB" 2>/dev/null | head -1 | cut -d'|' -f2)"
    if [[ -z "$path" ]]; then
        log "ERROR: шара '$name' из $SHADOW_DB не найдена в $SHARES_DB (переименована/удалена?), пропускаю"
        fail_count=$((fail_count + 1))
        continue
    fi
    if [[ ! -d "$path" ]]; then
        log "ERROR: шара '$name' — папка '$path' не найдена, пропускаю"
        fail_count=$((fail_count + 1))
        continue
    fi

    snap_root="${path}/.snapshots"
    mkdir -p "$snap_root"

    ts="$(date -u '+%Y.%m.%d-%H.%M.%S')"
    new_snap="${snap_root}/@GMT-${ts}"

    latest="$(ls -1 "$snap_root" 2>/dev/null | grep '^@GMT-' | sort | tail -1 || true)"

    log "шара '$name': снапшот $path -> $new_snap$( [[ -n "$latest" ]] && echo " (инкремент от $latest)" )"

    rsync_args=(-a --delete
        --exclude=.snapshots --exclude=.recycle --exclude=.quarantine)
    if [[ -n "$latest" ]]; then
        rsync_args+=(--link-dest="${snap_root}/${latest}")
    fi

    if rsync "${rsync_args[@]}" "${path}/" "${new_snap}/" 2>"/var/log/sambapanel/shadow-${name}.err"; then
        log "шара '$name': OK, снапшот создан"
        ok_count=$((ok_count + 1))
    else
        rm -rf "${new_snap:?}"
        log "ERROR: шара '$name' — rsync завершился с ошибкой, см. /var/log/sambapanel/shadow-${name}.err"
        fail_count=$((fail_count + 1))
        continue
    fi

    # ротация: оставляем только $retention самых новых снапшотов этой шары
    mapfile -t old_snaps < <(ls -1 "$snap_root" 2>/dev/null | grep '^@GMT-' | sort | head -n -"$retention")
    if [[ "${#old_snaps[@]}" -gt 0 ]]; then
        log "шара '$name': ротация — удаляю ${#old_snaps[@]} старых снапшотов (оставляю $retention)"
        for old in "${old_snaps[@]}"; do
            rm -rf "${snap_root:?}/${old:?}"
        done
    fi
done < "$SHADOW_DB"

log "готово: успешно $ok_count, с ошибкой $fail_count"
[[ "$fail_count" -gt 0 ]] && exit 1
exit 0
