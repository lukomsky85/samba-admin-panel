#!/usr/bin/env bash
#
# samba-recycle-cleanup.sh — запускается по таймеру (см. systemd unit) от root.
# Проходит по всем шарам из /etc/sambapanel/shares.db и для тех, у кого
# recycle=yes и retention_days>0, удаляет файлы в .recycle старше N дней.
#
# retention_days=0 означает «хранить вечно» — такие шары этот скрипт
# пропускает, их корзину можно очистить только руками через панель
# (кнопка «очистить корзину») или вручную на сервере.

set -euo pipefail

SHARES_DB="/etc/sambapanel/shares.db"
LOG_TAG="samba-recycle-cleanup"

log() { echo "[$LOG_TAG] $*"; }

if [[ ! -f "$SHARES_DB" ]]; then
    log "файл $SHARES_DB не найден, ничего чистить — выхожу"
    exit 0
fi

total_deleted=0

while IFS='|' read -r name path group writable hosts veto recycle retention; do
    [[ -z "$name" ]] && continue
    recycle="${recycle:-no}"
    retention="${retention:-0}"

    [[ "$recycle" != "yes" ]] && continue
    [[ "$retention" == "0" ]] && continue   # хранить вечно — не трогаем

    recycle_dir="${path}/.recycle"
    [[ -d "$recycle_dir" ]] || continue

    count_before="$(find "$recycle_dir" -type f 2>/dev/null | wc -l)"
    # find -mtime +N означает "старше N полных суток"
    find "$recycle_dir" -type f -mtime +"$retention" -delete 2>/dev/null || true
    # подчищаем опустевшие подкаталоги (recycle:keeptree создаёт дерево папок)
    find "$recycle_dir" -mindepth 1 -type d -empty -delete 2>/dev/null || true
    count_after="$(find "$recycle_dir" -type f 2>/dev/null | wc -l)"
    deleted=$(( count_before - count_after ))

    if [[ "$deleted" -gt 0 ]]; then
        log "шара '$name': удалено $deleted файлов старше $retention дней из $recycle_dir"
        total_deleted=$(( total_deleted + deleted ))
    fi
done < "$SHARES_DB"

log "готово, всего удалено файлов: $total_deleted"
