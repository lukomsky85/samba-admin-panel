#!/usr/bin/env bash
#
# samba-restore.sh — восстановление шары из архива, созданного samba-backup.sh.
#
# Использование:
#   sudo ./samba-restore.sh <имя_шары>                    # показать список архивов
#   sudo ./samba-restore.sh <имя_шары> <имя_файла_архива> # восстановить конкретный
#   sudo ./samba-restore.sh <имя_шары> latest             # восстановить самый свежий
#
# Намеренно НЕ доступен как кнопка в веб-панели — это операция с реальным
# риском перезаписать текущие данные, ей место в командной строке с явным
# подтверждением, а не в один клик мышкой (та же логика, что и с отказом
# от форматирования дисков через панель — см. README).

set -euo pipefail

BACKUP_CONF="/etc/sambapanel/backup.conf"
SHARES_DB="/etc/sambapanel/shares.db"

if [[ "$EUID" -ne 0 ]]; then
    echo "запусти через sudo: sudo ./samba-restore.sh ..." >&2
    exit 1
fi

if [[ ! -f "$BACKUP_CONF" ]]; then
    echo "ERROR: $BACKUP_CONF не найден — бэкап на этом сервере не настроен" >&2
    exit 1
fi
# shellcheck source=/dev/null
source "$BACKUP_CONF"

if [[ -z "${BACKUP_DEST:-}" ]]; then
    echo "ERROR: BACKUP_DEST не задан в $BACKUP_CONF" >&2
    exit 1
fi
if [[ ! -d "$BACKUP_DEST" ]]; then
    echo "ERROR: папка бэкапов '$BACKUP_DEST' не существует или не смонтирована" >&2
    exit 1
fi

share_name="${1:-}"
if [[ -z "$share_name" ]]; then
    echo "Использование: $0 <имя_шары> [имя_файла_архива|latest]" >&2
    exit 1
fi

if [[ ! -f "$SHARES_DB" ]] || ! grep -q "^${share_name}|" "$SHARES_DB"; then
    echo "ERROR: шара '$share_name' не найдена в $SHARES_DB (проверь имя)" >&2
    exit 1
fi

share_path="$(grep "^${share_name}|" "$SHARES_DB" | head -1 | cut -d'|' -f2)"

shopt -s nullglob
archives=("${BACKUP_DEST}/${share_name}-"*.tar.gz)
shopt -u nullglob

if [[ "${#archives[@]}" -eq 0 ]]; then
    echo "Архивов для шары '$share_name' в '$BACKUP_DEST' не найдено." >&2
    echo "(бэкап включён для неё в панели? уже успел отработать таймер samba-backup.timer хотя бы раз?)" >&2
    exit 1
fi

archive_arg="${2:-}"

if [[ -z "$archive_arg" ]]; then
    echo "Доступные архивы шары '$share_name' (в $BACKUP_DEST):"
    echo
    for a in "${archives[@]}"; do
        sz="$(du -h "$a" 2>/dev/null | cut -f1)"
        dt="$(date -d "@$(stat -c %Y "$a" 2>/dev/null || echo 0)" '+%Y-%m-%d %H:%M' 2>/dev/null)"
        printf '  %-45s %8s   %s\n' "$(basename "$a")" "${sz:-?}" "${dt:-?}"
    done
    echo
    echo "Восстановить конкретный:  $0 $share_name <имя_файла_из_списка_выше>"
    echo "Восстановить самый свежий: $0 $share_name latest"
    exit 0
fi

if [[ "$archive_arg" == "latest" ]]; then
    archive="$(ls -t "${archives[@]}" | head -1)"
else
    archive="${BACKUP_DEST}/${archive_arg}"
fi

if [[ ! -f "$archive" ]]; then
    echo "ERROR: архив '$archive' не найден" >&2
    exit 1
fi
if [[ ! -d "$share_path" ]]; then
    echo "ERROR: путь шары '$share_path' не существует на диске (шара сломана?)" >&2
    exit 1
fi

echo "Шара:   $share_name"
echo "Путь:   $share_path"
echo "Архив:  $archive"
echo
echo "Содержимое архива (это просто просмотр, ничего ещё не менялось на диске):"
tar tzf "$archive" | head -30
total_count="$(tar tzf "$archive" | wc -l)"
if [[ "$total_count" -gt 30 ]]; then
    echo "  ... и ещё $((total_count - 30)) записей"
fi
echo

echo "ВНИМАНИЕ: восстановление распакует архив ПОВЕРХ текущего содержимого '$share_path'."
echo "Файлы с совпадающими именами будут ПЕРЕЗАПИСАНЫ версией из архива."
echo "Файлы, которых нет в архиве, но есть сейчас в шаре, — НЕ удаляются (это"
echo "наложение содержимого архива, а не полная синхронизация 1:1)."
echo
read -r -p "Продолжить восстановление? Введи 'да' для подтверждения: " confirm
if [[ "${confirm,,}" != "да" ]]; then
    echo "Отменено, ничего не изменено."
    exit 0
fi

echo "Восстанавливаю..."
tar xzf "$archive" -C "$share_path"
echo "OK: архив '$(basename "$archive")' распакован в '$share_path'"
