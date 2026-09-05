#!/usr/bin/env bash
#
# samba-notify-failure.sh — отправляет уведомление о падении systemd-юнита.
# Вызывается автоматически через OnFailure=samba-notify@%n.service из
# юнитов сервисов, за которыми следит панель (см. install.sh).
#
# БЕЗ настроенного /etc/sambapanel/notify.conf ничего не отправляет и не
# падает с ошибкой — просто тихо пишет в journal. Это специально: скрипт
# ставится при каждой установке панели независимо от того, настроены ли
# каналы уведомлений, поэтому он не должен ничего ломать, если их ещё нет.

set -uo pipefail

CONF="/etc/sambapanel/notify.conf"
UNIT="${1:-неизвестный сервис}"
HOSTNAME_SHORT="$(hostname -s 2>/dev/null || hostname)"
TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"
MESSAGE="⚠️ [${HOSTNAME_SHORT}] Сервис '${UNIT}' завершился с ошибкой (${TIMESTAMP})"

TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
NOTIFY_EMAIL=""

# shellcheck source=/dev/null
[[ -f "$CONF" ]] && source "$CONF"

sent=0

if [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
    if command -v curl &>/dev/null; then
        if curl -s -f -m 10 "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d chat_id="${TELEGRAM_CHAT_ID}" \
            --data-urlencode "text=${MESSAGE}" >/dev/null 2>&1; then
            sent=1
        fi
    fi
fi

if [[ -n "$NOTIFY_EMAIL" ]]; then
    if command -v mail &>/dev/null; then
        if echo "$MESSAGE" | mail -s "samba-admin panel: ${UNIT} упал" "$NOTIFY_EMAIL" 2>/dev/null; then
            sent=1
        fi
    fi
fi

if [[ "$sent" -eq 0 ]]; then
    # Не настроено (или обе попытки не удались) — не молчим в никуда,
    # хотя бы в journal остаётся видимый след, что сервис падал и что
    # уведомление НЕ ушло (полезно при диагностике "а я думал, придёт сообщение").
    logger -t samba-notify "уведомление НЕ отправлено (проверь /etc/sambapanel/notify.conf): $MESSAGE"
    echo "STATUS|NOT_SENT|ни Telegram, ни почта не настроены или обе попытки завершились ошибкой"
else
    echo "STATUS|SENT|уведомление отправлено хотя бы одним из настроенных каналов"
fi

exit 0
