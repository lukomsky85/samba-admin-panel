#!/usr/bin/env bash
#
# samba-panel-monitor.sh — запускается по таймеру (см. systemd unit) от
# root. Проверяет три класса событий, о которых раньше можно было узнать
# только зайдя в панель руками, и шлёт уведомление (Telegram/почта, если
# настроены — см. вкладку "Мониторинг" в панели) только когда СОСТОЯНИЕ
# РЕАЛЬНО ИЗМЕНИЛОСЬ, а не при каждом запуске таймера — иначе при
# продолжающейся проблеме приходило бы одно и то же сообщение каждые 15
# минут бесконечно, что на практике быстро приводит к игнорированию всех
# уведомлений вообще ("опять то же самое").
#
#  1. Карантин антивируса — появился новый файл в .quarantine какой-либо шары
#  2. Превышение мониторинговой квоты шары
#  3. Диск, у которого SMART сообщает FAILED
#
# Состояние между запусками хранится в STATE_DIR — по одному файлу на
# каждую проверяемую сущность, с последним известным значением.

set -uo pipefail
# Без -e: одна неудачная проверка (например, share без .quarantine) не
# должна тихо оборвать весь скрипт для остальных шар/дисков.

SHARES_DB="/etc/sambapanel/shares.db"
STATE_DIR="/var/lib/sambapanel/monitor-state"
NOTIFY_SCRIPT="/usr/local/sbin/samba-notify-failure.sh"
LOG_TAG="samba-panel-monitor"

log() { echo "[$LOG_TAG] $*"; }

mkdir -p "$STATE_DIR"

notify() {
    # $1 — человекочитаемое описание события, уходит в Telegram/почту
    # тем же самым уже проверенным механизмом, что и уведомления о
    # падении сервисов — код там уже умеет молчать, если каналы не
    # настроены, отдельно предусматривать это здесь не нужно.
    if [[ -x "$NOTIFY_SCRIPT" ]]; then
        "$NOTIFY_SCRIPT" "$1" >/dev/null 2>&1 || true
    fi
    log "СОБЫТИЕ: $1"
}

# Возвращает 0, если значение изменилось с прошлого запуска (и обновляет
# сохранённое состояние), 1 — если совпадает с прошлым разом.
state_changed() {
    local key="$1" new_value="$2"
    local state_file="${STATE_DIR}/${key}"
    local old_value=""
    [[ -f "$state_file" ]] && old_value="$(cat "$state_file")"
    echo "$new_value" > "$state_file"
    [[ "$old_value" != "$new_value" ]]
}

if [[ ! -f "$SHARES_DB" ]]; then
    log "нет $SHARES_DB — шар пока нет, проверяю только диски"
fi

# --- 1. Карантин антивируса и 2. превышение квоты — по каждой шаре ---
if [[ -f "$SHARES_DB" ]]; then
    while IFS='|' read -r name path group writable hosts veto recycle retention av quota backup full_audit enforced; do
        [[ -z "$name" ]] && continue
        [[ ! -d "$path" ]] && continue

        # --- карантин ---
        if [[ "${av:-no}" == "yes" && -d "$path/.quarantine" ]]; then
            q_count="$(find "$path/.quarantine" -type f 2>/dev/null | wc -l)"
            state_key="quarantine_${name}"
            if state_changed "$state_key" "$q_count"; then
                if [[ "$q_count" -gt 0 ]]; then
                    notify "антивирус: в шаре '$name' файлов в карантине теперь $q_count"
                fi
                # если q_count стал 0 после того, как было >0 — тоже полезно
                # знать (карантин почистили), но не шумим отдельным событием
                # при первом запуске, когда состояние ещё не было известно
            fi
        fi

        # --- квота (мониторинговая, не enforced — см. README) ---
        quota="${quota:-0}"
        if [[ "$quota" -gt 0 ]]; then
            used_bytes="$(du -sb "$path" 2>/dev/null | cut -f1)"
            used_bytes="${used_bytes:-0}"
            state_key="quota_${name}"
            if [[ "$used_bytes" -gt "$quota" ]]; then
                if state_changed "$state_key" "over"; then
                    used_h="$(numfmt --to=iec "$used_bytes" 2>/dev/null || echo "${used_bytes}B")"
                    quota_h="$(numfmt --to=iec "$quota" 2>/dev/null || echo "${quota}B")"
                    notify "шара '$name' превысила квоту: занято $used_h из $quota_h"
                fi
            else
                state_changed "quota_${name}" "ok" >/dev/null || true
            fi
        fi
    done < "$SHARES_DB"
fi

# --- 3. SMART-статус физических дисков ---
if command -v smartctl &>/dev/null; then
    for dev in $(lsblk -dpno NAME 2>/dev/null); do
        [[ "$dev" == *loop* ]] && continue
        health="$(smartctl -H "$dev" 2>/dev/null | grep -oP '(PASSED|FAILED|OK)' | head -1)"
        [[ -z "$health" ]] && continue

        state_key="smart_$(basename "$dev")"
        if state_changed "$state_key" "$health"; then
            if [[ "$health" == "FAILED" ]]; then
                notify "диск $dev: SMART сообщает FAILED — проверь вкладку 'Диски' как можно скорее"
            fi
        fi
    done
fi

# --- 4. Срок действия TLS-сертификата панели ---
# Самоподписанный сертификат выпускается на 825 дней при установке — без
# этой проверки через два с лишним года он просто истечёт без единого
# предупреждения заранее.
CERT_FILE="/etc/ssl/sambapanel/cert.pem"
if [[ -f "$CERT_FILE" ]] && command -v openssl &>/dev/null; then
    end_date_raw="$(openssl x509 -enddate -noout -in "$CERT_FILE" 2>/dev/null | cut -d= -f2)"
    if [[ -n "$end_date_raw" ]]; then
        end_epoch="$(date -d "$end_date_raw" +%s 2>/dev/null || true)"
        if [[ -n "$end_epoch" ]]; then
            now_epoch="$(date +%s)"
            days_left=$(( (end_epoch - now_epoch) / 86400 ))

            # Пороги, а не просто "меньше 30 дней" — иначе от 30-го до
            # 1-го дня было бы 30 одинаковых уведомлений подряд, каждое
            # состояние срабатывает один раз при пересечении своего порога.
            for threshold in 30 14 7 1; do
                state_key="cert_expiry_${threshold}d"
                if [[ "$days_left" -le "$threshold" ]]; then
                    if state_changed "$state_key" "crossed"; then
                        if [[ "$days_left" -le 0 ]]; then
                            notify "TLS-сертификат панели УЖЕ ИСТЁК — обнови как можно скорее (переустановка через install.sh создаст новый, если удалить /etc/ssl/sambapanel вручную, или замени на Let's Encrypt)"
                        else
                            notify "TLS-сертификат панели истекает через ${days_left} дн. — обнови заранее (переустановка через install.sh создаст новый, если удалить /etc/ssl/sambapanel вручную, или замени на Let's Encrypt)"
                        fi
                    fi
                fi
            done
        fi
    fi
fi

log "проверка завершена"
