#!/usr/bin/env bash
#
# uninstall.sh — убирает панель и связанные с ней системные артефакты.
# Данные в самих шарах (файлы пользователей) НЕ трогает никогда.
# Samba (smbd) и созданных через панель Linux-пользователей тоже не трогает —
# только саму веб-панель и её системные хуки.

set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
    echo "запусти через sudo: sudo ./uninstall.sh" >&2
    exit 1
fi

echo "Останавливаю и убираю сервис sambapanel..."
systemctl disable --now sambapanel 2>/dev/null || true
rm -f /etc/systemd/system/sambapanel.service
systemctl daemon-reload

echo "Останавливаю и убираю таймер автоочистки корзины..."
systemctl disable --now samba-recycle-cleanup.timer 2>/dev/null || true
rm -f /etc/systemd/system/samba-recycle-cleanup.service /etc/systemd/system/samba-recycle-cleanup.timer
rm -f /usr/local/sbin/samba-recycle-cleanup.sh
systemctl daemon-reload

echo "Останавливаю и убираю таймер бэкапа (сами архивы в BACKUP_DEST НЕ трогаю)..."
systemctl disable --now samba-backup.timer 2>/dev/null || true
rm -f /etc/systemd/system/samba-backup.service /etc/systemd/system/samba-backup.timer
rm -f /usr/local/sbin/samba-backup.sh
systemctl daemon-reload

echo "Убираю sudoers-правило..."
rm -f /etc/sudoers.d/samba-admin

echo "Убираю хелпер-скрипт..."
rm -f /usr/local/sbin/samba-admin-helper.sh

echo "Убираю nginx-конфиг панели (сам nginx и ClamAV не трогаю — могут использоваться независимо)..."
rm -f /etc/nginx/sites-enabled/sambapanel /etc/nginx/sites-available/sambapanel
systemctl reload nginx 2>/dev/null || true

echo "Убираю logrotate-конфиг журнала действий панели (лог полного аудита файлов"
echo "оставляю как есть — это функция самой Samba, а не панели, и может использоваться независимо)..."
rm -f /etc/logrotate.d/sambapanel

read -r -p "Удалить папку /opt/sambapanel (код панели, venv)? [y/N] " ans
if [[ "${ans,,}" == "y" ]]; then
    rm -rf /opt/sambapanel
fi

read -r -p "Удалить системного пользователя www-panel? [y/N] " ans
if [[ "${ans,,}" == "y" ]]; then
    userdel -r www-panel 2>/dev/null || true
fi

echo
echo "Панель удалена. Samba, шары и все Linux-пользователи, созданные через неё,"
echo "остались нетронутыми — если нужно снести и их, делай это отдельно и осознанно."
echo "Конфиг /etc/samba/panel-shares.conf и include в smb.conf оставлены как есть."
echo "ClamAV и его systemd-сервисы тоже не тронуты — если он не нужен отдельно от"
echo "панели, убери руками: sudo apt remove clamav-daemon clamav-freshclam"
