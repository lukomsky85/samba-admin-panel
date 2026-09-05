#!/usr/bin/env bash
# release.sh — закоммитить текущее состояние проекта в git, поставить тег
# и создать релиз на GitHub (через gh CLI, если он есть).
#
# Использование:
#   ./scripts/release.sh                          # всё по умолчанию (см. ниже)
#   ./scripts/release.sh -v v1.4.5                # явно задать версию тега
#   ./scripts/release.sh -m "fix: SMART parsing"  # своё сообщение коммита
#   ./scripts/release.sh -n notes.md              # свой файл с описанием релиза
#   ./scripts/release.sh -r git@github.com:you/samba-admin-panel.git  # remote,
#                                                  # если репозиторий ещё не привязан
#
# По умолчанию:
#   - версия тега = патч-инкремент от содержимого файла VERSION (v1.4.1 -> v1.4.2)
#   - сообщение коммита = "Локальные фиксы: см. CHANGES-local.md"
#   - текст релиза = содержимое CHANGES-local.md (если файл есть рядом)
#   - если `gh` не установлен — тег и коммит всё равно запушатся,
#     а релиз нужно будет создать руками по ссылке, которую скрипт покажет
#
# Требования: git всегда; gh — опционально (для автосоздания релиза на GitHub).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

VERSION_FILE="VERSION"
NOTES_FILE_DEFAULT="CHANGES-local.md"
COMMIT_MSG="Локальные фиксы: см. CHANGES-local.md"
TAG=""
NOTES_FILE=""
REMOTE_URL=""
BRANCH="$(git symbolic-ref --short HEAD 2>/dev/null || echo main)"

usage() {
    sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d; s/^# \{0,1\}//'
    exit 1
}

while getopts "v:m:n:r:h" opt; do
    case "$opt" in
        v) TAG="$OPTARG" ;;
        m) COMMIT_MSG="$OPTARG" ;;
        n) NOTES_FILE="$OPTARG" ;;
        r) REMOTE_URL="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

command -v git >/dev/null 2>&1 || { echo "ERROR: git не установлен" >&2; exit 1; }

HAVE_GH=0
if command -v gh >/dev/null 2>&1; then
    HAVE_GH=1
else
    echo "Внимание: 'gh' (GitHub CLI) не найден — коммит и тег будут запушены," >&2
    echo "но релиз на GitHub придётся создать руками (ссылку покажу в конце)." >&2
fi

# --- версия тега ---
if [[ -z "$TAG" ]]; then
    current="unknown"
    [[ -f "$VERSION_FILE" ]] && current="$(tr -d '[:space:]' < "$VERSION_FILE")"
    if [[ "$current" =~ ^v?([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        major="${BASH_REMATCH[1]}"; minor="${BASH_REMATCH[2]}"; patch="${BASH_REMATCH[3]}"
        TAG="v${major}.${minor}.$((patch + 1))"
        echo "Текущая версия: $current -> новый тег: $TAG"
    else
        echo "ERROR: не смог разобрать версию из '$VERSION_FILE' (содержимое: '$current')." >&2
        echo "Задай тег явно: ./scripts/release.sh -v v1.5.0" >&2
        exit 1
    fi
fi
[[ "$TAG" =~ ^v ]] || TAG="v$TAG"

# --- текст релиза ---
if [[ -z "$NOTES_FILE" ]]; then
    if [[ -f "$NOTES_FILE_DEFAULT" ]]; then
        NOTES_FILE="$NOTES_FILE_DEFAULT"
    fi
fi
if [[ -n "$NOTES_FILE" && ! -f "$NOTES_FILE" ]]; then
    echo "ERROR: файл с описанием релиза не найден: $NOTES_FILE" >&2
    exit 1
fi

echo "== release.sh =="
echo "Директория:      $SCRIPT_DIR"
echo "Тег:              $TAG"
echo "Сообщение коммита: $COMMIT_MSG"
echo "Файл описания:    ${NOTES_FILE:-<нет — будет пустое описание>}"
echo ""

# --- git-репозиторий ---
if [[ ! -d .git ]]; then
    echo "Git-репозиторий не найден — инициализирую (git init)."
    git init
    git checkout -b "$BRANCH" 2>/dev/null || true
fi

if [[ -n "$REMOTE_URL" ]]; then
    if git remote get-url origin >/dev/null 2>&1; then
        git remote set-url origin "$REMOTE_URL"
    else
        git remote add origin "$REMOTE_URL"
    fi
    echo "remote 'origin' -> $REMOTE_URL"
fi

if ! git remote get-url origin >/dev/null 2>&1; then
    echo "ERROR: нет remote 'origin'. Укажи его через -r:" >&2
    echo "  ./scripts/release.sh -r git@github.com:USER/REPO.git" >&2
    exit 1
fi

# --- коммит ---
git add -A
if git diff --cached --quiet; then
    echo "Нет изменений для коммита (рабочее дерево уже совпадает с последним коммитом)."
else
    git commit -m "$COMMIT_MSG"
    echo "Закоммичено: $COMMIT_MSG"
fi

# --- версия в файле VERSION (для встроенной системы самообновления панели) ---
echo "$TAG" > "$VERSION_FILE"
if ! git diff --quiet -- "$VERSION_FILE" 2>/dev/null; then
    git add "$VERSION_FILE"
    git commit -m "Bump VERSION -> $TAG"
fi

# --- тег ---
if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "ERROR: тег $TAG уже существует локально. Выбери другую версию (-v) или удали старый тег." >&2
    exit 1
fi
if [[ -n "$NOTES_FILE" ]]; then
    git tag -a "$TAG" -F "$NOTES_FILE"
else
    git tag -a "$TAG" -m "$TAG"
fi
echo "Тег создан: $TAG"

# --- push ---
git push origin "$BRANCH"
git push origin "$TAG"
echo "Запушено: ветка $BRANCH и тег $TAG"

# --- релиз ---
REPO_URL_NO_GIT="$(git remote get-url origin)"
REPO_URL_NO_GIT="${REPO_URL_NO_GIT%.git}"
REPO_SLUG="$(echo "$REPO_URL_NO_GIT" | sed -E 's#^.*[:/]([^/]+/[^/]+)$#\1#')"

if [[ "$HAVE_GH" -eq 1 ]]; then
    if [[ -n "$NOTES_FILE" ]]; then
        gh release create "$TAG" --title "$TAG" --notes-file "$NOTES_FILE"
    else
        gh release create "$TAG" --title "$TAG" --notes "Релиз $TAG"
    fi
    echo ""
    echo "Готово: релиз $TAG создан -> https://github.com/${REPO_SLUG}/releases/tag/${TAG}"
else
    echo ""
    echo "Тег и коммит запушены. Создай релиз вручную:"
    echo "  https://github.com/${REPO_SLUG}/releases/new?tag=${TAG}"
    [[ -n "$NOTES_FILE" ]] && echo "  (текст описания — в файле $NOTES_FILE)"
fi
