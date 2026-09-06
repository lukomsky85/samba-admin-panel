#!/usr/bin/env python3
"""
release_gui.py — GUI-обёртка над той же логикой, что и scripts/release.sh:
указываешь архив проекта (.zip) через диалог выбора файла — дальше всё
происходит само: распаковка, git init/commit, обновление VERSION,
git tag, push, и (если установлен gh) создание релиза на GitHub.

Требования:
  - Python 3 (на Windows скачать с https://python.org — при установке
    поставь галочку "Add python.exe to PATH")
  - Git (https://git-scm.com/download/win)
  - (опционально) GitHub CLI 'gh' (https://cli.github.com/) — без него
    релиз придётся один раз создать вручную по ссылке, которую скрипт
    покажет в конце.

Запуск (Windows): двойной клик по release-gui-py.bat
Запуск (Linux/macOS): python3 release_gui.py
"""

import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

NOTES_FILENAME = "CHANGES-local.md"
MARKER_FILENAME = "samba-admin-helper.sh"


def run_capture(args):
    """Запустить команду, перехватив вывод. Возвращает (returncode, stdout+stderr)."""
    result = subprocess.run(
        args, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    combined = (result.stdout or "") + (result.stderr or "")
    return result.returncode, combined.strip()


def run_live(args):
    """Запустить команду БЕЗ перехвата вывода — видно в консоли и работают
    интерактивные запросы (например, подтверждение SSH host key)."""
    print(f">> {' '.join(args)}")
    result = subprocess.run(args)
    return result.returncode


def git_capture(*args):
    return run_capture(["git", *args])


def git_live_required(*args):
    """Запустить git-команду, показывая вывод, и упасть с понятным сообщением
    при ошибке — для действий, где сбой критичен (commit, tag, push)."""
    code = run_live(["git", *args])
    if code != 0:
        raise RuntimeError(f"Команда 'git {' '.join(args)}' завершилась с кодом {code}.")
    return code


def ask_text(prompt, initial=""):
    return simpledialog.askstring("release-gui", prompt, initialvalue=initial)


def find_project_root(extract_dir: Path) -> Path:
    for version_file in extract_dir.rglob("VERSION"):
        if (version_file.parent / MARKER_FILENAME).exists():
            return version_file.parent
    raise RuntimeError(
        f"Не нашёл в архиве файл VERSION рядом с {MARKER_FILENAME} — "
        "это точно проект samba-admin-panel?"
    )


def repo_slug_from_url(url: str):
    no_git = re.sub(r"\.git$", "", url.strip())
    parts = [p for p in re.split(r"[:/]", no_git) if p]
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    return None


def main():
    root = tk.Tk()
    root.withdraw()

    # --- 0. проверка git ---
    if shutil.which("git") is None:
        messagebox.showerror(
            "release-gui",
            "Git не найден в PATH. Установи Git for Windows:\n"
            "https://git-scm.com/download/win\nи запусти скрипт заново.",
        )
        sys.exit(1)
    have_gh = shutil.which("gh") is not None
    if not have_gh:
        print(
            "Внимание: 'gh' (GitHub CLI) не найден — релиз на GitHub "
            "нужно будет создать вручную по ссылке в конце."
        )

    # --- 1. выбор архива ---
    zip_path_str = filedialog.askopenfilename(
        title="Выбери архив проекта (.zip)",
        filetypes=[("ZIP-архивы", "*.zip"), ("Все файлы", "*.*")],
    )
    if not zip_path_str:
        print("Отменено пользователем.")
        return
    zip_path = Path(zip_path_str)
    print(f"Архив: {zip_path}")

    # --- 2. распаковка ---
    extract_dir = zip_path.with_suffix("")  # убирает .zip
    if extract_dir.exists():
        choice = messagebox.askyesnocancel(
            "release-gui",
            f"Папка '{extract_dir}' уже существует.\n"
            "Да — использовать как есть (без повторной распаковки).\n"
            "Нет — удалить и распаковать архив заново.\n"
            "Отмена — прервать.",
        )
        if choice is None:
            return
        if choice is False:
            shutil.rmtree(extract_dir)
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(extract_dir)
    else:
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(extract_dir)
    print(f"Распаковано в: {extract_dir}")

    # --- 3. найти корень проекта ---
    try:
        project_root = find_project_root(extract_dir)
    except RuntimeError as e:
        messagebox.showerror("release-gui", str(e))
        sys.exit(1)
    print(f"Корень проекта: {project_root}")
    os.chdir(project_root)

    try:
        # --- 4. git identity ---
        _, user_name = git_capture("config", "--get", "user.name")
        _, user_email = git_capture("config", "--get", "user.email")
        if not user_name:
            user_name = ask_text("Git не настроен (user.name). Введи своё имя для коммитов:")
            if user_name:
                git_live_required("config", "--global", "user.name", user_name)
        if not user_email:
            user_email = ask_text("И email для коммитов (user.email):")
            if user_email:
                git_live_required("config", "--global", "user.email", user_email)

        # --- 5. репозиторий ---
        branch = "main"
        if not (project_root / ".git").exists():
            git_live_required("init")
            git_live_required("checkout", "-b", branch)
        else:
            code, current_branch = git_capture("symbolic-ref", "--short", "HEAD")
            if code == 0 and current_branch:
                branch = current_branch

        code, remote_url = git_capture("remote", "get-url", "origin")
        if code != 0 or not remote_url:
            remote_url = ask_text(
                "Укажи URL git-репозитория (например git@github.com:user/repo.git).\n"
                "Если оставить пустым — коммит и тег будут только локальными, без push."
            )
            if remote_url:
                git_live_required("remote", "add", "origin", remote_url)
            else:
                remote_url = ""

        # --- 6. коммит ---
        git_live_required("add", "-A")
        code, _ = git_capture("diff", "--cached", "--quiet")
        has_changes = code != 0
        if has_changes:
            git_live_required("commit", "-m", "Локальные фиксы: см. CHANGES-local.md")
            print("Закоммичено.")
        else:
            print("Изменений для коммита нет.")

        # --- 7. версия ---
        version_file = project_root / "VERSION"
        ver_content = version_file.read_text(encoding="utf-8").strip()
        m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)$", ver_content)
        if not m:
            messagebox.showerror(
                "release-gui",
                f"Не смог разобрать версию из файла VERSION (содержимое: '{ver_content}').",
            )
            sys.exit(1)
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
        tag = f"v{major}.{minor}.{patch + 1}"
        print(f"Новый тег: {tag} (было: {ver_content})")

        version_file.write_text(tag, encoding="utf-8")
        git_live_required("add", "VERSION")
        code, _ = git_capture("diff", "--cached", "--quiet")
        if code != 0:
            git_live_required("commit", "-m", f"Bump VERSION -> {tag}")

        # --- 8. тег ---
        code, _ = git_capture("rev-parse", tag)
        if code == 0:
            messagebox.showerror(
                "release-gui",
                f"Тег {tag} уже существует локально. Удали старый тег или "
                "поправь VERSION вручную и запусти скрипт заново.",
            )
            sys.exit(1)
        notes_file = project_root / NOTES_FILENAME
        if notes_file.exists():
            git_live_required("tag", "-a", tag, "-F", str(notes_file))
        else:
            git_live_required("tag", "-a", tag, "-m", tag)
        print(f"Тег создан: {tag}")

        # --- 9. push ---
        code, remote_url = git_capture("remote", "get-url", "origin")
        if code == 0 and remote_url:
            git_live_required("push", "origin", branch)
            git_live_required("push", "origin", tag)
            print(f"Запушено: ветка {branch} и тег {tag}")
        else:
            print("Remote не задан — push пропущен, тег и коммит только локальные.")

        # --- 10. релиз ---
        code, remote_url = git_capture("remote", "get-url", "origin")
        repo_slug = repo_slug_from_url(remote_url) if code == 0 and remote_url else None

        if have_gh and remote_url:
            if notes_file.exists():
                gh_args = ["gh", "release", "create", tag, "--title", tag,
                           "--notes-file", str(notes_file)]
            else:
                gh_args = ["gh", "release", "create", tag, "--title", tag,
                           "--notes", f"Релиз {tag}"]
            print(f">> {' '.join(gh_args)}")
            gh_code = subprocess.run(gh_args).returncode
            if gh_code == 0:
                messagebox.showinfo(
                    "release-gui",
                    f"Готово: релиз {tag} создан.\n"
                    f"https://github.com/{repo_slug}/releases/tag/{tag}",
                )
            else:
                messagebox.showerror(
                    "release-gui",
                    f"Тег и коммит запушены, но 'gh release create' завершился "
                    f"с ошибкой (код {gh_code}).\nСоздай релиз вручную: "
                    f"https://github.com/{repo_slug}/releases/new?tag={tag}",
                )
        elif remote_url:
            messagebox.showinfo(
                "release-gui",
                f"Тег {tag} и коммит запушены.\n"
                f"Создай релиз вручную (gh не установлен):\n"
                f"https://github.com/{repo_slug}/releases/new?tag={tag}",
            )
        else:
            messagebox.showinfo(
                "release-gui",
                f"Тег {tag} создан локально (без push — remote не был задан).\n"
                f"Проект лежит здесь: {project_root}",
            )

    except RuntimeError as e:
        messagebox.showerror("release-gui", f"Ошибка:\n{e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
