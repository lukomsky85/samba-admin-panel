"""
test_shares_db_schema.py — статическая проверка согласованности схемы
shares.db (12 полей: name|path|group|writable|hosts|veto|recycle|
retention_days|antivirus|quota_bytes|backup_enabled|full_audit) во всех
bash-скриптах, которые её парсят.

Почему это вообще существует: два реальных, ранее незамеченных бага —
`samba-backup.sh` и `samba-recycle-cleanup.sh` читали МЕНЬШЕ переменных
через `IFS='|' read`, чем реальных полей в shares.db. Bash в такой
ситуации молча склеивает все "лишние" поля в ПОСЛЕДНЮЮ переменную вместе
с разделителями ("1|no|0|yes|no" вместо "1"), из-за чего сравнения вроде
`[[ "$backup" == "yes" ]]` или `find -mtime +"$retention"` тихо ломались —
автобэкап и автоочистка корзины по факту не работали, хотя код не падал
и не жаловался. Этот тест не даёт такому повториться при следующем
изменении схемы (например, если добавится 13-е поле).
"""
import os
import re

import pytest

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPECTED_FIELD_COUNT = 12

SCRIPTS_TO_CHECK = [
    "samba-backup.sh",
    "samba-recycle-cleanup.sh",
    "samba-admin-helper.sh",
    "samba-panel-monitor.sh",
]


def _find_shares_db_read_statements(filepath):
    """
    Находит места вида:
      while IFS='|' read -r var1 var2 ... ; do ... done < "$SHARES_DB"
      IFS='|' read -r var1 var2 ... <<< "$line"       (разбор одной уже найденной строки shares.db)

    Важно: `while IFS='|' read` сам по себе НЕ означает чтение shares.db —
    тот же самый паттерн (тот же разделитель) используется и для разбора
    вообще любых pipe-separated данных, например вывода `find -printf`
    при листинге файлов бэкапа. Поэтому для конструкции "while...do"
    дополнительно проверяем, что соответствующий "done" читает именно из
    $SHARES_DB — иначе это ложное совпадение по счастливому совпадению
    синтаксиса, а не реальное чтение схемы шар.
    """
    results = []
    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()

    while_pat = re.compile(r"while\s+IFS='\|'\s+read\s+-r\s+(.+?);\s*do")
    heredoc_pat = re.compile(r"IFS='\|'\s+read\s+-r\s+(.+?)\s*<<<")
    done_shares_db_pat = re.compile(r"done\s*<\s*\"?\$SHARES_DB\"?")

    for i, line in enumerate(lines, 1):
        m = while_pat.search(line)
        if m:
            # ищем соответствующий "done" в разумных пределах ниже по файлу
            is_shares_db_loop = any(
                done_shares_db_pat.search(lines[j])
                for j in range(i, min(i + 60, len(lines)))
            )
            if is_shares_db_loop:
                vars_list = m.group(1).split()
                results.append((i, vars_list, line.strip()))
            continue

        m = heredoc_pat.search(line)
        if m:
            vars_list = m.group(1).split()
            results.append((i, vars_list, line.strip()))

    return results


def _is_intentional_partial_read(vars_list):
    """
    Единственный законный случай меньшего числа переменных — последняя
    названа с ведущим "_" (например "_rest"): явный сигнал "остальное
    не нужно, специально отбрасываю". Такая переменная по всему проекту
    нигде не участвует в сравнениях — если бы участвовала, это была бы
    точно такая же ошибка, как обе исправленные сегодня (значение
    содержало бы необработанные разделители "|" внутри).
    """
    return bool(vars_list) and vars_list[-1].startswith("_")


@pytest.mark.parametrize("script_name", SCRIPTS_TO_CHECK)
def test_shares_db_field_count_consistency(script_name):
    path = os.path.join(PROJECT_DIR, script_name)
    if not os.path.isfile(path):
        pytest.skip(f"{script_name} не найден рядом с тестами — проверь PROJECT_DIR")

    statements = _find_shares_db_read_statements(path)
    assert statements, (
        f"{script_name}: не нашёл ни одной конструкции чтения shares.db через "
        f"IFS='|' read — если скрипт больше не читает shares.db, удали его из "
        f"SCRIPTS_TO_CHECK; если читает другим способом, добавь для него отдельную проверку"
    )

    problems = []
    for lineno, vars_list, line_text in statements:
        count = len(vars_list)
        if count == EXPECTED_FIELD_COUNT:
            continue
        if _is_intentional_partial_read(vars_list):
            continue
        problems.append(
            f"  строка {lineno}: читает {count} переменных, ожидается "
            f"{EXPECTED_FIELD_COUNT}\n    {line_text}"
        )

    assert not problems, (
        f"{script_name}: несоответствие количества полей shares.db "
        f"(ожидается {EXPECTED_FIELD_COUNT} — name|path|group|writable|hosts|"
        f"veto|recycle|retention_days|antivirus|quota_bytes|backup_enabled|"
        f"full_audit):\n" + "\n".join(problems)
    )
