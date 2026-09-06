# release-gui.ps1 — GUI-обёртка над той же логикой, что и scripts/release.sh:
# указываешь архив проекта (.zip) через диалог выбора файла — дальше всё
# происходит само: распаковка, git init/commit, обновление VERSION,
# git tag, push, и (если установлен gh) создание релиза на GitHub.
#
# Требования на Windows:
#   - Git for Windows (https://git-scm.com/download/win)
#   - (опционально) GitHub CLI 'gh' (https://cli.github.com/) —
#     без него релиз придётся один раз создать вручную по ссылке,
#     которую скрипт покажет в конце.
#
# Запуск: двойной клик по release-gui.bat (он вызывает этот скрипт
# с нужными правами выполнения). Можно и напрямую:
#   powershell -ExecutionPolicy Bypass -File release-gui.ps1

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName Microsoft.VisualBasic

function Show-Info($msg) {
    [System.Windows.Forms.MessageBox]::Show($msg, "release-gui", "OK", "Information") | Out-Null
}
function Show-ErrorBox($msg) {
    [System.Windows.Forms.MessageBox]::Show($msg, "release-gui", "OK", "Error") | Out-Null
}
function Ask-Text($prompt, $default = "") {
    return [Microsoft.VisualBasic.Interaction]::InputBox($prompt, "release-gui", $default)
}

function Invoke-Git {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$GitArgs)
    Write-Host ">> git $($GitArgs -join ' ')" -ForegroundColor Cyan
    $output = & git @GitArgs 2>&1
    $output | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) {
        throw "Команда 'git $($GitArgs -join ' ')' завершилась с ошибкой (код $LASTEXITCODE):`n$($output -join "`n")"
    }
    return $output
}

try {
    # --- 0. проверка git ---
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Show-ErrorBox "Git не найден в PATH. Установи Git for Windows: https://git-scm.com/download/win и запусти скрипт заново."
        exit 1
    }
    $haveGh = [bool](Get-Command gh -ErrorAction SilentlyContinue)
    if (-not $haveGh) {
        Write-Host "Внимание: 'gh' (GitHub CLI) не найден — релиз на GitHub нужно будет создать вручную по ссылке в конце." -ForegroundColor Yellow
    }

    # --- 1. выбор архива ---
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = "Выбери архив проекта (.zip)"
    $dialog.Filter = "ZIP-архивы (*.zip)|*.zip|Все файлы (*.*)|*.*"
    if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        Write-Host "Отменено пользователем."
        exit 0
    }
    $zipPath = $dialog.FileName
    Write-Host "Архив: $zipPath"

    # --- 2. распаковка ---
    $baseDir  = Split-Path $zipPath -Parent
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($zipPath)
    $extractDir = Join-Path $baseDir $baseName

    if (Test-Path $extractDir) {
        $choice = [System.Windows.Forms.MessageBox]::Show(
            "Папка '$extractDir' уже существует.`nДа — использовать как есть (без повторной распаковки).`nНет — удалить и распаковать архив заново.`nОтмена — прервать.",
            "release-gui", "YesNoCancel", "Question")
        if ($choice -eq [System.Windows.Forms.DialogResult]::Cancel) { exit 0 }
        if ($choice -eq [System.Windows.Forms.DialogResult]::No) {
            Remove-Item -Recurse -Force $extractDir
            Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
        }
    } else {
        Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
    }
    Write-Host "Распаковано в: $extractDir"

    # --- 3. найти реальный корень проекта (архив может содержать вложенную папку) ---
    $versionFile = Get-ChildItem -Path $extractDir -Recurse -Filter "VERSION" -File |
        Where-Object { Test-Path (Join-Path $_.DirectoryName "samba-admin-helper.sh") } |
        Select-Object -First 1
    if (-not $versionFile) {
        Show-ErrorBox "Не нашёл в архиве файл VERSION рядом с samba-admin-helper.sh — это точно проект samba-admin-panel?"
        exit 1
    }
    $projectRoot = $versionFile.DirectoryName
    Write-Host "Корень проекта: $projectRoot"
    Set-Location $projectRoot

    # --- 4. настройка git identity, если ещё не задана ---
    $userName  = (& git config --get user.name 2>$null)
    $userEmail = (& git config --get user.email 2>$null)
    if (-not $userName) {
        $userName = Ask-Text "Git не настроен (user.name). Введи своё имя для коммитов:"
        if ($userName) { Invoke-Git config --global user.name $userName }
    }
    if (-not $userEmail) {
        $userEmail = Ask-Text "И email для коммитов (user.email):"
        if ($userEmail) { Invoke-Git config --global user.email $userEmail }
    }

    # --- 5. git-репозиторий ---
    $branch = "main"
    if (-not (Test-Path ".git")) {
        Invoke-Git init | Out-Null
        Invoke-Git checkout -b $branch | Out-Null
    } else {
        $currentBranch = (& git symbolic-ref --short HEAD 2>$null)
        if ($currentBranch) { $branch = $currentBranch }
    }

    $remoteUrl = (& git remote get-url origin 2>$null)
    if (-not $remoteUrl) {
        $remoteUrl = Ask-Text "Укажи URL git-репозитория (например git@github.com:user/repo.git).`nЕсли оставить пустым — коммит и тег будут только локальными, без push."
        if ($remoteUrl) {
            Invoke-Git remote add origin $remoteUrl | Out-Null
        }
    }

    # --- 6. коммит ---
    Invoke-Git add -A | Out-Null
    & git diff --cached --quiet
    $hasChanges = ($LASTEXITCODE -ne 0)
    if ($hasChanges) {
        Invoke-Git commit -m "Локальные фиксы: см. CHANGES-local.md" | Out-Null
        Write-Host "Закоммичено."
    } else {
        Write-Host "Изменений для коммита нет."
    }

    # --- 7. версия ---
    $verContent = (Get-Content -Raw "VERSION").Trim()
    if ($verContent -match '^v?(\d+)\.(\d+)\.(\d+)$') {
        $major = [int]$Matches[1]; $minor = [int]$Matches[2]; $patch = [int]$Matches[3]
        $tag = "v$major.$minor.$($patch + 1)"
    } else {
        Show-ErrorBox "Не смог разобрать версию из файла VERSION (содержимое: '$verContent')."
        exit 1
    }
    Write-Host "Новый тег: $tag (было: $verContent)"

    if (Test-Path "VERSION") {
        Set-Content -Path "VERSION" -Value $tag -NoNewline
        Invoke-Git add "VERSION" | Out-Null
        & git diff --cached --quiet
        if ($LASTEXITCODE -ne 0) {
            Invoke-Git commit -m "Bump VERSION -> $tag" | Out-Null
        }
    }

    # --- 8. тег ---
    & git rev-parse $tag 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Show-ErrorBox "Тег $tag уже существует локально. Удали старый тег или поправь VERSION вручную и запусти скрипт заново."
        exit 1
    }
    $notesFile = Join-Path $projectRoot "CHANGES-local.md"
    if (Test-Path $notesFile) {
        Invoke-Git tag -a $tag -F $notesFile | Out-Null
    } else {
        Invoke-Git tag -a $tag -m $tag | Out-Null
    }
    Write-Host "Тег создан: $tag"

    # --- 9. доверие SSH host key (иначе push падает без возможности спросить,
    #        т.к. мы перехватываем вывод команды в переменную) ---
    if ($remoteUrl -match '^git@([^:]+):') {
        $sshHost = $Matches[1]
        $sshDir = Join-Path $env:USERPROFILE ".ssh"
        if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir | Out-Null }
        $knownHosts = Join-Path $sshDir "known_hosts"
        $alreadyKnown = $false
        if (Test-Path $knownHosts) {
            $existing = Get-Content $knownHosts -ErrorAction SilentlyContinue
            $alreadyKnown = [bool]($existing | Where-Object { $_ -match [regex]::Escape($sshHost) })
        }
        if (-not $alreadyKnown) {
            if (Get-Command ssh-keyscan -ErrorAction SilentlyContinue) {
                Write-Host "Добавляю SSH host key для '$sshHost' в known_hosts..."
                $keyLines = & ssh-keyscan -H $sshHost 2>$null
                if ($keyLines) {
                    Add-Content -Path $knownHosts -Value $keyLines
                    Write-Host "Host key для '$sshHost' добавлен."
                } else {
                    Write-Host "Не удалось получить host key через ssh-keyscan — push может запросить подтверждение вручную." -ForegroundColor Yellow
                }
            } else {
                Write-Host "ssh-keyscan не найден — если push попросит подтвердить host key, ответь 'yes' в консоли." -ForegroundColor Yellow
            }
        }
    }

    # --- 10. push ---
    if (& git remote get-url origin 2>$null) {
        Invoke-Git push origin $branch | Out-Null
        Invoke-Git push origin $tag | Out-Null
        Write-Host "Запушено: ветка $branch и тег $tag"
    } else {
        Write-Host "Remote не задан — push пропущен, тег и коммит только локальные."
    }

    # --- 11. релиз ---
    $remoteUrl = (& git remote get-url origin 2>$null)
    $repoSlug = $null
    if ($remoteUrl) {
        $noGit = $remoteUrl -replace '\.git$', ''
        $parts = $noGit -split '[:/]' | Where-Object { $_ -ne "" }
        if ($parts.Count -ge 2) {
            $repoSlug = "$($parts[-2])/$($parts[-1])"
        }
    }

    if ($haveGh -and $remoteUrl) {
        if (Test-Path $notesFile) {
            & gh release create $tag --title $tag --notes-file $notesFile
        } else {
            & gh release create $tag --title $tag --notes "Релиз $tag"
        }
        if ($LASTEXITCODE -eq 0) {
            Show-Info "Готово: релиз $tag создан.`nhttps://github.com/$repoSlug/releases/tag/$tag"
        } else {
            Show-ErrorBox "Тег и коммит запушены, но 'gh release create' завершился с ошибкой (код $LASTEXITCODE).`nСоздай релиз вручную: https://github.com/$repoSlug/releases/new?tag=$tag"
        }
    } elseif ($remoteUrl) {
        Show-Info "Тег $tag и коммит запушены.`nСоздай релиз вручную (gh не установлен):`nhttps://github.com/$repoSlug/releases/new?tag=$tag"
    } else {
        Show-Info "Тег $tag создан локально (без push — remote не был задан).`nПроект лежит здесь: $projectRoot"
    }
}
catch {
    Show-ErrorBox "Ошибка:`n$($_.Exception.Message)"
    exit 1
}
