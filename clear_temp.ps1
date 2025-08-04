<#
.SYNOPSIS
    Утилита очистки временных файлов с сохранением файлов за последние 2 недели
.DESCRIPTION
    Поддерживает очистку через административные ресурсы, WMI и PowerShell Remoting
.VERSION
    2.1
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [string]$ComputerName,
    
    [switch]$AutoMode,
    
    [switch]$Force,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath
)

#region Инициализация и настройки
$scriptVersion = "2.1"
$defaultLogPath = "$env:TEMP\clear_temp_files.log"
$maxLogSize = 1MB
$global:ErrorActionPreference = "Stop"
$daysOld = 14
$excludedProfiles = @(
    "systemprofile", "service", "defaultuser*", 
    "public", "Администратор", "Administrator",
    "network*", "localservice", "networkservice"
)

# Определение пути для логов
if (-not $LogPath) {
    $LogPath = $defaultLogPath
}

# Инициализация логов
function Initialize-Log {
    param([string]$OperationType = "Локальная")
    
    try {
        if (Test-Path $LogPath) {
            $logSize = (Get-Item $LogPath).Length
            if ($logSize -gt $maxLogSize) {
                Remove-Item $LogPath -Force -ErrorAction Stop
            } else {
                return
            }
        }
        
        $header = @"
====================================================================
ЛОГ ОЧИСТКИ ВРЕМЕННЫХ ФАЙЛОВ (v$scriptVersion)          
Дата: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")       
Операция: $OperationType                             
Пользователь: $env:USERNAME                         
Компьютер: $env:COMPUTERNAME                         
====================================================================

"@
        $header | Out-File -FilePath $LogPath -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        Write-Console "Ошибка инициализации лога" -Level "ERROR"
    }
}

# Функция записи в лог
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    
    try {
        $logEntry | Out-File -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction Stop
    }
    catch {
        Write-Console "Ошибка записи в лог" -Level "ERROR"
    }
}

# Функция вывода в консоль
function Write-Console {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $color = switch ($Level) {
        "SUCCESS" { "Green" }
        "ERROR"   { "Red" }
        "WARNING" { "Yellow" }
        default   { "Cyan" }
    }
    
    $prefix = switch ($Level) {
        "SUCCESS" { "[УСПЕХ] " }
        "ERROR"   { "[ОШИБКА] " }
        "WARNING" { "[ВНИМАНИЕ] " }
        default   { "[ИНФО] " }
    }
    
    if (-not $AutoMode -or $Level -in @("ERROR", "WARNING")) {
        Write-Host "$prefix$Message" -ForegroundColor $color
    }
}

# Инициализация логов
Initialize-Log -OperationType "Локальная"
Write-Log "=== НАЧАЛО НОВОЙ ОПЕРАЦИИ ===" -Level "INFO"
#endregion

#region Вспомогательные функции
function Test-IsAdmin {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Write-Console "Ошибка проверки прав администратора" -Level "ERROR"
        Write-Log "Ошибка проверки прав администратора: $_" -Level "ERROR"
        return $false
    }
}

function Test-ComputerAvailability {
    param([string]$Computer)
    
    try {
        Write-Console "Проверка доступности компьютера $Computer..." -Level "INFO"
        $result = Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction Stop
        if (-not $result) {
            Write-Console "Компьютер $Computer недоступен" -Level "ERROR"
            Write-Log "Компьютер $Computer недоступен" -Level "ERROR"
        }
        return $result
    }
    catch {
        Write-Console "Ошибка проверки доступности компьютера $Computer" -Level "ERROR"
        Write-Log "Ошибка проверки доступности компьютера ${Computer}: $_" -Level "ERROR"
        return $false
    }
}

function Test-AdminShare {
    param([string]$Computer)
    
    try {
        $result = Test-Path "\\$Computer\c$\Windows" -ErrorAction Stop
        if (-not $result) {
            Write-Log "Административная шара на компьютере $Computer недоступна" -Level "WARNING"
        }
        return $result
    }
    catch {
        Write-Log "Ошибка проверки административной шары на ${Computer}: $_" -Level "ERROR"
        return $false
    }
}

function Test-PSRemoting {
    param([string]$Computer)
    
    try {
        Write-Console "Проверка доступности PSRemoting на $Computer..." -Level "INFO"
        $null = Invoke-Command -ComputerName $Computer -ScriptBlock { $true } -ErrorAction Stop
        return $true
    }
    catch {
        Write-Log "Ошибка проверки PSRemoting на ${Computer}: $_" -Level "ERROR"
        return $false
    }
}

function Get-ValidProfiles {
    param([string]$Computer = $env:COMPUTERNAME)
    
    try {
        # Получение профилей через WMI для единообразия
        $profiles = Get-WmiObject -Class Win32_UserProfile -ComputerName $Computer -ErrorAction Stop | 
                    Where-Object { 
                        $_.Special -eq $false -and 
                        $_.LocalPath -notmatch ($excludedProfiles -join '|')
                    }
        
        return $profiles
    }
    catch {
        Write-Console "Ошибка получения профилей на $Computer" -Level "ERROR"
        Write-Log "Ошибка получения профилей на ${Computer}: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Функции очистки временных файлов
function Clear-TempFiles {
    param(
        [string]$LiteralPath,
        [string]$Computer = $env:COMPUTERNAME
    )
    
    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        Write-Log "Путь $LiteralPath не найден" -Level "INFO"
        return 0
    }
    
    $deletedCount = 0
    $cutoffDate = (Get-Date).AddDays(-$daysOld)
    
    try {
        # Удаление файлов
        $files = Get-ChildItem -LiteralPath $LiteralPath -Recurse -File -ErrorAction SilentlyContinue | 
                 Where-Object { $_.LastWriteTime -lt $cutoffDate }
        
        foreach ($file in $files) {
            try {
                if ($PSCmdlet.ShouldProcess($file.FullName, "Удаление файла")) {
                    Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                    $deletedCount++
                }
            }
            catch {
                Write-Log "Ошибка удаления $($file.FullName): $($_.Exception.Message)" -Level "ERROR"
            }
        }
        
        # Удаление пустых папок (кроме корневой)
        $folders = Get-ChildItem -LiteralPath $LiteralPath -Recurse -Directory -ErrorAction SilentlyContinue | 
                   Where-Object { 
                       $_.LastWriteTime -lt $cutoffDate -and 
                       @(Get-ChildItem -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue).Count -eq 0
                   } | 
                   Sort-Object -Property FullName -Descending
        
        foreach ($folder in $folders) {
            try {
                if ($PSCmdlet.ShouldProcess($folder.FullName, "Удаление папки")) {
                    Remove-Item -LiteralPath $folder.FullName -Force -Recurse -ErrorAction Stop
                    $deletedCount++
                }
            }
            catch {
                Write-Log "Ошибка удаления $($folder.FullName): $($_.Exception.Message)" -Level "ERROR"
            }
        }
        
        if ($deletedCount -gt 0) {
            Write-Log "Удалено элементов в ${LiteralPath}: $deletedCount" -Level "SUCCESS"
        } else {
            Write-Log "Не найдено элементов для удаления в $LiteralPath" -Level "INFO"
        }
    }
    catch {
        Write-Log "Ошибка доступа к $LiteralPath : $($_.Exception.Message)" -Level "ERROR"
    }
    
    return $deletedCount
}

function Clear-ViaAdminShare {
    param([string]$Computer)
    
    try {
        Write-Console "Используем метод административной шары" -Level "INFO"
        Write-Log "Попытка очистки через административную шару на $Computer" -Level "INFO"
        
        $totalDeleted = 0
        
        # Системные временные файлы
        $sysTempPath = "\\$Computer\c$\Windows\Temp"
        $totalDeleted += Clear-TempFiles -LiteralPath $sysTempPath -Computer $Computer
        
        # Пользовательские временные файлы
        $profiles = Get-ValidProfiles -Computer $Computer
        if ($profiles) {
            foreach ($profile in $profiles) {
                $userPath = $profile.LocalPath
                $drive = $userPath.Substring(0, 1)
                $pathWithoutDrive = $userPath.Substring(3)
                $profilePath = "\\$Computer\$drive`$$pathWithoutDrive"
                
                $userTempPath = Join-Path $profilePath "AppData\Local\Temp"
                $sbisBackupPath = Join-Path $profilePath "AppData\Local\Sbis3Plugin\backup"
                
                $totalDeleted += Clear-TempFiles -LiteralPath $userTempPath -Computer $Computer
                $totalDeleted += Clear-TempFiles -LiteralPath $sbisBackupPath -Computer $Computer
            }
        }
        else {
            Write-Console "Не удалось получить список профилей" -Level "WARNING"
        }
        
        if ($totalDeleted -gt 0) {
            Write-Console "Удалено элементов: $totalDeleted" -Level "SUCCESS"
            return $true
        } else {
            Write-Console "Не найдено файлов для удаления" -Level "WARNING"
            return $false
        }
    }
    catch {
        Write-Console "Ошибка при использовании административной шары: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Ошибка при использовании административной шары: $_" -Level "ERROR"
        return $false
    }
}

function Clear-ViaPSRemoting {
    param([string]$Computer)
    
    try {
        Write-Console "Используем метод PowerShell Remoting" -Level "INFO"
        Write-Log "Попытка очистки через PSRemoting на $Computer" -Level "INFO"
        
        $scriptBlock = {
            $days = 14
            $cutoffDate = (Get-Date).AddDays(-$days)
            $totalDeleted = 0
            $excluded = @(
                "systemprofile", "service", "defaultuser*", 
                "public", "Администратор", "Administrator",
                "network*", "localservice", "networkservice"
            )
            
            # Системные временные файлы
            $sysTempPath = Join-Path $env:SystemRoot "Temp"
            if (Test-Path $sysTempPath) {
                $files = Get-ChildItem -LiteralPath $sysTempPath -Recurse -File -ErrorAction SilentlyContinue | 
                         Where-Object { $_.LastWriteTime -lt $cutoffDate }
                
                foreach ($file in $files) {
                    try {
                        Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                        $totalDeleted++
                    }
                    catch {
                        Write-Error "Ошибка удаления $($file.FullName): $_"
                    }
                }
            }
            
            # Пользовательские временные файлы
            $profiles = Get-WmiObject -Class Win32_UserProfile | 
                        Where-Object { 
                            $_.Special -eq $false -and 
                            $_.LocalPath -notmatch ($excluded -join '|')
                        }
            
            foreach ($profile in $profiles) {
                $userPath = $profile.LocalPath
                
                $userTempPath = Join-Path $userPath "AppData\Local\Temp"
                if (Test-Path $userTempPath) {
                    $files = Get-ChildItem -LiteralPath $userTempPath -Recurse -File -ErrorAction SilentlyContinue | 
                             Where-Object { $_.LastWriteTime -lt $cutoffDate }
                    
                    foreach ($file in $files) {
                        try {
                            Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                            $totalDeleted++
                        }
                        catch {
                            Write-Error "Ошибка удаления $($file.FullName): $_"
                        }
                    }
                }
                
                $sbisBackupPath = Join-Path $userPath "AppData\Local\Sbis3Plugin\backup"
                if (Test-Path $sbisBackupPath) {
                    $files = Get-ChildItem -LiteralPath $sbisBackupPath -Recurse -File -ErrorAction SilentlyContinue | 
                             Where-Object { $_.LastWriteTime -lt $cutoffDate }
                    
                    foreach ($file in $files) {
                        try {
                            Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                            $totalDeleted++
                        }
                        catch {
                            Write-Error "Ошибка удаления $($file.FullName): $_"
                        }
                    }
                }
            }
            
            return $totalDeleted
        }
        
        $result = Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ErrorAction Stop
        
        if ($result -gt 0) {
            Write-Console "Удалено $result файлов через PSRemoting" -Level "SUCCESS"
            Write-Log "Удалено $result файлов через PSRemoting на $Computer" -Level "SUCCESS"
            return $true
        } else {
            Write-Console "Не найдено файлов для удаления через PSRemoting" -Level "WARNING"
            Write-Log "Не найдено файлов для удаления через PSRemoting на $Computer" -Level "WARNING"
            return $false
        }
    }
    catch {
        Write-Console "Ошибка при использовании PSRemoting: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Ошибка при использовании PSRemoting: $_" -Level "ERROR"
        return $false
    }
}

function Clear-RemoteTempFiles {
    param([string]$Computer)
    
    Write-Console "Очистка временных файлов на $Computer" -Level "INFO"
    Write-Log "=== Начало очистки на $Computer ===" -Level "INFO"
    
    if (-not (Test-ComputerAvailability -Computer $Computer)) {
        return
    }
    
    # Проверяем методы в порядке приоритета
    if (Test-AdminShare -Computer $Computer) {
        Clear-ViaAdminShare -Computer $Computer
        return
    }
    
    if (Test-PSRemoting -Computer $Computer) {
        Clear-ViaPSRemoting -Computer $Computer
        return
    }
    
    Write-Console "Нет доступных методов для очистки" -Level "ERROR"
    Write-Log "Не найдено доступных методов для очистки на $Computer" -Level "ERROR"
}

function Clear-LocalTempFiles {
    Write-Console "Очистка локальных временных файлов" -Level "INFO"
    Write-Log "=== Начало локальной очистки ===" -Level "INFO"
    
    $totalDeleted = 0
    $cutoffDate = (Get-Date).AddDays(-$daysOld)
    
    # Системные временные файлы
    $sysTempPath = Join-Path $env:SystemRoot "Temp"
    $totalDeleted += Clear-TempFiles -LiteralPath $sysTempPath
    
    # Пользовательские временные файлы
    $profiles = Get-ValidProfiles
    if ($profiles) {
        foreach ($profile in $profiles) {
            $userPath = $profile.LocalPath
            
            $userTempPath = Join-Path $userPath "AppData\Local\Temp"
            $sbisBackupPath = Join-Path $userPath "AppData\Local\Sbis3Plugin\backup"
            
            $totalDeleted += Clear-TempFiles -LiteralPath $userTempPath
            $totalDeleted += Clear-TempFiles -LiteralPath $sbisBackupPath
        }
    }
    else {
        Write-Console "Не удалось получить список профилей" -Level "WARNING"
    }
    
    if ($totalDeleted -gt 0) {
        Write-Console "Локальная очистка завершена. Удалено файлов: $totalDeleted" -Level "SUCCESS"
    } else {
        Write-Console "Не найдено файлов для удаления" -Level "WARNING"
    }
}
#endregion

#region Главное меню и интерфейс
function Show-Menu {
    if ($AutoMode) { return }
    
    Clear-Host
    Write-Host "====================================================================" -ForegroundColor Cyan
    Write-Host "=       УТИЛИТА ОЧИСТКИ ВРЕМЕННЫХ ФАЙЛОВ $scriptVersion                       =" -ForegroundColor Cyan
    Write-Host "====================================================================" -ForegroundColor Cyan
    Write-Host "= 1. Очистить временные файлы на ЛОКАЛЬНОМ компьютере              =" -ForegroundColor Cyan
    Write-Host "= 2. Очистить временные файлы на УДАЛЕННОМ компьютере              =" -ForegroundColor Cyan
    Write-Host "= 3. Просмотреть лог                                               =" -ForegroundColor Cyan
    Write-Host "=                                                                  =" -ForegroundColor Cyan
    Write-Host "= 0. ВЫХОД                                                         =" -ForegroundColor Cyan
    Write-Host "====================================================================" -ForegroundColor Cyan
}
#endregion

#region Точка входа
if (-not (Test-IsAdmin)) {
    Write-Console "Требуются права администратора. Перезапуск..." -Level "WARNING"
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    if ($ComputerName) { $arguments += " -ComputerName `"$ComputerName`"" }
    if ($AutoMode) { $arguments += " -AutoMode" }
    if ($Force) { $arguments += " -Force" }
    if ($LogPath) { $arguments += " -LogPath `"$LogPath`"" }
    Start-Process powershell -ArgumentList $arguments -Verb RunAs
    exit
}

if (-not $AutoMode -and -not $ComputerName -and -not $Force) {
    # Режим с меню
    while ($true) {
        Show-Menu
        $choice = Read-Host "Выберите действие"
        
        switch ($choice) {
            "1" { Clear-LocalTempFiles }
            "2" { 
                $computer = Read-Host "Введите имя или IP-адрес компьютера"
                Clear-RemoteTempFiles -Computer $computer 
            }
            "3" { 
                if (Test-Path $LogPath) {
                    try {
                        notepad $LogPath
                    }
                    catch {
                        Write-Console "Не удалось открыть лог" -Level "ERROR"
                    }
                }
                else {
                    Write-Console "Лог не найден" -Level "WARNING"
                }
            }
            "0" { exit }
            default { 
                Write-Console "Неверный выбор!" -Level "ERROR"
            }
        }
        
        if ($choice -in "1","2") {
            Write-Host "`nНажмите любую клавишу для продолжения..."
            [void][System.Console]::ReadKey($true)
        }
    }
}
else {
    # Прямой режим (для автоматизации)
    if ($ComputerName) {
        Clear-RemoteTempFiles -Computer $ComputerName
    }
    else {
        Clear-LocalTempFiles
    }
}
#endregion