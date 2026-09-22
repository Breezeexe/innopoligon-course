# Контекст текущего пользователя и его привилегии в Windows: Разведка на этапе пост-эксплуатации

## Контекст текущего пользователя: Идентификация и сегрегация

В контексте тестирования на проникновение и реагирования на инциденты (IR) «контекст текущего пользователя» — это совокупность атрибутов безопасности, определяющих уровень доверия операционной системы Windows к процессу, от имени которого выполняется код. Ключевым элементом этого контекста является **токен доступа (Access Token)**, который содержит идентификатор безопасности (SID) пользователя, SID групп членства, права (privileges) и уровень целостности (Integrity Level). Понимание контекста необходимо для оценки потенциального ущерба: пользователь с низким уровнем целостности (Low Integrity) не может модифицировать системные файлы, даже если он является администратором, в то время как процесс с высоким уровнем целостности (High Integrity) и правами `SeDebugPrivilege` может инъектировать код в процессы других пользователей.

Разграничение понятий «пользователь» (User) и «привилегия» (Privilege) критически важно. Пользователь — это субъект доступа, идентифицируемый SID. Привилегия — это системное разрешение, позволяющее выполнять специфические действия на уровне ОС (например, `SeShutdownPrivilege` или `SeDebugPrivilege`). Один и тот же пользователь может иметь разные наборы привилегий в зависимости от того, в каком контексте запущен процесс (например, через UAC-промпт или как служба).

Следующая таблица фиксирует ключевые разграничения между уровнями целостности и типами учетных записей в Windows, которые определяют границы возможностей атакующего на этапе разведки.

| Сущность / Уровень | Ключевые признаки в токене | Ограничения и возможности | Типичные индикаторы в разведке |
|---|---|---|---|
| **Low Integrity (Низкий)** | `Mandatory Label\Low Mandatory Level` | Не может писать в High/Medium области. Может читать публичные данные. Изолирован от большинства системных компонентов. | Процесс в `C:\Users\<user>\AppData\LocalLow\...`; браузер в Protected Mode. |
| **Medium Integrity (Средний)** | `Mandatory Label\Medium Mandatory Level` | Стандартный пользовательский контекст. Не может писать в `C:\Windows` или `HKLM`. Может запускать GUI. | Обычный процесс `explorer.exe`, `cmd.exe` без UAC. |
| **High Integrity (Высокий)** | `Mandatory Label\High Mandatory Level` | Административный доступ к файловой системе и реестру (с учетом ACL). Требует прав администратора. | Процесс, запущенный от имени Local Admin. |
| **System (Системный)** | `NT AUTHORITY\SYSTEM` | Полный контроль над ОС. Обходит большинство ACL. Имеет доступ к памяти всех процессов. | Службы Windows, `svchost.exe` (часто). |
| **Authenticated Users** | SID `S-1-5-11` | Группа, обозначающая любого, прошедшего аутентификацию. Часто используется в ACL для сетевых ресурсов. | `whoami /groups` показывает эту группу. |
| **Local System** | SID `S-1-5-18` | Специальная учетная запись с максимальными правами на локальной машине. Не имеет сетевого токена. | `getuid` в Meterpreter возвращает `NT AUTHORITY\SYSTEM`. |

Контекст пользователя также включает в себя **сессию (Session ID)**. В современных версиях Windows (Vista и новее) сессии изолированы. Процесс в сессии 0 (обычно службы) не может взаимодействовать с GUI в сессии 1 (рабочий стол пользователя). Это ограничение влияет на выбор методов эксплуатации: например, инъекция DLL в процесс сессии 0 не позволит атакующему увидеть графический интерфейс, но позволит перехватывать сетевой трафик или управлять службами.

Разведка контекста начинается с ответа на вопросы: «Кто я?», «В какой группе я состою?», «Какие привилегии у меня есть?» и «Какой уровень целостности у моего процесса?». Ошибкой является предположение, что наличие имени администратора в группе `Administrators` автоматически дает полный контроль. Из-за UAC (User Account Control) токен администратора разделяется на два: фильтр-токен (без прав администратора) и полный токен (с правами). Если процесс запущен без повышения прав, он работает с низким подмножеством прав администратора, что ограничивает возможности локального повышения привилегий.

## Внутреннее устройство привилегий и токенов доступа

Привилегии в Windows — это системные разрешения, связанные с токеном безопасности процесса. Они не зависят от прав доступа (ACL) к объектам, а определяют способность процесса взаимодействовать с ядром ОС. Например, право `SeDebugPrivilege` позволяет процессу открывать дескрипторы других процессов, даже если ACL запрещает это. Без этого права даже администратор не сможет использовать инструменты вроде Process Explorer для просмотра памяти чужих процессов.

Структура токена доступа в Windows включает несколько ключевых полей, которые определяют контекст выполнения. Токен создается при входе пользователя в систему и модифицируется при повышении прав (UAC) или при использовании функции `ImpersonateNamedPipeClient`.

Ниже представлена структурная схема токена доступа (упрощенная модель, основанная на внутренней структуре `EPROCESS->Token` в ядре Windows, доступной через документацию Microsoft и анализ драйверов).

```json
{
  "Token": {
    "TokenId": "<GUID токена>",
    "AuthenticationId": "<SID аутентификации, связанный с логин-сессией>",
    "PrimaryGroupId": "<SID основной группы пользователя>",
    "IntegrityLevel": "<Low / Medium / High / System>",
    "MandatoryPolicy": "<0: No Restriction / 1: Mandatory / 2: Audit / 3: Mandatory + Audit>",
    "Privileges": [
      {
        "Luid": "<Локальный уникальный идентификатор привилегии>",
        "Name": "<Название, напр. SeDebugPrivilege>",
        "Attributes": "<0: Disabled / 2: Enabled / 4: Enabled by Default>"
      }
    ],
    "Groups": [
      {
        "Sid": "<SID группы>",
        "Attributes": "<0: Used for access / 16: Enabled / 32: Enabled and Mandatory>"
      }
    ],
    "OwnerSid": "<SID владельца токена>",
    "DefaultDacl": "<Дескриптор по умолчанию для создаваемых объектов>"
  }
}
```

Ключевым механизмом контроля привилегий является **Mandatory Integrity Control (MIC)**. Он предотвращает запись процессов с низким уровнем целостности в области с высоким уровнем. Однако MIC не защищает от процессов с высоким уровнем целостности, записывающих в области с низким. Это используется в атаках типа «перехват сессии», когда вредоносный код с высоким уровнем целостности внедряется в процесс с низким (например, браузер), чтобы обойти ограничения записи.

Привилегии делятся на две категории: **User Rights** (права входа, например, `SeInteractiveLogonRight`) и **Privileges** (системные права, например, `SeBackupPrivilege`). На этапе пост-эксплуатации атакующий фокусируется на `Privileges`, так как они позволяют обходить стандартные механизмы защиты.

Список основных привилегий, критичных для повышения привилегий (Privilege Escalation):

1.  **SeDebugPrivilege**: Позволяет открывать процессы других пользователей. Критично для инъекции кода и дампа памяти (LSASS).
2.  **SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege**: Позволяет имперсонировать токен клиента. Используется в атаках типа PrintNightmare, JuicyPotato, RoguePotato.
3.  **SeBackupPrivilege / SeRestorePrivilege**: Позволяет читать/писать файлы, игнорируя ACL. Используется для дампа SAM-базы или файлов реестра.
4.  **SeLoadDriverPrivilege**: Позволяет загружать драйверы ядра. Используется для установки rootkit-драйверов или обхода UAC через загрузку недоверенного драйвера.
5.  **SeTcbPrivilege**: Дает право действовать как часть операционной системы. Аналогично `SeImpersonate`, но с более широкими правами.
6.  **SeCreateTokenPrivilege**: Позволяет создавать новые токены. Редко встречается в стандартных конфигурациях, но критично для полного контроля.
7.  **SeTakeOwnershipPrivilege**: Позволяет менять владельца объекта. После этого можно дать себе полный контроль (ACL).

Проверка наличия этих привилегий является первым шагом в оценке вектора атаки. Если у пользователя нет `SeDebugPrivilege`, атака через инъекцию в LSASS невозможна без предварительного повышения прав. Если нет `SeImpersonatePrivilege`, атаки на основе токенов (JuicyPotato) не сработают.

## Применение и работа с предметом: Инструменты и методы разведки

На практике разведка контекста пользователя и привилегий выполняется с помощью комбинации нативных утилит Windows и специализированных фреймворков. Нативные утилиты предпочтительны на ранних этапах для минимизации артефактов (Living off the Land), в то время как специализированные инструменты (WinPEAS, PowerUp) используются для глубокого анализа.

### 1. Базовая идентификация и проверка привилегий

Команда `whoami` является базовой, но её расширенные версии дают больше информации.

```powershell
# Проверка текущего пользователя и группы
whoami /all

# Проверка только привилегий
whoami /priv

# Проверка уровня целостности
whoami /groups | findstr "Mandatory"
```

Вывод `whoami /priv` показывает список привилегий и их статус (Disabled/Enabled). Атакующий ищет привилегии со статусом `Enabled`. Если привилегия есть, но отключена, её можно включить с помощью `RtlAdjustPrivilege` (в WinPEAS) или `AdjustTokenPrivileges` (в PowerShell).

### 2. Анализ прав доступа к объектам (ACL)

Многие векторы повышения привилегий основаны на слабых разрешениях (Weak ACLs) на файлы, реестр или сервисы. Утилита `accesschk` из набора Sysinternals является стандартом для проверки прав.

```bash
# Проверка прав на сервисы (можно ли изменить бинарник сервиса)
accesschk.exe -uwcqv "Authenticated Users" * /accepteula

# Проверка прав на ключи реестра (можно ли записать в путь запуска сервиса)
accesschk.exe -uvwqk HKLM\System\CurrentControlSet\Services\* /accepteula
```

Если `Authenticated Users` или `BUILTIN\Users` имеют права `CHANGE` или `FULL CONTROL` над сервисом, это позволяет изменить путь к исполняемому файлу сервиса и выполнить код от имени SYSTEM при перезапуске сервиса.

### 3. Автоматизированная разведка с помощью WinPEAS

WinPEAS (Windows Privilege Escalation Awesome Scripts) — это инструмент, который объединяет сотни проверок в одном бинарнике. Он проверяет:
*   Неименованные сервисы (Unquoted Service Paths).
*   Слабые разрешения реестра.
*   Уязвимые бинарники (можно ли перезаписать EXE-файл).
*   Ключи автозагрузки.
*   Скрытые учетные записи.
*   Уязвимые драйверы.

Запуск WinPEAS в контексте текущего пользователя:

```powershell
# Запуск WinPEAS в тихом режиме с выводом в HTML
.\winPEAS.exe quiet html
```

Результатом является HTML-файл, содержащий все найденные уязвимости. Атакующий анализирует разделы "Interesting Findings" и "Vulnerabilities".

### 4. Разведка через PowerShell и WMI

PowerShell предоставляет доступ к WMI (Windows Management Instrumentation), что позволяет получать информацию о системе без запуска внешних бинарников.

```powershell
# Получение информации о патчах (для поиска уязвимостей)
Get-CimInstance -ClassName Win32_QuickFixEngineering | Select-Object HotFixID, InstalledOn

# Проверка прав на сервисы через PowerShell
Get-CimInstance -ClassName Win32_Service | Where-Object { $_.StartMode -eq "Auto" } | ForEach-Object {
    $path = $_.PathName
    if ($path -and (Test-Path $path)) {
        $acl = Get-Acl $path
        $acl.Access | Where-Object { $_.IdentityReference -match "Users|Everyone|Authenticated" }
    }
}
```

Этот код проверяет все сервисы с режимом запуска `Auto` и выводит ACL для их бинарных файлов. Если пользователь имеет права на запись, он может заменить бинарник.

## Сквозной практический пример: Разведка и выявление вектора повышения привилегий

**Исходные условия:**
Атакующий получил обратный шелл (reverse shell) от имени пользователя `jdoe` на Windows Server 2019. Пользователь `jdoe` входит в локальную группу `Administrators`, но процесс запущен с уровнем целостности `Medium` (из-за отсутствия UAC-повышения). Цель — определить, можно ли повысить привилегии до `SYSTEM` без использования внешних эксплойтов, основываясь на текущем контексте.

**Шаг 1: Проверка текущего контекста и привилегий**

Действие: Определение текущего пользователя, группы и привилегий.

```powershell
whoami /all
```

Ожидаемый вывод:
```text
ИМЯ: jdoe
ГРУППЫ:
Name                     Type             SID          Attributes
======================== ================ ============ ==================================================
Everyone                 Well-known group S-1-1-0      Mandatory, Enabled, Group
BUILTIN\Administrators   Alias            S-1-5-32-544 Mandatory, Enabled, Group, Used as default
NT AUTHORITY\SYSTEM      Well-known group S-1-5-18    Mandatory, Enabled, Group
...

ПРИВИЛЕГИИ:
Name                             Description                    State
===============================  ============================== =====
SeShutdownPrivilege              Shut down the system           Disabled
SeChangeNotifyPrivilege          Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege    Increase a process working set Disabled
```

Анализ: Пользователь `jdoe` является администратором, но процесс работает с `Medium Integrity`. Привилегия `SeDebugPrivilege` отсутствует. Это означает, что инъекция в LSASS невозможна напрямую. Однако наличие в группе `Administrators` дает возможность запустить процесс с высоким уровнем целостности, если будет найден способ обойти UAC или если сервис запустит процесс от имени SYSTEM.

**Шаг 2: Проверка слабых разрешений на сервисы**

Действие: Поиск сервисов, путь к которым не заключен в кавычки (Unquoted Service Path) или над которыми есть слабые ACL.

```powershell
# Использование accesschk для поиска сервисов с правами на запись у пользователей
accesschk.exe -uwcqv "Authenticated Users" * /accepteula | findstr /i "SERVICE_ALL_ACCESS"
```

Ожидаемый вывод:
```text
SERVICE_ALL_ACCESS
  MyCustomService
```

Анализ: Найдена служба `MyCustomService`, над которой у `Authenticated Users` есть полный доступ. Теперь нужно проверить путь к бинарному файлу этой службы.

```powershell
reg query HKLM\SYSTEM\CurrentControlSet\Services\MyCustomService /v ImagePath
```

Ожидаемый вывод:
```text
ImagePath    REG_EXPAND_SZ    C:\Program Files\MyApp\myapp.exe
```

Анализ: Путь не содержит кавычек. Если в папке `C:\Program Files\MyApp\` есть пробел, Windows будет искать `C:\Program.exe` перед `Files\MyApp\myapp.exe`. Если атакующий может создать файл `C:\Program.exe`, он будет выполнен от имени SYSTEM при перезапуске службы.

**Шаг 3: Проверка наличия привилегии SeImpersonatePrivilege**

Действие: Проверка, есть ли у текущего пользователя право имперсонировать токен.

```powershell
whoami /priv | findstr /i "SeImpersonate"
```

Ожидаемый вывод:
```text
SeImpersonatePrivilege       Impersonate a client after authentication   Enabled
```

Анализ: Привилегия `SeImpersonatePrivilege` активна. Это открывает вектор атаки через токены (например, JuicyPotato, RoguePotato), даже если пользователь не является администратором в полном смысле (если он в группе `Administrators`, это работает еще надежнее).

**Шаг 4: Проверка уязвимых драйверов**

Действие: Поиск драйверов, которые можно перезаписать или загрузить.

```powershell
# Поиск драйверов с правами на запись у пользователей
accesschk.exe -uwcqv "Authenticated Users" C:\Windows\System32\drivers\* /accepteula | findstr /i "FILE_ALL_ACCESS"
```

Ожидаемый вывод:
```text
FILE_ALL_ACCESS
  C:\Windows\System32\drivers\vulnerable.sys
```

Анализ: Драйвер `vulnerable.sys` имеет слабые права. Атакующий может заменить его на свой драйвер и загрузить через `sc.exe`, получив контроль над ядром (Ring 0).

**Ожидаемый вывод:**
На основе разведки выявлены три вектора повышения привилегий:
1.  **Unquoted Service Path** для `MyCustomService`.
2.  **SeImpersonatePrivilege** для атаки через токены.
3.  **Слабые права на драйвер** `vulnerable.sys`.

Атакующий выбирает вектор с наименьшим риском обнаружения. Например, замена бинарника сервиса может быть менее заметной, чем загрузка нового драйвера, который может вызвать BSOD или быть заблокирован EDR.

## Аналитический вывод

Контекст текущего пользователя и его привилегии являются фундаментальным элементом этапа пост-эксплуатации в Windows. Понимание структуры токена доступа, уровней целостности и специфических привилегий позволяет атакующему оценить потенциал для локального повышения привилегий. Разведка должна быть комплексной: она включает не только проверку `whoami`, но и анализ ACL на сервисы, реестр и файлы, а также проверку наличия специфических прав, таких как `SeImpersonatePrivilege` или `SeDebugPrivilege`. Использование автоматизированных инструментов, таких как WinPEAS, значительно ускоряет этот процесс, но требует понимания underlying-механизмов для интерпретации результатов. Для защитников мониторинг выполнения команд `whoami`, `accesschk` и запуск подозрительных процессов с высоким уровнем целостности является ключевым индикатором компрометации.

## Источники

*   [Inside Post-Exploitation: Techniques and Tactics - ExamCollection](https://www.examcollection.com/blog/inside-post-exploitation-techniques-and-tactics/)
*   [Privilege Escalation in Windows for OSCP | InfoSec Write-ups](https://infosecwriteups.com/privilege-escalation-in-windows-380bee3a2842)
*   [Local privilege escalation | InfoSec Notes](https://notes.qazeer.io/windows/local_privilege_escalation)
*   [Post-Exploitation Persistence Techniques - Securium Solutions](https://securiumsolutions.com/post-exploitation-persistence-techniques/)
*   [Post Exploitation in Windows 7 (EternalBlue) - GeeksforGeeks](https://www.geeksforgeeks.org/ethical-hacking/post-exploitation-in-windows-7-eternalblue/)
*   [Detecting exploitation for privilege escalation (T1068) - ManageEngine](https://www.manageengine.com/log-management/mitre-attack/privilege-escalation/exploitation-for-privilege-escalation.html)
*   [Повышение привилегий в Windows: разведка и эксплойты - Codeby](https://codeby.net/threads/metody-povysheniya-privilegii-v-windows-gaid-po-recon.84656/)
*   [Windows Enumeration and Exploitation - Davis CyberSec](https://daviscybersec.org/2024-summer/windows-enumeration-exploitation/)
*   [Windows Post Exploitation 12.2 - mrw0r57](https://mrw0r57.github.io/2020-06-03-Windows-Post-Exploitation-12.2/)
*   [Top 10 post-exploitation tools threat actors use in real intrusions - ThreatLocker](https://www.threatlocker.com/blog/top-post-exploitation-tools-threat-actors-use)
*   [Post-exploitation - Stony Brook University](https://www3.cs.stonybrook.edu/~mikepo/CSE509/2023/lectures/CSE509_2023_lecture_16_post-exploitation.pdf)