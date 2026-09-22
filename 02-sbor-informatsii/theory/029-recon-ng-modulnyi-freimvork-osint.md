# Recon-ng: Архитектура, модульность и применение в OSINT-разведке

## Контекст и базовые понятия

Recon-ng (Reconnaissance Framework) — это фреймворк для сбора открытых источников информации (OSINT), сфокусированный на веб-разведке. В отличие от универсальных фреймворков, таких как Metasploit (эксплуатация) или Social-Engineer Toolkit (социальная инженерия), Recon-ng специализируется исключительно на этапе разведки в цикле тестирования на проникновение. Инструмент написан на Python и использует SQLite в качестве встроенной базы данных для хранения результатов.

Ключевая особенность Recon-ng — модульная архитектура. Функциональность не вшита в ядро, а реализуется через независимые скрипты (модули), которые загружаются в сессию. Это позволяет расширять возможности инструмента без обновления ядра, а также изолировать логику сбора данных. Фреймворк предоставляет среду, похожую на Metasploit (CLI с автодополнением, контекстная помощь), что снижает порог входа для специалистов, знакомых с экосистемой Rapid7.

В контексте кибербезопасности важно разграничивать понятия **OSINT** и **Web Reconnaissance**. OSINT — это методология сбора информации из любых открытых источников (соцсети, форумы, базы данных, публичные реестры). Web Reconnaissance — это подмножество OSINT, ориентированное на техническую инфраструктуру: DNS, SSL-сертификаты, поддомены, IP-адреса, открытые порты и сервисы. Recon-ng позиционируется как инструмент для *web-based* OSINT, то есть он автоматизирует сбор технических артефактов из публичных API и поисковых систем.

Существует путаница между Recon-ng и другими инструментами разведки, такими как `theHarvester` или `Maltego`. `theHarvester` — это скрипт, собирающий данные из ограниченного набора источников (поисковики, сертификаты) и выводящий их в консоль без глубокой структуризации. Maltego — это графический инструмент для визуализации связей между сущностями. Recon-ng занимает промежуточное положение: он предлагает программный интерфейс для автоматизации цепочек сбора данных (chaining) и сохраняет результаты в реляционной базе данных, что позволяет выполнять сложные SQL-запросы к собранным данным.

| Характеристика | Recon-ng | Metasploit Framework | theHarvester | Maltego |
| :--- | :--- | :--- | :--- | :--- |
| **Основная цель** | Сбор OSINT (Web Recon) | Эксплуатация уязвимостей | Сбор контактов/доменов | Визуализация связей |
| **Интерфейс** | CLI (Python) | CLI (Ruby) | CLI (Python) | GUI (Java) |
| **Хранение данных** | Встроенная SQLite БД | БД Metasploit (PostgreSQL) | Временные файлы/консоль | Graph Database |
| **Модульность** | Высокая (Marketplace) | Высокая (Modules/Plugins) | Низкая (Скрипты) | Высокая (Transforms) |
| **Фокус** | Пассивная и активная разведка | Активная эксплуатация | Пассивная разведка | Анализ данных |
| **Типичное применение** | Подготовительный этап пентеста | Этап эксплуатации | Первичный сбор контактов | Глубокий анализ связей |

Recon-ng не предназначен для эксплуатации уязвимостей. Его задача — минимизировать время на сбор информации, предоставляя структурированные данные для последующего анализа или передачи в другие инструменты (например, Nmap, Burp Suite).

## Внутреннее устройство предмета

Recon-ng представляет собой микроядро, управляющее жизненным циклом модулей, и систему управления данными. Архитектура строится на трех основных компонентах: ядро (Core), модули (Modules) и база данных (Database).

### Ядро и среда выполнения

Ядро предоставляет командную оболочку (shell) и управляет состоянием сессии. Оно обрабатывает глобальные команды (`workspaces`, `keys`, `marketplace`) и делегирует выполнение задач загруженным модулям. Ключевой механизм ядра — **Workspace** (рабочее пространство). Workspace изолирует данные разных проектов. Все таблицы базы данных, загруженные модули и API-ключи привязаны к текущему workspace. Это позволяет вести разведку для нескольких клиентов параллельно без риска смешивания данных.

### Модульная система

Модули — это Python-скрипты, наследующие базовый класс `Module`. Каждый модуль описывает:
1.  **Метаданные:** имя, описание, автор, лицензия.
2.  **Опции:** параметры, необходимые для работы (например, `SOURCE` для домена или `API_KEY` для сервиса).
3.  **Логику:** метод `do_run()`, который содержит основной код сбора данных.
4.  **Схему данных:** определение таблиц, в которые модуль будет записывать результаты.

Модули группируются в категории (например, `recon/domains-hosts/`, `recon/hosts-ports/`). Фреймворк включает встроенный **Marketplace** — репозиторий модулей, доступный из командной строки. Это позволяет устанавливать новые источники данных без ручного копирования файлов.

### База данных и схема

Recon-ng использует SQLite. Схема данных динамически расширяется модулями. Базовые сущности включают:
*   `domains`: список целевых доменов.
*   `hosts`: IP-адреса и имена хостов.
*   `contacts`: адреса электронной почты.
*   `credentials`: учетные данные (если найдены в утечках).

Модули могут создавать собственные таблицы или расширять существующие. Данные из разных модулей могут быть связаны через внешние ключи (например, `host_id` связывает IP с доменом).

### Управление API-ключами

Многие модули требуют доступа к сторонним API (Shodan, Bing, Google, GitHub). Recon-ng предоставляет безопасный менеджер ключей (`keys`), который шифрует и хранит их в локальном файле `keys.db`. Модули получают доступ к ключам через API ядра, не имея прямого доступа к исходному коду хранилища.

| Компонент | Функция | Техническая реализация |
| :--- | :--- | :--- |
| **Workspace** | Изоляция проектов | Временные базы данных SQLite, контекст сессии |
| **Module** | Сбор данных | Python-классы, наследующие `recon.core.Module` |
| **Marketplace** | Распределение модулей | HTTP-запросы к GitHub-репозиторию, Git-клонирование |
| **Database** | Хранение и запросы | SQLite, ORM-подобный интерфейс `db` |
| **Keys** | Управление секретами | Шифрование AES, файл `keys.db` |
| **Reporting** | Экспорт результатов | Генераторы CSV, JSON, XML, HTML |

Архитектура позволяет модулям передавать данные друг другу. Например, модуль `recon/domains-hosts/brute_hosts` может найти поддомены, а модуль `recon/hosts-ports/shodan_ip` может использовать эти поддомены для поиска открытых портов. Эта связность достигается через общую базу данных workspace.

## Применение и работа с предметом

Работа с Recon-ng строится вокруг типичного пайплайна разведки: создание окружения → установка модулей → добавление цели → запуск сбора → анализ данных.

### Инициализация и управление окружением

Перед началом работы необходимо создать workspace. Это гарантирует, что данные не пересекутся с предыдущими проектами.

```bash
# Создание и переключение в новое рабочее пространство
[recon-ng][default] > workspaces create target_alpha
[recon-ng][target_alpha] >
```

Проверка текущего контекста и списка доступных пространств:

```bash
# Просмотр активных пространств
[recon-ng][target_alpha] > workspaces list
```

### Управление модулями и API-ключами

Модули не загружаются по умолчанию. Их необходимо установить из Marketplace и загрузить в сессию.

```bash
# Поиск модуля для сбора поддоменов через Bing
[recon-ng][target_alpha] > marketplace search bing

# Установка найденного модуля
[recon-ng][target_alpha] > marketplace install recon/domains-hosts/bing_domain_web

# Загрузка модуля в активную сессию
[recon-ng][target_alpha] > modules load recon/domains-hosts/bing_domain_web
```

Для работы модуля часто требуется API-ключ. Ключи добавляются глобально для workspace.

```bash
# Добавление ключа Shodan (замените YOUR_KEY на реальный ключ)
[recon-ng][target_alpha] > keys add shodan_api YOUR_KEY

# Проверка списка ключей
[recon-ng][target_alpha] > keys list
```

### Выполнение разведки и цепочка модулей

Типичный процесс включает добавление целевого домена и запуск модулей. Модули могут работать автономно или передавать данные друг другу.

```bash
# Добавление целевого домена в базу данных
[recon-ng][target_alpha] > db insert domains domain=example.com

# Проверка добавленных доменов
[recon-ng][target_alpha] > show domains

# Настройка опций модуля
[recon-ng][bing_domain_web] > show options
Module options (recon/domains-hosts/bing_domain_web):

   Name     Current Value  Required  Description
   ------   -------------  --------  -----------
   SOURCE   example.com    yes       Domain to search

# Запуск модуля
[recon-ng][bing_domain_web] > run
```

После выполнения модуля результаты сохраняются в БД. Для анализа данных используются команды `show` и `db`.

```bash
# Просмотр собранных хостов
[recon-ng][bing_domain_web] > show hosts

# Экспорт результатов в CSV для дальнейшего анализа
[recon-ng][bing_domain_web] > export csv /tmp/recon_hosts.csv
```

### Типичные ошибки и подводные камни

1.  **Отсутствие API-ключей:** Многие модули возвращают пустые результаты, если не настроены ключи. Всегда проверяйте `keys list` перед запуском.
2.  **Игнорирование rate-limiting:** Агрессивный запуск модулей может привести к блокировке IP-адреса на стороне провайдера API. Рекомендуется использовать модули с поддержкой пауз или запускать их в фоновом режиме.
3.  **Путаница в схемах БД:** Модули могут создавать таблицы с одинаковыми именами, но разными структурами. Перед экспортом данных используйте `db schema` для понимания структуры.
4.  **Незакрытие workspace:** При завершении работы не забывайте переключаться в другой workspace или удалять временные, чтобы избежать утечки данных.

## Сквозной практический пример: Автоматизированный сбор инфраструктуры домена

**Исходные условия:**
*   **Среда:** Kali Linux с установленным Recon-ng.
*   **Роль:** Пентестер, проводящий внешнюю разведку.
*   **Цель:** `target-site.com`.
*   **Инструменты:** Recon-ng, API-ключ Shodan (предварительно получен и добавлен).
*   **Сценарий:** Сбор поддоменов, разрешение IP-адресов и поиск открытых сервисов.

### Шаг 1: Создание workspace и добавление цели

Создаем изолированное окружение и добавляем корневой домен в базу данных.

```bash
# Создание workspace
[recon-ng][default] > workspaces create infra_recon

# Добавление домена
[recon-ng][infra_recon] > db insert domains domain=target-site.com

# Проверка наличия домена
[recon-ng][infra_recon] > show domains
+---------------------+
| domains             |
+---------------------+
| target-site.com     |
+---------------------+
```

### Шаг 2: Установка и загрузка модуля brute_hosts

Используем модуль для перебора поддоменов (DNS brute-force).

```bash
# Установка модуля
[recon-ng][infra_recon] > marketplace install recon/domains-hosts/brute_hosts

# Загрузка модуля
[recon-ng][infra_recon] > modules load recon/domains-hosts/brute_hosts

# Просмотр опций
[recon-ng][brute_hosts] > show options
Module options (recon/domains-hosts/brute_hosts):

   Name     Current Value  Required  Description
   ------   -------------  --------  -----------
   SOURCE   target-site.com yes      Domain to brute force
   WORDLIST /usr/share... yes      Path to wordlist
```

### Шаг 3: Запуск brute-force и разрешение хостов

Запускаем перебор. После завершения, загружаем модуль `resolve` для получения IP-адресов.

```bash
# Запуск перебора
[recon-ng][brute_hosts] > run
[*] 10.0.0.1 - mail.target-site.com
[*] 10.0.0.2 - dev.target-site.com
[*] 10.0.0.3 - api.target-site.com

# Загрузка модуля разрешения
[recon-ng][brute_hosts] > modules load recon/domains-hosts/resolve

# Настройка источника (берет данные из БД автоматически)
[recon-ng][resolve] > show options
Module options (recon/domains-hosts/resolve):

   Name     Current Value  Required  Description
   ------   -------------  --------  -----------
   SOURCE   target-site.com yes      Domain to resolve

# Запуск разрешения
[recon-ng][resolve] > run
[*] Resolved mail.target-site.com -> 10.0.0.1
[*] Resolved dev.target-site.com -> 10.0.0.2
```

### Шаг 4: Поиск сервисов через Shodan

Используем модуль Shodan для поиска открытых портов и сервисов на найденных IP.

```bash
# Установка и загрузка модуля Shodan
[recon-ng][resolve] > marketplace install recon/hosts-ports/shodan_ip
[recon-ng][resolve] > modules load recon/hosts-ports/shodan_ip

# Проверка наличия ключа
[recon-ng][shodan_ip] > keys list
+------------+------------------+
| Key        | Value            |
+------------+------------------+
| shodan_api | YOUR_SHODAN_KEY  |
+------------+------------------+

# Запуск модуля
[recon-ng][shodan_ip] > run
[*] 10.0.0.1:25 (SMTP)
[*] 10.0.0.1:80 (HTTP)
[*] 10.0.0.2:443 (HTTPS)
```

### Шаг 5: Экспорт результатов

Выгрузка данных для отчета.

```bash
# Экспорт хостов и сервисов
[recon-ng][shodan_ip] > export csv /tmp/infra_recon_results.csv
```

**Ожидаемый вывод:**
В результате выполнения шагов 1–5 в workspace `infra_recon` формируется полная карта инфраструктуры: список поддоменов, их IP-адреса и открытые сервисы. Данные доступны для SQL-запросов или экспорта в CSV. Пример вывода `show hosts`:

```bash
[recon-ng][shodan_ip] > show hosts
+---------------------+------------------+
| host                | ip_address       |
+---------------------+------------------+
| mail.target-site.com| 10.0.0.1         |
| dev.target-site.com | 10.0.0.2         |
| api.target-site.com | 10.0.0.3         |
+---------------------+------------------+
```

Этот пример демонстрирует ключевое преимущество Recon-ng: автоматизацию цепочки задач (домен → поддомены → IP → сервисы) в единой среде с сохранением контекста.

## Аналитический вывод

Recon-ng представляет собой мощный инструмент для автоматизации веб-разведки благодаря своей модульной архитектуре и встроенной базе данных. Его главное преимущество — способность связывать данные из различных источников (DNS, API, поисковые системы) в единую графовую структуру, что позволяет выявлять скрытые связи и расширять поверхность атаки. Интерфейс, похожий на Metasploit, делает его удобным для специалистов, уже работающих с экосистемой Linux и пентестинга.

Однако использование Recon-ng требует понимания принципов работы API и ограничений rate-limiting. Многие модули зависят от внешних сервисов, которые могут изменять свои условия доступа или требовать платных подписок. Кроме того, фреймворк не заменяет глубокий анализ трафика или ручную разведку, а служит инструментом для первичного сбора и структурирования данных. Для эффективного применения необходимо комбинировать Recon-ng с другими инструментами (Nmap, Burp Suite, custom scripts) и тщательно настраивать workspace для обеспечения изоляции и безопасности собранных данных.

## Источники

1.  [An overview of Recon-ng, command list & domain OSINT workflow](https://nativenode.io/an-overview-of-recon-ng-command-list-domain-osint-workflow/)
2.  [Comprehensive Guide to Recon-ng for Reconnaissance](https://www.test-king.com/blog/comprehensive-guide-to-recon-ng-for-reconnaissance/)
3.  [GitHub - lanmaster53/recon-ng](https://github.com/lanmaster53/recon-ng)
4.  [What is Recon-ng | Cybersecurity Glossary | CyCognito](https://www.cycognito.com/glossary/recon-ng.php)
5.  [Recon-ng: A Powerful Reconnaissance Tool for Hackers](https://darkmarc.substack.com/p/recon-ng-a-powerful-reconnaissance)
6.  [Beginners guide to Recon-ng](https://hackercoolmagazine.com/beginners-guide-to-recon-ng/?srsltid=AfmBOoqvNHhWWZsFWQPJK8zt1pU66Km8YbVEc0fq0L4Z7lk22KKWVBxX)
7.  [Open Source Intelligence (OSINT), Part 02: recon-ng to Identify the Same User on Multiple Platforms](https://hackers-arise.com/open-source-intelligence-osint-part-2-recon-ng-to-identify-the-same-user-on-multiple-platforms/)
8.  [Recon-NG Tutorial | HackerTarget.com](https://hackertarget.com/recon-ng-tutorial/)
9.  [Mastering Recon-ng: The Complete OSINT Guide for Ethical Hackers](https://medium.com/@rajkumarkumawat/mastering-recon-ng-the-complete-osint-guide-for-ethical-hackers-226b352fbf5b)
10. [Топ-инструменты для OSINT-разведки: подробный обзор](https://www.securitylab.ru/blog/personal/Technolady/354845.php)
11. [Getting Started with Recon-ng: The Ultimate Reconnaissance Framework for Ethical Hackers](https://medium.com/@simran.malakar/getting-started-with-recon-ng-the-ultimate-reconnaissance-framework-for-ethical-hackers-56e9f433fe68)
12. [Recon-ng Information gathering tool in Kali Linux - GeeksforGeeks](https://www.geeksforgeeks.org/linux-unix/recon-ng-installation-on-kali-linux/)