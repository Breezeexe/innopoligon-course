# OWASP ZAP как open-source альтернатива Burp Suite: Архитектура, функционал и применение в пентесте

## Контекст и базовые понятия

OWASP ZAP (Zed Attack Proxy) представляет собой инструмент динамического тестирования безопасности приложений (DAST), разработанный проектом OWASP. Его основная функция заключается в автоматизированном и ручном поиске уязвимостей в веб-приложениях и API путем перехвата, анализа и модификации HTTP/HTTPS трафика между браузером тестировщика и целевым сервером. В отличие от статического анализа (SAST), который изучает исходный код, ZAP работает с работающим приложением, что позволяет выявлять ошибки конфигурации, уязвимости времени выполнения и логические дефекты, недоступные для статического анализа.

Ключевое различие между ZAP и Burp Suite заключается в модели лицензирования и экосистеме. Burp Suite (PortSwigger) имеет коммерческую модель с бесплатной Community Edition, которая ограничивает функционал автоматизации (например, сканирование в одном потоке). ZAP распространяется под лицензией Apache 2.0, что делает его полностью бесплатным для любого использования, включая коммерческое. Это определяет сферу применения: ZAP является стандартом де-факто для open-source CI/CD пайплайнов, образовательных целей и проектов с ограниченным бюджетом, тогда как Burp Suite остается индустриальным стандартом для ручного пентеста благодаря более зрелому интерфейсу и глубокой интеграции инструментов.

Важно разграничивать понятия **Intercepting Proxy** и **DAST Scanner**. ZAP объединяет обе функции. В режиме прокси он выступает как Man-in-the-Middle (MitM), позволяя инспектировать пакеты. В режиме сканера он использует данные прокси или собственный движок (Spider) для автоматического обхода приложения и запуска атакующих тестов (Active Scan). Burp Suite также выполняет обе роли, но разделяет их на разные модули (Proxy, Intruder, Scanner) с разной степенью автоматизации.

| Характеристика | OWASP ZAP | Burp Suite (Community/Professional) |
| :--- | :--- | :--- |
| **Лицензия** | Apache 2.0 (Open Source) | Proprietary (Freemium / Commercial) |
| **Основной фокус** | Автоматизация, CI/CD, доступность | Ручной пентест, глубокий анализ |
| **Архитектура** | Java (Desktop), Docker, CLI, API | Java (Desktop), API, Extensions |
| **Активное сканирование** | Встроенный движок (Multi-threaded) | Community: 1 поток; Pro: Multi-threaded |
| **Расширяемость** | Add-ons (Java/Python/Groovy), API | Extensions (Java/Python/BurpScripting) |
| **Интеграция в CI/CD** | Нативная (Docker, API, CLI) | Возможна (Pro API, ZAP API аналог) |
| **Стоимость** | 0 USD | 475 USD/год (Pro) |
| **Поддержка** | Сообщество, Checkmarx (спонсор) | PortSwigger (коммерческая поддержка) |

ZAP также позиционируется как инструмент для разработчиков (Shift Left), позволяя интегрировать проверку безопасности на ранних этапах разработки. В то время как Burp Suite чаще используется специалистами по безопасности (AppSec Engineers, Pentesters) для глубокого аудита. Оба инструмента используют одинаковые принципы работы с трафиком, что делает переход между ними относительно плавным для специалистов, знающих HTTP-протокол.

## Внутреннее устройство предмета

OWASP ZAP представляет собой сложную систему, состоящую из нескольких взаимосвязанных компонентов. Архитектура ZAP построена вокруг ядра на базе Java, которое обеспечивает кроссплатформенность. Основные компоненты включают:

1.  **ZAP Core (Engine):** Обрабатывает логику перехвата, маршрутизации и модификации HTTP-запросов.
2.  **Spider (Crawler):** Движок обхода, который строит карту приложения (Site Map), исследуя ссылки, формы и API-эндпоинты.
3.  **Active Scanner:** Движок атакующих тестов, который отправляет вредоносные payloads в найденные точки входа (параметры, заголовки, тело запроса).
4.  **Passive Scanner:** Анализирует проходящий трафик в реальном времени на наличие паттернов уязвимостей (например, отсутствие заголовков безопасности, передача чувствительных данных в URL).
5.  **API:** RESTful API, позволяющий управлять всеми функциями ZAP удаленно, что критично для автоматизации.
6.  **Add-ons:** Пакеты расширений, загружаемые из ZAP Marketplace, которые добавляют новый функционал (например, специфичные проверки для GraphQL, OAuth).

### Архитектура и потоки данных

ZAP работает как прокси-сервер, обычно на порту `8080`. Браузер или скрипт отправляют запросы на этот прокси, который затем пересылает их на целевой сервер, перехватывая ответ.

```text
[Браузер / Клиент] ──(HTTP Request)──▶ [ZAP Proxy (8080)] ──(HTTP Request)──▶ [Целевой Сервер]
       ▲                                      │                              │
       │                                      ▼                              ▼
       │                              [ZAP Core]                      [Response]
       │                                   │                              │
       │                              [Passive]                         [Response]
       │                              [Scanner]                           │
       │                                   │                              │
       │                                   ▼                              │
[Отчет / Alert] ◀──────────────────── [Alerts DB] ◀──────────────────────┘
```

### Режимы работы

ZAP поддерживает четыре режима, определяющих уровень взаимодействия с пользователем:

1.  **Standard Mode:** Полноценный графический интерфейс (GUI) для ручного тестирования.
2.  **Daemon Mode:** Запуск в фоне без GUI, управление через API. Идеально для серверов.
3.  **Quick Start Mode:** Упрощенный интерфейс для быстрого запуска сканирования.
4.  **API Mode:** Полное управление через HTTP API (JSON). Используется в CI/CD.

### Сравнительная таблица ключевых компонентов ZAP

| Компонент | Функция | Ключевые признаки | Типичные индикаторы использования |
| :--- | :--- | :--- | :--- |
| **Site Map** | Дерево обхода приложения | Иерархия URL, методы (GET/POST), параметры | Визуализация attack surface |
| **Alerts** | Список найденных уязвимостей | Уровень риска (High/Med/Low), описание, URL | Фильтрация по риску, экспорт в CSV/JSON |
| **Spider** | Автоматический обход | Настройка глубины, домена, ограничений скорости | Построение карты для сканирования |
| **Active Scanner** | Генерация атак | Payloads, политики сканирования, многопоточность | Поиск SQLi, XSS, Command Injection |
| **Passive Scanner** | Анализ трафика | Правила анализа (Rules), пороговые значения | Обнаружение отсутствующих заголовков |
| **API** | Удаленное управление | REST endpoints (`/JSON`), аутентификация | Интеграция в Jenkins/GitLab CI |

### Структура алерта (уязвимости) в ZAP

Каждая найденная уязвимость в ZAP имеет структурированное представление. Понимание этой структуры критично для парсинга результатов в автоматизированных пайплайнах.

```json
{
  "alert": {
    "id": "12345",
    "name": "Cross-Site Scripting (Reflected)",
    "risk": "High",
    "confidence": "Medium",
    "description": "The value of the parameter 'q' is reflected in the response...",
    "solution": "Ensure that the data is correctly escaped...",
    "reference": "https://owasp.org/www-community/attacks/xss/",
    "cweid": "79",
    "wascid": "8",
    "sourceId": "1",
    "alertRef": "core-1",
    "param": "q",
    "attack": "<script>alert(1)</script>",
    "evidence": "<script>alert(1)</script>",
    "request": "GET /search?q=<script>alert(1)</script> HTTP/1.1...",
    "response": "HTTP/1.1 200 OK...",
    "pluginId": "10010"
  }
}
```

Поля `param`, `attack`, `evidence` и `request` являются ключевыми для верификации ложноположительных срабатываний. `pluginId` указывает на конкретное правило сканера, что позволяет отключать или настраивать определенные проверки.

## Применение и работа с предметом

На практике OWASP ZAP используется в двух основных сценариях: ручное тестирование (Manual Pentesting) и автоматизированное тестирование (Automated DAST). В ручном тестировании ZAP заменяет Burp Suite в роли прокси и инструмента для модификации запросов. В автоматизации он интегрируется в CI/CD пайплайны для непрерывной проверки безопасности.

### Ручное тестирование: Интерфейс и инструменты

Интерфейс ZAP разделен на панели: Sites, Alerts, Http History, Request/Response. Для ручного тестирования ключевыми инструментами являются:

1.  **Proxy:** Перехват и модификация запросов в реальном времени.
2.  **Repeater:** Инструмент для повторной отправки и модификации отдельных запросов (аналог Burp Repeater).
3.  **Intruder:** Инструмент для фаззинга (аналог Burp Intruder), но с более сложной настройкой для автоматизации.
4.  **Comparer:** Сравнение двух ответов для выявления различий (например, при blind SQLi).

Для настройки HTTPS-перехвата необходимо установить корневой сертификат ZAP (ZAP Root CA) в браузер. Без этого HTTPS-трафик не будет расшифрован, и сканирование будет неполным.

### Автоматизация: CLI и API

Для интеграции в CI/CD (Jenkins, GitLab CI, GitHub Actions) используется CLI-интерфейс или API. CLI позволяет запускать сканирование из командной строки без GUI.

**Типовая команда CLI для быстрого сканирования:**

```bash
zap.sh -cmd quickurl -url http://testphp.vulnweb.com -quickurl
```

Эта команда запускает ZAP в фоновом режиме, обходит указанный URL и сохраняет результаты в сессию. Для более сложного сценария используется API.

**Пример API-запроса на запуск активного сканирования:**

```bash
curl -X POST http://localhost:8080/JSON/ascan/action/scan/ \
  --data "url=http://testphp.vulnweb.com&scanPolicyName=Default"
```

Здесь `scanPolicyName` определяет, какие типы атак будут использованы. По умолчанию используется политика "Default", которая включает наиболее распространенные проверки.

### Настройка политик сканирования (Scan Policies)

ZAP позволяет настраивать политики сканирования, определяя, какие атаки выполнять, какие игнорировать и как часто отправлять запросы. Это критично для предотвращения DoS-эффекта на целевую систему.

**Структура политики сканирования (JSON):**

```json
{
  "scanPolicyName": "CustomPolicy",
  "maxDuration": "10",
  "rules": [
    {
      "id": "10010",
      "name": "Cross-Site Scripting (Reflected)",
      "enabled": true,
      "maxDepth": 10,
      "maxResults": 100
    },
    {
      "id": "10011",
      "name": "Cross-Site Scripting (Persistent)",
      "enabled": false
    }
  ]
}
```

Поле `enabled: false` позволяет отключать конкретные правила, если они вызывают ложные срабатывания или не релевантны для приложения.

### Типичные ошибки и подводные камни

1.  **Игнорирование HTTPS:** Без установки ZAP Root CA сканирование HTTPS-приложений будет некорректным.
2.  **Недостаточная настройка Spider:** По умолчанию Spider может быть слишком агрессивным или, наоборот, слишком медленным. Необходимо настраивать ограничения по домену и глубине.
3.  **Ложноположительные срабатывания:** ZAP, как и другие DAST-инструменты, генерирует ложноположительные результаты. Требуется ручная верификация.
4.  **Отсутствие контекста:** ZAP не понимает бизнес-логику приложения. Он может пропустить уязвимости, связанные с авторизацией, если не настроен правильный обход.

## Сквозной практический пример: Автоматизированное сканирование уязвимостей в CI/CD

**Исходные условия:**
*   **Среда:** Linux (Ubuntu 22.04), Docker.
*   **Цель:** Веб-приложение `http://testphp.vulnweb.com` (тестовый сайт Acunetix).
*   **Роль:** DevSecOps Engineer.
*   **Инструменты:** OWASP ZAP (Docker-образ), Bash, Curl.
*   **Сценарий:** Настройка автоматического сканирования в пайплайне с генерацией отчета в HTML и JSON.

### Шаг 1: Запуск ZAP в Docker-контейнере

Запускаем ZAP в режиме демона (без GUI) с сохранением сессии.

```bash
docker run -d --name zap \
  -p 8080:8080 \
  -v $(pwd)/zap_home:/home/zap/.ZAP_D \
  owasp/zap2docker-stable zap.sh -daemon -config api.key=secretkey
```

*   `-p 8080:8080`: Пробрасываем порт API.
*   `-v $(pwd)/zap_home:/home/zap/.ZAP_D`: Монтируем том для сохранения сессии и отчетов.
*   `-config api.key=secretkey`: Устанавливаем ключ API для аутентификации.

**Ожидаемый вывод:** Контейнер запускается, ZAP инициализируется, API становится доступным на `http://localhost:8080`.

### Шаг 2: Инициализация сессии и обход приложения (Spider)

Создаем новую сессию и запускаем Spider для обхода целевого приложения.

```bash
# Создание сессии
curl -X POST http://localhost:8080/JSON/core/action/newSession \
  --data "apikey=secretkey&sessionName=TestSession"

# Запуск Spider
curl -X GET "http://localhost:8080/JSON/spider/action/scan/?apikey=secretkey&url=http://testphp.vulnweb.com&maxDuration=5"
```

*   `maxDuration=5`: Ограничиваем время обхода 5 минутами.
*   Spider начнет обходить приложение, добавляя URL в Site Map.

**Ожидаемый вывод:** Возврат JSON с статусом `success`. В логах ZAP видно процесс обхода.

### Шаг 3: Запуск активного сканирования (Active Scan)

После завершения обхода запускаем активное сканирование для поиска уязвимостей.

```bash
curl -X POST http://localhost:8080/JSON/ascan/action/scan/ \
  --data "url=http://testphp.vulnweb.com&apikey=secretkey&scanPolicyName=Default"
```

*   `url`: URL для сканирования (должен быть в Site Map).
*   `scanPolicyName`: Используем политику по умолчанию.

**Ожидаемый вывод:** Возврат JSON с статусом `success`. Значок сканирования в интерфейсе ZAP (если бы он был запущен) начнет мигать.

### Шаг 4: Ожидание завершения и получение результатов

Проверяем статус сканирования и ждем его завершения.

```bash
# Проверка статуса
curl -X GET "http://localhost:8080/JSON/ascan/view/status/?apikey=secretkey&scanId=1"
```

*   `scanId`: ID сканирования, возвращенный на шаге 3.
*   Когда `status` достигает 100, сканирование завершено.

**Ожидаемый вывод:** `{"status": "100"}`.

### Шаг 5: Экспорт отчетов

Генерируем отчеты в форматах JSON и HTML.

```bash
# Экспорт в JSON
curl -X GET "http://localhost:8080/JSON/core/view/alerts/?apikey=secretkey&baseurl=http://testphp.vulnweb.com&format=json" > zap_alerts.json

# Экспорт в HTML
curl -X GET "http://localhost:8080/OTHER/core/other/htmlreport/?apikey=secretkey" > zap_report.html
```

*   `zap_alerts.json`: Содержит список всех уязвимостей в машиночитаемом формате.
*   `zap_report.html`: Человекочитаемый отчет.

**Ожидаемый вывод:** Файлы `zap_alerts.json` и `zap_report.html` сохраняются в текущей директории.

**Ожидаемый вывод примера:**
Пример фрагмента из `zap_alerts.json`:
```json
{
  "alerts": [
    {
      "alert": {
        "id": "10010",
        "name": "Cross-Site Scripting (Reflected)",
        "risk": "High",
        "confidence": "Medium",
        "description": "The value of the parameter 'cat' is reflected in the response...",
        "param": "cat",
        "attack": "<script>alert(1)</script>",
        "evidence": "<script>alert(1)</script>"
      }
    }
  ]
}
```
Этот пример демонстрирует полный цикл автоматизированного сканирования: от запуска демона до получения структурированных данных об уязвимостях, готовых для интеграции в систему управления рисками.

## Аналитический вывод

OWASP ZAP является зрелым и полнофункциональным инструментом динамического тестирования безопасности, способным эффективно заменять Burp Suite в сценариях, где критичны открытость кода, стоимость и автоматизация. Его архитектура, основанная на Java и REST API, обеспечивает гибкость интеграции в современные DevSecOps практики. В то время как Burp Suite предлагает более отполированный пользовательский опыт и глубокие инструменты для ручного анализа, ZAP компенсирует это мощными возможностями автоматизации и кроссплатформенностью.

Ключевым преимуществом ZAP является его роль в экосистеме open-source: он не только бесплатен, но и активно развивается сообществом, что обеспечивает быстрое реагирование на новые векторы атак. Однако для сложных ручных пентестов, требующих тонкой настройки и глубокого анализа бизнес-логики, Burp Suite Professional может оставаться предпочтительным выбором из-за более развитого интерфейса и специализированных расширений. Выбор между инструментами должен основываться на балансе между бюджетом, требованиями к автоматизации и уровнем ручного анализа.

## Источники

*   [Burp Suite vs. ZAP: Features, Key Differences & Limitations](https://www.pynt.io/learning-hub/burp-suite-guides/burp-suite-vs-zap-features-key-differences-limitations)
*   [The Ultimate Showdown: Burp vs. Zap in the World of Vulnerability Scanning](https://www.softwaresecured.com/post/burp-versus-zap)
*   [Top ZAP alternatives and competitors [September 2025]](https://beaglesecurity.com/blog/article/top-zap-alternatives.html)
*   [Vulnerability Scanning Tools - OWASP Foundation](https://owasp.org/www-community/Vulnerability_Scanning_Tools)
*   [OWASP ZAP (Zed Attack Proxy): Everything You Need to Know](https://www.stackhawk.com/blog/guide-to-zap-application-security-testing/)
*   [A Comprehensive Comparison of OWASP ZAP and Burp Suite Vulnerability Assessment Tools - Part 2](https://valencynetworks.com/blogs/a-comprehensive-comparison-of-owasp-zap-and-burp-suite-vulnerability-assessment-tools-part-2/)
*   [How to Use OWASP ZAP for Penetration Testing](https://www.jit.io/resources/owasp-zap/6-essential-steps-to-use-owasp-zap-for-penetration-testing)
*   [8 Burp Suite Alternatives and Competitors](https://www.pynt.io/learning-hub/burp-suite-guides/8-burp-suite-alternatives-and-competitors)
*   [A Complete Guide to OWASP ZAP for Web Application Security Testing](https://estatic-infotech.com/blog/post/a-complete-guide-to-owasp-zap-for-web-application-security-testing/)