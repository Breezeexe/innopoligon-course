# Создание собственных шаблонов Nuclei для специфических проверок

## Контекст и базовые понятия

Nuclei (ProjectDiscovery) представляет собой сканер уязвимостей с открытым исходным кодом, основанный на шаблонизации. В отличие от классических DAST-инструментов (например, Burp Suite Professional или Acunetix), которые полагаются на внутренние эвристические алгоритмы и базы сигнатур, Nuclei использует декларативный подход. Логика проверки инкапсулируется в YAML-файлы, что позволяет любому исследователю безопасности формализовать новый вектор атаки или метод обнаружения без перекомпиляции бинарного кода.

Ключевое отличие Nuclei от традиционных сканеров заключается в механизме **template clustering** (кластеризации шаблонов). При сканировании Nuclei группирует запросы, направленные на один и тот же endpoint, в единый HTTP-вызов. Это снижает нагрузку на целевую инфраструктуру и минимизирует вероятность срабатывания WAF (Web Application Firewall) из-за аномально высокой частоты запросов.

Для понимания архитектуры необходимо разграничить три сущности, часто путаемые в контексте автоматизации безопасности:

| Сущность | Функция | Область применения | Отличительные признаки |
| :--- | :--- | :--- | :--- |
| **Nuclei Template** | Декларативное описание проверки (запрос + условия матчинга) | Сканер Nuclei | YAML-формат, DSL для выражений, протокольно-независимая структура (http, dns, tcp, ssl) |
| **Nuclei Workflow** | Оркестрация нескольких шаблонов с условной логикой | Комплексные проверки | YAML-файл с секцией `workflows`, содержит `subtemplates`, зависимости между шагами |
| **Nuclei Plugin** | Расширение ядра на языке Go | Разработка ядра Nuclei | Go-код, компилируется в бинарник, позволяет выполнять сложную логику, недоступную в DSL |

Nuclei поддерживает протоколы `http`, `dns`, `tcp`, `ssl`, `file`, `headless`, `network` и другие. Однако подавляющее большинство кастомных шаблонов разрабатывается для протокола `http`, так как он покрывает 90% векторов атак на веб-приложения (XSS, SQLi, SSRF, IDOR, misconfig).

Синтаксис шаблонов базируется на YAML, но содержит собственный **Domain Specific Language (DSL)**. DSL позволяет использовать переменные (например, `{{BaseURL}}`, `{{Hostname}}`), функции (например, `to_lower`, `contains`, `regex`), и интерполяцию. Это превращает шаблон из статической сигнатуры в динамический скрипт проверки.

```yaml
# Структурная схема разграничения сущностей
[Template] ──(описывает)──▶ [Single Check]
   │
   ├── info: metadata (name, severity, author)
   ├── protocol: http/dns/tcp
   ├── requests: [HTTP Request Object]
   └── matchers: [Condition Logic]

[Workflow] ──(оркестрирует)──▶ [Template A] ──(условие)──▶ [Template B]
```

## Внутреннее устройство предмета

Шаблон Nuclei — это строго типизированный YAML-документ. Его внутренняя структура определяет жизненный цикл проверки: от формирования запроса до интерпретации ответа. Понимание внутренних компонентов необходимо для отладки ложных срабатываний (false positives) и создания надежных детекторов.

### Архитектура шаблона

Шаблон состоит из трех основных блоков: `info`, `id` (на уровне корня) и `protocol-specific` секции (например, `http`).

1.  **Metadata (`info`)**: Содержит контекст уязвимости. Поле `severity` определяет приоритет алерта (critical, high, medium, low, info). Поле `classification` позволяет связать шаблон со стандартами (CVE, CWE, CVSS).
2.  **Request Definition**: Определяет, что отправляется на сервер. Включает метод, путь, заголовки, тело запроса. Поддерживает динамическую генерацию через переменные.
3.  **Matchers & Extractors**: Ядро логики детектирования.
    *   `matchers`: Условие, при котором проверка считается успешной (уязвимость найдена).
    *   `extractors`: Извлекают данные из ответа для последующего использования в других шаблонах или для вывода.

### Типы матчеров и логика сравнения

Nuclei поддерживает несколько типов матчеров, каждый из которых оперирует разными частями ответа (part):

| Тип матчера | Проверяемая часть | Описание | Пример использования |
| :--- | :--- | :--- | :--- |
| `word` | `body`, `header`, `status`, `body_hex`, `raw` | Точное или частичное совпадение строки | Поиск специфического заголовка `X-Powered-By: PHP` |
| `regex` | `body`, `header`, `status` | Совпадение по регулярному выражению | Извлечение версии ПО из заголовка `Server` |
| `size` | `body` | Проверка размера тела ответа в байтах | Обнаружение пустых страниц или ошибок 500 |
| `status` | `status` | Проверка HTTP-кода ответа | Обнаружение 403/404/500 |
| `dsl` | `body`, `header`, `status` | Выполнение DSL-выражения | Сравнение двух полей ответа, математические операции |

Для обеспечения точности (low false-positive rate) рекомендуется комбинировать матчеры. Например, проверка на SSRF часто требует совпадения статуса `200` И наличия специфического заголовка в ответе.

### DSL и переменные

DSL Nuclei позволяет создавать сложные условия. Переменные окружения шаблона включают:
*   `{{BaseURL}}`: Полный URL цели (scheme://host:port).
*   `{{Hostname}}`: Только имя хоста.
*   `{{Path}}`: Путь к файлу (для file-протокола).
*   `{{RetryCount}}`: Текущий номер попытки (для retry-логики).

Функции DSL включают строковые манипуляции (`to_lower`, `trim`, `replace`), криптографические хеши (`md5`, `sha256`), и логические операторы (`and`, `or`, `not`).

```json
{
  "template_structure": {
    "id": "string (уникальный идентификатор)",
    "info": {
      "name": "string (челочитаемое имя)",
      "severity": "enum (critical|high|medium|low|info)",
      "description": "string",
      "reference": ["url"],
      "classification": {
        "cve-id": "string",
        "cwe-id": "string",
        "cvss-score": "float"
      }
    },
    "http": [
      {
        "method": "enum (GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)",
        "path": ["string (интерполируемый путь)"],
        "headers": {
          "key": "value"
        },
        "body": "string (для POST/PUT)",
        "matchers": [
          {
            "type": "enum (word|regex|size|status|dsl)",
            "part": "enum (body|header|status|raw)",
            "condition": "enum (and|or)",
            "words": ["string"],
            "regex": ["string"],
            "status": ["int"],
            "dsl": ["string"]
          }
        ],
        "extractors": [
          {
            "type": "regex|kval|json",
            "part": "body|header",
            "name": "string",
            "regex": ["string"]
          }
        ]
      }
    ]
  }
}
```

## Применение и работа с предметом

Создание кастомного шаблона — это итеративный процесс, требующий понимания протокола, логики уязвимости и синтаксиса DSL. Процесс включает исследование, прототипирование, валидацию и оптимизацию.

### Этапы разработки шаблона

1.  **Анализ уязвимости**: Необходимо понять, какой запрос вызывает уязвимость и какой ответ является индикатором. Важно найти уникальный признак (indicator), который не встречается в легитимном ответе.
2.  **Базовая структура**: Создание YAML-файла с заполненными полями `id`, `info`.
3.  **Формирование запроса**: Настройка `http.requests`. Использование переменных `{{BaseURL}}`. Добавление заголовков, если требуется (например, `Content-Type`).
4.  **Настройка матчеров**: Определение условий совпадения. Для надежности используйте комбинацию `status` и `word`/`regex`.
5.  **Валидация**: Запуск `nuclei -validate -t template.yaml` для проверки синтаксиса.
6.  **Тестирование на целевой системе**: Запуск против известной уязвимой среды (например, DVWA или Metasploitable) для проверки на false positives/negatives.

### Типичные ошибки и подводные камни

*   **Слишком общие матчеры**: Использование слов, встречающихся в любой странице (например, "error", "not found"). Это приводит к ложным срабатываниям.
*   **Игнорирование кодировки**: Ответы сервера могут быть в UTF-8, ISO-8859-1 и т.д. Рекомендуется использовать `body_hex` или `regex` для более надежного поиска.
*   **Отсутствие проверки статуса**: Ответ с телом, содержащим индикатор уязвимости, но со статусом `403` или `500`, может быть ложным срабатыванием (или ошибкой сервера, а не уязвимостью). Всегда проверяйте `status: [200]`.
*   **Неучет редиректов**: По умолчанию Nuclei следует за редиректами. Если уязвимость проявляется только на исходном URL, необходимо использовать `redirects: false`.

### Инструментарий и команды

Для разработки используются:
*   `nuclei`: Основной CLI.
*   `nuclei -validate`: Валидация синтаксиса.
*   `nuclei -t template.yaml -u target`: Тестирование.
*   `nuclei -t template.yaml -u target -v`: Вывод детальной информации (verbose).
*   `nuclei -t template.yaml -u target -json`: Вывод в JSON-формате для интеграции в CI/CD.

```bash
# Валидация шаблона
nuclei -validate -t ./custom_template.yaml

# Тестирование с выводом совпавших данных
nuclei -t ./custom_template.yaml -u https://target.com -v -d

# Экспорт результатов в JSON
nuclei -t ./custom_template.yaml -u https://target.com -json -o results.json
```

## Сквозной практический пример: Обнаружение SSRF через заголовок Host

**Исходные условия**:
Среда: Локальная установка Nuclei v3.x.
Цель: Веб-приложение с потенциальной уязвимостью Server-Side Request Forgery (SSRF) через заголовок `Host`.
Роль: Пентестер, проверяющий API-эндпоинт `/api/v1/fetch`.
Сценарий: Приложение перенаправляет запросы на указанный в заголовке `Host` хост. Если целевой сервер возвращает статус `200` и содержит строку `success`, уязвимость подтверждена.

### Шаг 1: Создание базовой структуры шаблона

Создаем файл `ssrf-host-header.yaml`. Заполняем метаданные.

```yaml
id: ssrf-host-header-test

info:
  name: SSRF via Host Header
  author: pentester-student
  severity: high
  description: |
    Detects SSRF vulnerability via Host header manipulation.
    If the server responds with 'success' to a modified Host header, it may be vulnerable.
  reference:
    - https://portswigger.net/web-security/ssrf
  tags: ssrf,http,header

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/fetch"
```

### Шаг 2: Добавление заголовка и условия матчинга

Добавляем заголовок `Host` с внутренним IP-адресом (иллюстративная схема, в реальности используется локальный endpoint или DNS-log-сервер). Для демонстрации матчинга используем строку `success` в теле ответа.

```yaml
    headers:
      Host: "127.0.0.1" # Иллюстративная схема: в реальном пентесте используется свой домен или localhost
    
    matchers:
      - type: word
        part: body
        words:
          - "success"
        condition: and
      - type: status
        part: status
        status:
          - 200
```

### Шаг 3: Полная структура шаблона с валидацией

Объединяем элементы. Добавляем `extractors` для извлечения версии сервера, если она есть в заголовке `Server`.

```yaml
id: ssrf-host-header-detect

info:
  name: SSRF via Host Header Detection
  author: pentester-student
  severity: high
  description: Detects SSRF via Host header by checking for specific response indicators.
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Server_Side_Request_Forgery
  tags: ssrf,http,header

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/fetch"
    
    headers:
      Host: "127.0.0.1"

    matchers:
      - type: word
        part: body
        words:
          - "success"
        condition: and
      - type: status
        part: status
        status:
          - 200

    extractors:
      - type: kval
        kval:
          - server
```

### Шаг 4: Валидация и запуск

Проверяем синтаксис и запускаем против цели.

```bash
# Валидация
nuclei -validate -t ssrf-host-header-detect.yaml
# Output: Template [ssrf-host-header-detect] validated successfully

# Запуск
nuclei -t ssrf-host-header-detect.yaml -u https://vulnerable-app.local -v
```

### Шаг 5: Анализ вывода

Если уязвимость присутствует, Nuclei выведет:

```json
{
  "template-id": "ssrf-host-header-detect",
  "matched-at": "https://vulnerable-app.local/api/v1/fetch",
  "host": "https://vulnerable-app.local",
  "matched": "success",
  "timestamp": "2023-10-27T10:00:00Z",
  "matcher-name": "word"
}
```

**Ожидаемый вывод**:
Пример демонстрирует создание шаблона, который использует заголовок `Host` для обхода стандартной логики маршрутизации. Комбинация `matchers` с `type: word` и `type: status` обеспечивает высокую точность, исключая случайные совпадения. Извлечение данных через `extractors` позволяет автоматизировать сбор информации о сервере.

## Аналитический вывод

Создание кастомных шаблонов Nuclei трансформирует процесс тестирования на проникновение из ручного поиска в инженерную дисциплину. YAML-шаблоны обеспечивают воспроизводимость проверок, что критично для интеграции в CI/CD пайплайны (DevSecOps). Ключевым преимуществом является гибкость DSL, позволяющая реализовывать сложную логику детектирования без написания кода на Go. Однако, эффективность шаблонов напрямую зависит от качества матчеров: слишком общие условия приводят к шуму, слишком специфичные — к пропускам. Рекомендуется всегда комбинировать несколько типов матчеров (статус, тело, заголовки) и использовать `body_hex` для устойчивости к кодировкам. Разработка шаблонов требует глубокого понимания HTTP-протокола и логики целевого приложения, но окупается многократным переиспользованием проверок.

## Источники

*   [Nuclei Template Creation Guide](https://github.com/projectdiscovery/nuclei-templates/blob/main/TEMPLATE-CREATION-GUIDE.md)
*   [If you're not writing custom Nuclei templates, you're missing out](https://projectdiscovery.io/blog/if-youre-not-writing-custom-nuclei-templates-youre-missing-out)
*   [The Ultimate Guide to Finding Bugs With Nuclei](https://projectdiscovery.io/blog/ultimate-nuclei-guide)
*   [Nuclei Plugin & Burp Suite – Template Creation Guide](https://blog.cyberadvisors.com/technical-blog/blog/nuclei-plugin-burp-suite-template-creation-guide)
*   [Using Nuclei Templates for Vulnerability Scanning](https://orca.security/resources/blog/using-nuclei-templates-for-vulnerability-scanning/)
*   [Nuclei без магии: запуск, шаблоны, практика](https://setka.ru/posts/019d94f4-ec3f-7be2-997e-75146faf7470)
*   [The ultimate beginner's guide to Nuclei](https://www.bugcrowd.com/blog/the-ultimate-beginners-guide-to-nuclei/)
*   [Template syntax overview - Nuclei](https://projectdiscovery-nuclei.mintlify.app/templates/syntax-overview)
*   [Создание шаблонов Nuclei](https://spy-soft.net/create-nuclei-templates/)
*   [Nuclei Automation: Deep-dive into Templates & DevSecOps](https://www.appsecengineer.com/blog/nuclei-automation-deep-dive-into-templates-devsecops-workflows)