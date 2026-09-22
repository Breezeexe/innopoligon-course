# WHOIS и Registrar данные как источник о владельце: от протокола к атрибуции

## Контекст и базовые понятия: Эволюция прозрачности и структура данных

WHOIS (от англ. *who is* — «кто есть») — это распределённый протокол и база данных, предназначенные для хранения и предоставления информации о зарегистрированных доменных именах и выделенных пулах IP-адресов. Исторически сложившаяся модель предполагала полную публичную прозрачность: любой пользователь сети мог запросить данные о владельце ресурса, получив в ответ контактную информацию (имя, адрес, телефон, email). В контексте тестирования на проникновение и OSINT (Open Source Intelligence) WHOIS является первичным источником для атрибуции (attribution) — установления связи между цифровым активом и реальным субъектом. Однако после вступления в силу Общего регламента по защите данных (GDPR) в ЕС в 2018 году и последующих политик ICANN (Temporary Specification for gTLD Registration Data) модель прозрачности была радикально изменена.

Современная инфраструктура доменных имен опирается на трехуровневую модель, которую необходимо четко разграничивать для корректного сбора информации:

1.  **Регистратор (Registrar):** Компания, аккредитованная ICANN (или национальным регистром для ccTLD), имеющая право напрямую регистрировать домены в пользу конечных клиентов. Именно регистратор собирает данные о владельце и предоставляет их в реестр.
2.  **Регистр (Registry):** Организация, управляющая зоной верхнего уровня (TLD), например, Verisign для `.com` или RIPE NCC для `.eu`. Регистр хранит базу всех доменов в своей зоне и предоставляет доступ к данным через протоколы WHOIS/RDAP.
3.  **Регистрант (Registrant):** Физическое или юридическое лицо, владеющее доменным именем.

Ключевое различие между традиционным WHOIS и современными реалиями заключается в доступности данных. Если раньше WHOIS был инструментом прямой идентификации, то сегодня он стал инструментом косвенной атрибуции через анализ метаданных, истории изменений и связей с регистратором.

Для понимания архитектуры сбора информации необходимо разграничить понятия **WHOIS** и **RDAP** (Registration Data Access Protocol). WHOIS — это текстовый протокол на базе TCP/43, который не имеет стандартизированной структуры ответа. RDAP — это его современная замена, основанная на HTTP/HTTPS и JSON, обеспечивающая аутентификацию и контроль доступа. В рамках пассивной разведки специалист должен понимать, что запрос к RDAP может вернуть разные наборы полей в зависимости от прав доступа (public vs. authenticated), тогда как WHOIS ответ всегда публичен, но часто содержит только маскированные данные.

| Характеристика | Традиционный WHOIS (pre-GDPR) | Современный WHOIS / RDAP (post-GDPR) |
| :--- | :--- | :--- |
| **Протокол** | TCP/43, текстовый формат | HTTP/HTTPS, JSON (RDAP) или текстовый (WHOIS) |
| **Доступность данных** | Полная публичная прозрачность | Ограниченная; персональные данные скрыты (redacted) |
| **Идентификатор** | Email, телефон, адрес владельца | Домен регистратора, контактная форма, ID записи |
| **Структура ответа** | Нестандартизированная, зависит от сервера | Стандартизированная (JSON для RDAP) |
| **Основное применение** | Прямая идентификация владельца | Поиск регистратора, анализ истории, косвенная атрибуция |
| **Юридический контекст** | Добровольное раскрытие | GDPR, CCPA, политика конфиденциальности ICANN |

Помимо доменных имен, WHOIS-подобные данные существуют для IP-адресов, но они управляются Региональными интернет-регистраторами (RIR): ARIN (Северная Америка), RIPE NCC (Европа/Ближний Восток/Центральная Азия), APNIC (Азиатско-Тихоокеанский регион), LACNIC (Латинская Америка) и AFRINIC (Африка). Данные RIR часто более надежны для атрибуции, так как юридические лица при выделении IP-блоков реже используют сервисы приватности, чем при регистрации доменов.

## Внутреннее устройство: Архитектура WHOIS-данных и механизмы маскировки

WHOIS-запись представляет собой набор полей, описывающих жизненный цикл домена и его владельца. Понимание структуры этих полей критично для анализа, так как именно в них часто остаются «отпечатки» владельца, даже при использовании услуг приватности.

### Структура WHOIS-записи

Типичная WHOIS-запись для домена содержит следующие ключевые элементы:

*   **Domain Name:** Сам домен.
*   **Registrar:** Название компании-регистратора (например, *GoDaddy.com, LLC*, *Namecheap, Inc.*).
*   **Registrar IANA ID:** Уникальный идентификатор регистратора в базе ICANN. Позволяет однозначно идентифицировать компанию.
*   **Registrar URL:** Веб-сайт регистратора.
*   **Registrar Abuse Contact Email/Phone:** Контакты для сообщения о злоупотреблениях. Часто эти данные не маскируются, так как требуются для правоприменения.
*   **Registrant Name/Organization:** Имя или название организации владельца.
*   **Registrant Street/City/State/Postal Code/Country:** Адрес владельца.
*   **Registrant Email/Phone:** Контактные данные владельца.
*   **Admin/Tech/Billing Contact:** Контакты административного, технического и платежного отделов. Исторически эти роли часто выполнялись разными людьми или отделами внутри компании, что позволяло выявить внутреннюю структуру организации.
*   **Name Server (NS):** DNS-серверы, обслуживающие домен.
*   **Dates:**
    *   *Creation Date:* Дата регистрации.
    *   *Expiration Date:* Дата истечения.
    *   *Updated Date:* Дата последнего изменения записи.
*   **Status:** Статус домена (например, `clientTransferProhibited`, `clientDeleteProhibited`).

### Механизмы маскировки и приватности

После внедрения GDPR регистраторы внедрили несколько уровней защиты данных:

1.  **Proxy/Privacy Service:** Данные владельца заменяются на данные компании-провайдера приватности (например, *Domains By Proxy, LLC* для GoDaddy). В поле `Registrant Email` указывается адрес вида `xxxx@domainsbyproxy.com`.
2.  **Redaction (Маскирование):** Личные данные удаляются или заменяются на плейсхолдеры (например, `REDACTED FOR PRIVACY`).
3.  **Access Control (RDAP):** Доступ к полным данным предоставляется только аутентифицированным пользователям с обоснованным интересом (law enforcement, правообладатели).

Однако маскировка не всегда эффективна. Анализаторы используют следующие техники для обхода или анализа последствий маскировки:

*   **Анализ Name Server (NS):** Если владелец использует собственные DNS-серверы (например, `ns1.company.com`), а не публичные DNS регистратора (например, `ns1.godaddy.com`), это указывает на наличие собственной инфраструктуры и, вероятно, на более зрелую организацию.
*   **Анализ Registrar Abuse Contact:** Контакты для сообщений об abuse часто остаются видимыми. Запрос к этим контактам с обоснованием (например, отчет о фишинге) может привести к раскрытию данных владельца регистратором.
*   **Исторические данные (Historical WHOIS):** До 2018 года или до момента включения приватности данные были открыты. Архивы WHOIS сохраняют эти записи.
*   **Косвенная атрибуция через платежные данные:** В поле `Billing Email` или `Registrar Abuse Contact` иногда остаются рабочие email-адреса сотрудников, не связанные с приватностью домена.

### Взаимосвязь с RDAP

RDAP (Registration Data Access Protocol) стандартизирует доступ к этим данным. В отличие от WHOIS, RDAP использует HTTP-методы:
*   `GET /domain/{domain}` — получение информации о домене.
*   `GET /entity/{handle}` — получение информации о сущности (регистраторе, контакте).
*   `GET /nameserver/{nameserver}` — информация о DNS-сервере.

Ответ RDAP имеет структуру JSON, что позволяет программно парсить данные. Ключевые поля в JSON-ответе RDAP:

```json
{
  "ldhName": "example.com",
  "handle": "DOMAIN_HANDLE",
  "entities": [
    {
      "handle": "REGISTRAR_HANDLE",
      "vcardarray": [
        "vcard",
        [
          [
            "version",
            {},
            "text",
            "4.0"
          ],
          [
            "fn",
            {},
            "text",
            "Example Registrar Inc."
          ]
        ]
      ],
      "roles": [ "registrar" ]
    },
    {
      "handle": "CONTACT_HANDLE",
      "vcardarray": [
        "vcard",
        [
          [ "version", {}, "text", "4.0" ],
          [ "fn", {}, "text", "REDACTED FOR PRIVACY" ],
          [ "email", {}, "uri", "REDACTED FOR PRIVACY" ]
        ]
      ],
      "roles": [ "registrant" ]
    }
  ],
  "events": [
    { "eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z" },
    { "eventAction": "expiration", "eventDate": "2025-01-01T00:00:00Z" }
  ]
}
```

Важно отметить, что RDAP также поддерживает фильтрацию данных. Если запрос не содержит аутентификации, поля `vcardarray` для роли `registrant` будут содержать только публичные данные, которые часто ограничиваются только доменом регистратора.

## Применение и работа с предметом: Инструменты и методы анализа

На практике специалист по пентесту или аналитик по кибербезопасности не ограничивается одним запросом. Сбор информации через WHOIS/RDAP включает несколько этапов: прямой запрос, анализ истории, обратный поиск и корреляцию с другими данными.

### Инструментарий и методы

1.  **Клиентские утилиты WHOIS:**
    *   `whois` (Linux/Unix): Стандартная утилита. Поддерживает прямые запросы к реестрам.
    *   `rdap` (Linux): Клиент для протокола RDAP.
    *   `dig` (BIND utilities): Может использоваться для получения NS-записей, которые косвенно указывают на инфраструктуру.

2.  **API и веб-сервисы:**
    *   **WhoisXML API:** Предоставляет доступ к историческим данным WHOIS, что критично для восстановления данных до GDPR.
    *   **RDAP Lookup Services:** Публичные сервисы (например, от ICANN или регистраторов) для тестирования структуры ответа.
    *   **WhoXY / DomainTools:** Коммерческие платформы для глубокого анализа связей (reverse WHOIS, отслеживание изменений).

3.  **Методы анализа:**
    *   **Reverse WHOIS:** Поиск всех доменов, зарегистрированных на один email, имя или адрес. Это позволяет выявить пул активов, принадлежащих одному субъекту.
    *   **Historical WHOIS:** Анализ старых записей для нахождения данных владельца до маскировки.
    *   **Correlation:** Сопоставление NS-записей, IP-адресов (через A/AAAA записи) и WHOIS-данных для построения графа инфраструктуры.

### Типичные ошибки и подводные камни

*   **Игнорирование ccTLD:** Домены верхнего уровня стран (например, `.ru`, `.cn`, `.de`) могут иметь собственные правила хранения данных и не всегда подчиняются политикам ICANN для gTLD.
*   **Неверная интерпретация NS:** Использование публичных DNS (Cloudflare, Google DNS) не означает, что владелец не контролирует инфраструктуру. Это может быть признаком использования CDN или защиты от DDoS.
*   **Отсутствие контекста:** Сам по себе WHOIS-данные не доказывают злонамеренность. Они лишь указывают на потенциального владельца. Требуется корреляция с другими индикаторами компрометации (IoC).

### Пример использования инструмента `whois`

Команда `whois` отправляет запрос к соответствующему реестру. Вывод зависит от политики реестра.

```bash
$ whois example.com
Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.iana.org
Registrar URL: http://reseller.example.com
Updated Date: 2023-08-14T09:13:43Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2024-08-13T04:00:00Z
Registrar: Example Registrar, LLC
Registrar IANA ID: 1234
Registrar Abuse Contact Email: abuse@example-registrar.com
Registrar Abuse Contact Phone: +1.5555555555
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
DNSSEC: signedDelegation
>>> Last update of whois database: 2024-05-20T10:00:00Z <<<

Registrant Name: REDACTED FOR PRIVACY
Registrant Organization: Privacy Protection Service
Registrant Street: REDACTED FOR PRIVACY
Registrant City: REDACTED FOR PRIVACY
Registrant State/Province: CA
Registrant Postal Code: REDACTED FOR PRIVACY
Registrant Country: US
Registrant Phone: REDACTED FOR PRIVACY
Registrant Phone Ext: REDACTED FOR PRIVACY
Registrant Fax: REDACTED FOR PRIVACY
Registrant Email: Please query the RDDS service of the Registrar of Record identified in this output.
```

В данном примере видно, что личные данные скрыты, но контакты для abuse (abuse contact) остаются видимыми, а также указаны NS-серверы, которые могут быть полезны для дальнейшего анализа.

## Сквозной практический пример: Атрибуция владельца фишингового домена

**Исходные условия:**
Среда: Linux (Kali Linux).
Инструменты: `whois`, `dig`, `whoisxmlapi` (или аналогичный сервис исторических данных), `jq` (для парсинга JSON).
Роль: Аналитик SOC / Пентестер.
Сценарий: Обнаружен фишинговый домен `secure-bank-login.com`, используемый для кражи учетных данных. Необходимо установить связь с владельцем для составления отчета и возможного блокирования.

**Шаг 1: Текущий WHOIS-запрос и анализ маскировки**

Действие: Выполняем стандартный запрос к реестру `.com` (через IANA или напрямую к регистратору).

```bash
$ whois secure-bank-login.com
Domain Name: SECURE-BANK-LOGIN.COM
Registry Domain ID: D123456789-LROR
Registrar WHOIS Server: whois.registrar-a.com
Registrar URL: https://www.registrar-a.com
Updated Date: 2023-10-01T12:00:00Z
Creation Date: 2023-09-28T10:00:00Z
Registrar Registration Expiration Date: 2024-09-28T10:00:00Z
Registrar: Registrar A Inc.
Registrar IANA ID: 9999
Registrar Abuse Contact Email: abuse@registrar-a.com
Registrar Abuse Contact Phone: +1.8005551234
Domain Status: clientTransferProhibited
Registry Registrant ID: REDACTED FOR PRIVACY
Registrant Name: REDACTED FOR PRIVACY
Registrant Organization: Privacy Protection Service LLC
Registrant Street: REDACTED FOR PRIVACY
Registrant City: REDACTED FOR PRIVACY
Registrant State/Province: WA
Registrant Postal Code: REDACTED FOR PRIVACY
Registrant Country: US
Registrant Phone: REDACTED FOR PRIVACY
Registrant Email: https://domainprivacy.registrar-a.com/contact?d=SECURE-BANK-LOGIN.COM
Name Server: NS1.CLOUDFLARE.COM
Name Server: NS2.CLOUDFLARE.COM
DNSSEC: unsigned
```

*Результат:* Данные владельца скрыты сервисом приватности `Privacy Protection Service LLC`. Домен использует Cloudflare для DNS, что указывает на использование CDN/защиты. Прямая идентификация невозможна.

**Шаг 2: Анализ исторических данных**

Действие: Используем API исторических WHOIS-данных для поиска записей до 2023-09-28 (дата создания) или до момента включения приватности.

```bash
$ curl -s "https://api.whoisxmlapi.com/v1?apiKey=YOUR_API_KEY&domain=secure-bank-login.com&type=historical" | jq '.result[0]'
```

*Иллюстративный вывод (JSON):*
```json
{
  "domainName": "secure-bank-login.com",
  "registrar": "Registrar A Inc.",
  "registrant": {
    "name": "John Doe",
    "organization": "Doe Digital Services",
    "email": "john.doe@tempmail-service.net",
    "phone": "+1.5551234567",
    "address": "123 Fake Street, Springfield, IL, 62704, US"
  },
  "creationDate": "2023-09-28T10:00:00Z",
  "expirationDate": "2024-09-28T10:00:00Z"
}
```

*Результат:* Найдена исходная запись. Владелец указан как `John Doe` из `Doe Digital Services`. Email `john.doe@tempmail-service.net` указывает на использование временной почты, что является индикатором злонамеренности. Адрес может быть фиктивным, но имя и организация — важные зацепки.

**Шаг 3: Reverse WHOIS и поиск связанных доменов**

Действие: Ищем другие домены, зарегистрированные на `john.doe@tempmail-service.net` или `Doe Digital Services`.

```bash
$ curl -s "https://api.whoisxmlapi.com/v1?apiKey=YOUR_API_KEY&searchType=reverseWhois&searchValue=john.doe@tempmail-service.net" | jq '.result[].domainName'
```

*Иллюстративный вывод:*
```text
"secure-bank-login.com"
"secure-bank-update.net"
"bank-verify-secure.org"
"login-secure-bank.info"
```

*Результат:* Выявлен пул из 4 фишинговых доменов. Все они имеют схожее название и, вероятно, принадлежат одному субъекту. Это усиливает уверенность в атрибуции и позволяет расширить область блокировки.

**Шаг 4: Корреляция с инфраструктурой**

Действие: Проверяем NS-записи и IP-адреса доменов из пула.

```bash
$ dig +short secure-bank-login.com A
$ dig +short secure-bank-update.net A
```

*Иллюстративный вывод:*
```text
104.21.45.67
104.21.45.67
```

*Результат:* Оба домена указывают на один IP-адрес (104.21.45.67), который принадлежит Cloudflare. Это подтверждает, что домены используют общую инфраструктуру проксирования. Хотя IP не раскрывает владельца напрямую, он указывает на использование одного и того же сервиса защиты, что может быть использовано для корреляции в более широком контексте (например, через отчеты об abuse в Cloudflare).

**Ожидаемый вывод:**
Прямая идентификация владельца через текущий WHOIS невозможна из-за GDPR. Однако анализ исторических данных позволил восстановить исходные данные: имя `John Doe`, организация `Doe Digital Services` и email `john.doe@tempmail-service.net`. Reverse WHOIS выявил пул связанных фишинговых доменов. Эти данные могут быть использованы для составления отчета в регистратор и Cloudflare для блокировки ресурсов, а также для поиска дополнительных следов в интернете (например, по имени `John Doe` или организации `Doe Digital Services`).

## Аналитический вывод

WHOIS и данные регистраторов остаются фундаментальным источником для атрибуции в кибербезопасности, несмотря на ужесточение политик конфиденциальности. Ключевым изменением является переход от прямой идентификации к косвенной атрибуции через анализ метаданных, истории изменений и связей между активами. Современные специалисты должны использовать комплексный подход: сочетание запросов к RDAP, анализа исторических WHOIS-данных, reverse WHOIS-поиска и корреляции с инфраструктурными данными (NS, IP). Успешная атрибуция часто зависит не от одного источника, а от синтеза информации из нескольких источников, включая контакты для abuse регистраторов и исторические архивы. Понимание структуры WHOIS-данных и механизмов их маскировки позволяет эффективно обходить ограничения GDPR и выявлять злонамеренную активность.

## Источники

1.  [How to use OSINT to uncover domain ownership: WHOIS, Reverse IP, and lookup techniques](https://authentic8.com/blog/unmasking-website-ownership-using-osint)
2.  [An In-Depth Guide to Understanding the WHOIS Database](https://medium.com/@okanyildiz1994/an-in-depth-guide-to-understanding-the-whois-database-775f6215c198)
3.  [How to Find the Real Owner of a Domain (Legally)](https://blog.whoisjsonapi.com/how-to-find-the-real-owner-of-a-domain/)
4.  [Retrieve Domain WHOIS History Data After Redaction](https://drs.whoisxmlapi.com/blog/retrieve-domain-data-after-redaction)
5.  [Как узнать владельца сайта](https://help.reg.ru/support/domains/obshchaya-informatsiya-o-domenakh/kak-uznat-vladeltsa-sayta)
6.  [Cyber Hunter Academy Explains How They Use WhoisXML API Tools to Teach OSINT](https://main.whoisxmlapi.com/success-stories/cyber-hunter-academy-explains-how-they-use-whoisxmlapi-tools-to-teach-osint)
7.  [Open Source Intelligence Gathering: Techniques, Automation, and Visualization](https://specterops.io/blog/2018/10/02/open-source-intelligence-gathering-techniques-automation-and-visualization/)
8.  [ICANN Temporary Specification for gTLD Registration Data](https://www.icann.org/en/system/files/files/gdpr-factsheet-12mar19-en.pdf)