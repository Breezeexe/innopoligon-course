# Согласование scope социальной инженерии в Rules of Engagement

## Контекст и базовые понятия

Rules of Engagement (RoE) в контексте тестирования на проникновение — это формализованный документ, определяющий правовые, технические и этические границы операции. В отличие от классического пентеста, где scope ограничивается IP-адресами и портами, социальная инженерия (SE) затрагивает человеческий фактор, что требует расширения границ до организационных структур, каналов связи и физических локаций.

Ключевое разграничение проводится между **Penetration Testing** (поиск уязвимостей в системах) и **Red Teaming** (адверсари симуляция, включающая SE). SE-кампании требуют особого внимания к compliance (HIPAA, GDPR) и безопасности персонала, так как атаки направлены на сотрудников, а не на код.

### Сравнение подходов к scope

| Характеристика | Технический Pentest | Социальная инженерия (SE) |
| :--- | :--- | :--- |
| **Объект атаки** | Серверы, сети, приложения, IoT | Сотрудники, физическая инфраструктура, репутация |
| **Методы** | Сканирование, эксплойты, брутфорс | Фишинг, вишинг, претекстинг, физический вход |
| **Риск для бизнеса** | Сбой сервисов, утечка данных | Психологический стресс, репутационные потери, нарушение доверия |
| **Юридические риски** | Нарушение CFAA (в США) или ст. 272-274 УК РФ | Нарушение прав на частную жизнь, трудовое законодательство, HIPAA/GDPR |
| **Степень скрытности** | Часто известна (White Box) или частично известна (Grey Box) | Максимально скрыта (Black Box) для реалистичности |
| **Ограничения** | Время, нагрузка на CPU/Network | Этика, безопасность пациентов/клиентов, критическая инфраструктура |

### Разрешение путаницы: «Тестирование» vs «Атака»

В RoE критически важно разграничить **Validation** (валидация контроля) и **Exploitation** (эксплуатация).
*   *Validation:* Отправка фишингового письма для измерения процента кликов.
*   *Exploitation:* Перехват учётных данных и доступ к файловой системе.
Для SE-кампаний scope часто ограничивается только Validation, если не согласовано иное, чтобы избежать юридических последствий несанкционированного доступа.

## Внутреннее устройство предмета

RoE для социальной инженерии — это не просто список IP-адресов, а многоуровневая структура ограничений. Она состоит из четырех основных слоев:

1.  **Legal & Compliance Layer:** Запреты, связанные с законами (HIPAA для здравоохранения, PCI DSS для платежей). Например, в HIPAA запрещено собирать реальные ePHI (электронные медицинские данные) в ходе тестирования.
2.  **Operational Layer:** Технические и физические границы. Какие отделы (C-suite, HR, IT) доступны? Какие каналы (email, phone, SMS, physical) разрешены?
3.  **Ethical & Safety Layer:** Запреты на использование тем, вызывающих травму (терроризм, насилие, сексуальные домогательства), или на атаки на критическую инфраструктуру (больницы, АЭС).
4.  **Communication Layer:** Протоколы связи между Red Team и Blue Team (SIRT). Как сообщать об инцидентах? Кто имеет право на «Stop Work»?

### Структура документа RoE для SE

```json
{
  "engagement_id": "SE-2024-Q3-001",
  "scope": {
    "targets": {
      "departments": ["HR", "Finance", "Executive"],
      "channels": ["email", "voip"],
      "exclusions": ["medical_devices", "patient_records"]
    },
    "methods": {
      "allowed": ["phishing", "vishing"],
      "prohibited": ["physical_bypass", "malware_delivery"]
    }
  },
  "constraints": {
    "time_window": "2024-10-01T09:00:00Z to 2024-10-05T17:00:00Z",
    "max_impact": "no_data_loss",
    "safety_stop_words": ["bomb", "virus", "police"]
  }
}
```

### Ключевые элементы согласования

*   **Authorization:** Требуется подпись CISO и Legal Counsel. Для SE часто требуется одобрение HR-директора, так как атаки влияют на персонал.
*   **Deconfliction:** Исключение конфликтов с другими операциями (например, с аудитами безопасности или реальными инцидентами).
*   **Data Handling:** Правила работы с собранными данными (если SE привела к получению данных). Данные должны быть немедленно уничтожены или переданы в защищенное хранилище.

## Применение и работа с предметом

Согласование scope — это итеративный процесс. На практике он включает:

1.  **Intelligence Gathering:** Сбор OSINT о компании для понимания структуры и возможных векторов.
2.  **Risk Assessment:** Оценка рисков для каждого вектора. Например, фишинг на HR безопасен, но вишинг на операторов АСУ ТП может быть критичным.
3.  **Drafting RoE:** Написание документа с четкими формулировками. Избегайте двусмысленности: «не причинять вреда» недостаточно; нужно «не использовать оружие, не имитировать насилие, не блокировать доступ к экстренным службам».
4.  **Review & Sign-off:** Согласование с юристами, HR, IT-безопасностью.
5.  **Execution & Monitoring:** Запуск кампании с постоянным мониторингом метрик и реагированием на непредвиденные события.

### Типичные ошибки при согласовании

*   **Scope Creep:** Постепенное расширение целей без пересмотра RoE.
*   **Lack of Escalation Path:** Отсутствие четкого номера телефона для остановки операции.
*   **Ignoring Compliance:** Игнорирование отраслевых стандартов (например, попытка получить реальные данные пациентов в медучреждении).

## Сквозной практический пример: Согласование SE-кампании в медицинском учреждении

**Исходные условия:**
Клиент: Частная клиника «HealthCare Plus».
Роль: Red Team Lead.
Цель: Оценка осведомленности персонала по фишингу.
Среда: Windows AD, Exchange Online, физический офис.

### Шаг 1: Определение ограничений по данным (HIPAA Compliance)

Первое действие — согласование того, какие данные *не* могут быть затронуты. В медицине это ePHI.

```bash
# Пример запроса к Legal-отделу для подтверждения ограничений
# (В реальности это email или форма согласования)

Subject: RoE Constraints for SE Campaign - HIPAA Impact Analysis

Body:
We are planning a phishing campaign targeting HR and Finance.
Please confirm the following exclusions are mandatory:
1. No access to Patient Management System (PMS).
2. No collection of any PHI (Protected Health Information).
3. No simulation of ransomware or data encryption.
4. No physical access to server rooms.

Approved by [Legal Counsel Name]: [Signature]
Date: 2024-10-01
```

### Шаг 2: Определение технических векторов и инструментов

Согласование методов атаки. Используем Metasploit Pro для создания фишинговой кампании.

```yaml
# Фрагмент конфигурации кампании в Metasploit Pro
campaign:
  name: "PhishAwareness_Q4"
  targets:
    - group: "HR_Department"
      count: 50
    - group: "Finance_Department"
      count: 30
  delivery:
    method: "email"
    template: "invoice_due"
    spoofing:
      from: "admin@healthcareplus.local"
      domain: "healthcareplus.com"
  payload:
    type: "meterpreter"
    stage: "disabled" # Важно: только сбор email, без выполнения кода
    callback: "c2.healthcareplus-test.local"
```

### Шаг 3: Согласование этических границ и стоп-слов

Определение тем, которые запрещены к использованию, чтобы избежать психологического дискомфорта.

```text
# Документ этических ограничений (Appendix A к RoE)

PROHIBITED TOPICS:
- Terrorism
- Death of family members
- Sexual harassment
- Discrimination (race, gender, religion)
- Impersonation of law enforcement (FBI, Police)

STOP WORK CONDITIONS:
- If a target shows signs of severe distress.
- If the target mentions a real security incident.
- If any critical system becomes unstable.
```

### Шаг 4: Формализация метрик и отчётности

Определение того, как будет измеряться успех.

```json
{
  "metrics": {
    "open_rate": "percentage of emails opened",
    "click_rate": "percentage of links clicked",
    "credential_submit": "percentage of credentials entered",
    "report_rate": "percentage of emails reported to IT"
  },
  "reporting": {
    "frequency": "daily",
    "format": "PDF + Executive Summary",
    "distribution": ["CISO", "HR_Director", "IT_Manager"]
  }
}
```

### Ожидаемый вывод
Пример демонстрирует, как техническая задача (фишинг) трансформируется в юридически и этически обоснованный процесс. Согласование scope предотвращает нарушение HIPAA, защищает персонал от стресса и обеспечивает четкие метрики для оценки эффективности обучения.

## Аналитический вывод

Согласование scope социальной инженерии в Rules of Engagement является критическим этапом, определяющим успех и безопасность операции. В отличие от технических пентестов, SE затрагивает человеческий фактор, что требует расширения границ до юридических, этических и организационных аспектов. Ключевые элементы RoE для SE включают:
1.  **Юридическую совместимость:** Соблюдение отраслевых стандартов (HIPAA, GDPR) и запрет на сбор реальных чувствительных данных.
2.  **Этические ограничения:** Запрет на использование травмирующих тем и обеспечение безопасности персонала.
3.  **Технические границы:** Четкое определение векторов (email, phone, physical) и методов (фишинг, претекстинг) с запретом на деструктивное ПО.
4.  **Протоколы связи:** Четкие процедуры эскалации и остановки операции.

Без детального согласования scope SE-кампания рискует превратиться в источник юридических исков, репутационных потерь и психологического вреда для сотрудников. RoE служит не только ограничителем, но и инструментом защиты как для Red Team, так и для клиента, обеспечивая фокус на измеримых результатах и улучшении безопасности, а не на хаотичной эксплуатации уязвимостей.

## Источники

1.  [Red Team Rules of Engagement: Scope, Limits and Practices - SecureLayer7](https://blog.securelayer7.net/red-team-rules-of-engagement/)
2.  [HIPAA Social Engineering Penetration Testing: Compliance Requirements and Best Practices - AccountableHQ](https://www.accountablehq.com/post/hipaa-social-engineering-penetration-testing-compliance-requirements-and-best-practices)
3.  [Red Team Rules of Engagement: The Complete Guide to Scoping, Legal Authorization, and Deconfliction - Lorikeet Security](https://lorikeetsecurity.com/blog/red-team-rules-of-engagement)
4.  [Rules of Engagement - NCSA](https://www.cyberstudents.org/wp-content/uploads/2021/09/Rules-of-Engagement-NCSA-Facing.pdf)
5.  [Best Practices for Social Engineering - Rapid7](https://help.rapid7.com/metasploit/Content/social-engineering/se-best-practices.html)
6.  [Mastering Rules of Engagement Penetration Testing: A Guide - Exploit Eliminator](https://www.exploiteliminator.com/mastering-rules-of-engagement-penetration-testing-a-guide/)
7.  [Social Engineering Penetration Testing: A Practical Guide - Sprocket Security](https://www.sprocketsecurity.com/blog/social-engineering-penetration-testing-a-practical-guide)
8.  [Social Engineering Penetration Testing: A Full How-To Guide - StationX](https://www.stationx.net/social-engineering-penetration-testing/)
9.  [Penetration Testing: Methodology, Scope & Types of Pentests - Vaadata](https://www.vaadata.com/blog/penetration-testing-methodology-scope-and-types-of-pentests/)
10. [Remote Social Engineering - HALOCK](https://www.halock.com/penetration-testing/remote-social-engineering/)