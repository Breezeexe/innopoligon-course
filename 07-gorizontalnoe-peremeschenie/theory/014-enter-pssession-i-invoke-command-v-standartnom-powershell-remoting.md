# Удалённое выполнение в Windows: Enter-PSSession и Invoke-Command в контексте горизонтального перемещения

## Контекст и базовые понятия: PowerShell Remoting как вектор горизонтального перемещения

PowerShell Remoting (PSRemoting) — это архитектура удалённого управления, позволяющая выполнять команды, скрипты и создавать интерактивные сессии на удалённых узлах Windows. В контексте тестирования на проникновение и реагирования на инциденты (IR) PSRemoting является критически важным механизмом горизонтального перемещения, так как он предоставляет легитимный, «белый» канал связи, который часто остаётся открытым в корпоративных сетях для целей администрирования. В отличие от RDP, требующего графического интерфейса и высокой пропускной способности, PSRemoting работает поверх протоколов WinRM (Windows Remote Management), что делает его малозаметным для базовых сетевых сенсоров и эффективным для автоматизации атак.

Ключевое разграничение в теме касается двух основных cmdlet: `Enter-PSSession` и `Invoke-Command`. Несмотря на то, что оба используют один и тот же underlying-механизм (WSMan-протокол), их функциональное назначение и влияние на инфраструктуру различаются. `Enter-PSSession` предназначен для создания интерактивной сессии, где пользователь получает командную строку удалённой системы. `Invoke-Command` предназначен для пакетного (batch) или однократного выполнения скриптблоков, что делает его более подходящим для автоматизации атак и массового распространения.

Путаница между этими понятиями часто возникает из-за того, что оба они могут использовать один и тот же параметр `-ComputerName`. Однако архитектурно `Enter-PSSession` всегда подразумевает создание сессии (даже если она временная и закрывается сразу после выхода), тогда как `Invoke-Command` может работать как с существующими сессиями (`-Session`), так и без них, создавая временные подключения «на лету». Для аналитика SOC или пентестера важно понимать, что `Enter-PSSession` генерирует события входа в систему (Logon Type 10 — RemoteInteractive в Event ID 4624), тогда как `Invoke-Command` без `-Session` часто маскируется под фоновую службу или планировщик задач, а с `-Session` — под административное управление.

Важным аспектом является разница между PowerShell Remoting (WinRM) и SSH-remoting (в PowerShell Core 6+). Классический PSRemoting, описываемый в данном конспекте, работает на Windows-хостах через WinRM. SSH-remoting требует установки OpenSSH Server и работает кроссплатформенно. В рамках Windows-инфраструктур (Active Directory) WinRM остаётся доминирующим протоколом, так как он интегрирован с Kerberos и NTLM, что упрощает аутентификацию, но усложняет обнаружение аномалий, так как трафик выглядит как легитимный административный.

| Характеристика | Enter-PSSession | Invoke-Command |
| :--- | :--- | :--- |
| **Основная цель** | Интерактивное управление (1:1) | Пакетное выполнение или скриптинг (1:N или 1:1) |
| **Тип сессии** | Создаёт интерактивную консольную сессию | Может создавать сессию или использовать временное соединение |
| **Видимость для пользователя** | Высокая (меняется prompt, активный процесс) | Низкая (выполняется в фоне, если не выводить результат) |
| **Сетевой трафик** | Длительное WSMan-соединение | Короткие WSMan-запросы или длительные сессии |
| **Индикаторы в логах** | Event ID 4624 (Logon Type 10), WinRM-события | WinRM-события (Event ID 800/801), возможные события планировщика |
| **Применение в атаке** | Ручное горизонтальное перемещение, «живой» доступ | Автоматизация, запуск payload, сбор данных, lateral movement |
| **Ограничения** | Только одна удалённая машина за сессию | Поддержка множественных узлов, скриптблоков, асинхронности |

Для специалиста по безопасности понимание этих различий определяет стратегию детекции. Интерактивная сессия (`Enter-PSSession`) часто указывает на активность злоумышленника «в реальном времени» (live hacking), тогда как `Invoke-Command` может быть частью автоматизированного скрипта распространения (например, в рамках атаки с использованием Cobalt Strike или Empire).

```text
[Атакующий] ──(WinRM/HTTPS)──▶ [WinRM Service (Remote)]
      │                              │
      │ 1. Enter-PSSession           │ Создает интерактивную сессию
      │    (Interactive Shell)       │ (Logon Type 10)
      │                              │
      │ 2. Invoke-Command            │ Выполняет скриптблок
      │    (ScriptBlock Execution)   │ (Фоновое выполнение)
      │                              │
      ▼                              ▼
[Локальная консоль]           [Удаленный процесс (svchost.exe)]
```

## Внутреннее устройство: Архитектура WinRM и механизмы аутентификации

Стандартный PowerShell Remoting базируется на протоколе WS-Management (WinRM), который является реализацией стандарта WS-Management, разработанной DMTF. WinRM работает как служба Windows (winrm), прослушивающая порты TCP 5985 (HTTP) и TCP 5986 (HTTPS). Архитектурно процесс удалённого выполнения можно разделить на три уровня: транспортный, аутентификационный и исполнительный.

На транспортном уровне WinRM использует SOAP-сообщения, инкапсулированные в HTTP/HTTPS. Это означает, что трафик PowerShell Remoting выглядит как обычный веб-трафик. Для атакующего это преимущество: трафик может проходить через прокси и межсетевые экраны, разрешающие HTTP/HTTPS. Для защитника это вызов: стандартные IDS/IPS могут не детектировать вредоносную нагрузку, если она зашифрована HTTPS или маскируется под легитимный SOAP-запрос.

На уровне аутентификации WinRM поддерживает несколько методов: Kerberos, NTLM, Certificate, Basic и Negotiate. Выбор метода зависит от конфигурации WinRM на клиенте и сервере, а также от сетевой среды (домен или рабочая группа).
1.  **Kerberos**: Основной метод в домене Active Directory. Требует наличия Service Principal Name (SPN) `HOST/имя_хоста` или `HOST/IP`. Kerberos обеспечивает взаимную аутентификацию и делегирование. В контексте атаки использование Kerberos делает трафик максимально легитимным, так как билеты TGT и TGS генерируются стандартным образом.
2.  **NTLM**: Используется в рабочих группах или при отсутствии Kerberos. NTLM более уязвим к ретрансляционным атакам (Pass-the-Hash), если не настроена защита от NTLM ретрансляции (LmCompatibilityLevel).
3.  **Basic**: Передает учётные данные в виде Base64-кодированной строки. Требует обязательного использования HTTPS для безопасности. В домене по умолчанию отключён из-за рисков перехвата.
4.  **Certificate**: Использует клиентские сертификаты для аутентификации. Применяется в сложных инфраструктурах с доверием между доменами.

Исполнительный уровень включает в себя конфигурацию Endpoint (конечной точки). По умолчанию существует две встроенные конечные точки: `Microsoft.PowerShell` (для PowerShell 2.0/3.0/4.0/5.1) и `Microsoft.PowerShell32` (для 32-битных сессий). В PowerShell 6+ появляются конечные точки для PowerShell Core. Конечная точка определяет, какие модули загружаются, какой уровень безопасности (Execution Policy) применяется и какие ограничения накладываются на сессию (Session Configuration).

Критическим внутренним механизмом является **Delegation** (делегирование) и проблема **Double-Hop**. Когда атакующий подключается к машине A, а затем пытается подключиться с машины A к машине B, аутентификационные данные не передаются автоматически из-за ограничений Kerberos/NTLM (credentials не могут быть использованы дважды без явного делегирования). Для решения этой проблемы в PowerShell Remoting используются:
*   **Kerberos Constrained Delegation (KCD)**: Разрешает машине A выступать от имени пользователя для доступа к машине B.
*   **CredSSP**: Позволяет делегировать учётные данные. Однако CredSSP считается небезопасным, так как уязвим к ретрансляции учётных данных, если не настроена строгая проверка сервера.
*   **Second-Hop Workaround**: Использование `Invoke-Command` с параметром `-Authentication CredSSP` или сохранение учётных данных в переменной и передача их в скриптблок (что небезопасно, так как данные могут быть выгружены из памяти).

Для пентестера понимание этого механизма определяет выбор инструмента. Если цель — быстрое перемещение без настройки делегирования, часто используются методы обхода, такие как использование `WMI` или `DCOM` вместо PSRemoting для второго хопа, либо настройка KCD в домене.

```json
{
  "winrm_config": {
    "service": {
      "hostname": "winrm",
      "ports": {
        "http": 5985,
        "https": 5986
      },
      "authentication_methods": [
        "Kerberos",
        "NTLM",
        "Certificate",
        "Basic",
        "Negotiate"
      ]
    },
    "endpoint": {
      "name": "Microsoft.PowerShell",
      "type": "PowerShell",
      "security_descriptor": "S-1-5-32-544", 
      "description": "Default PowerShell endpoint"
    },
    "transport": {
      "protocol": "WS-Management",
      "encoding": "SOAP",
      "content_type": "application/soap+xml"
    }
  }
}
```

## Применение и работа с предметом: Команды, конфигурация и детекция

На практике работа с PowerShell Remoting для горизонтального перемещения включает три этапа: подготовка среды, установление соединения и выполнение действий.

**1. Подготовка среды (WinRM Configuration)**
Для работы PSRemoting служба WinRM должна быть запущена. Команда `Enable-PSRemoting` настраивает службу, создаёт слушатель (listener) на порту 5985/5986 и добавляет правило в брандмауэр. В доменной среде по умолчанию клиенты доверяют всем хостам в домене. В рабочих группах необходимо добавить удалённый хост в список `TrustedHosts` на клиенте, иначе аутентификация не удастся.

```powershell
# Настройка TrustedHosts на атакующей машине (если не в домене)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.1.10,192.168.1.11" -Force

# Проверка конфигурации слушателя
Get-ChildItem WSMan:\localhost\Listener
```

**2. Использование Enter-PSSession**
`Enter-PSSession` используется для интерактивного входа. Он принимает параметры `-ComputerName` (или `-HostName`), `-Credential` (если нужны другие учётные данные) и `-Authentication`.

```powershell
# Интерактивный вход с явным указанием учётных данных
$cred = Get-Credential
Enter-PSSession -ComputerName 192.168.1.10 -Credential $cred -Authentication Negotiate

# Вывод: [192.168.1.10]: PS C:\Users\Target\Documents>
# Теперь все команды выполняются на удалённой машине
Get-ChildItem C:\Users
```

**3. Использование Invoke-Command**
`Invoke-Command` более гибок. Он может выполнять команды на множестве машин параллельно.

```powershell
# Выполнение на одной машине без интерактивной сессии
Invoke-Command -ComputerName 192.168.1.10 -Credential $cred -ScriptBlock {
    Get-Process | Where-Object {$_.WorkingSet -gt 100MB}
}

# Параллельное выполнение на множестве машин
Invoke-Command -ComputerName PC01,PC02,PC03 -ScriptBlock {
    Get-EventLog -LogName Security -Newest 5
}
```

**4. Обход ограничений и продвинутые техники**
В современных средах (Windows 10/11, Server 2016+) включена функция **Constrained Language Mode** и **Script Block Logging**. Атакующие могут использовать обходные пути:
*   **EncodedCommand**: Передача скрипта в Base64 для обхода политик выполнения и логирования команд.
*   **JEA (Just Enough Administration)**: Если цель — привилегированный доступ, атакующие могут пытаться эксплуатировать уязвимости в конфигурациях JEA.
*   **PSRemoting через SSH**: В PowerShell 7+ можно использовать SSH-транспорт, что позволяет обходить ограничения WinRM и работать с Linux-хостами.

**Детекция и мониторинг**
Для обнаружения несанкционированного PSRemoting необходимо мониторить:
1.  **Event ID 800/801**: WinRM-события (успешные/неуспешные подключения).
2.  **Event ID 4624**: Logon Type 10 (RemoteInteractive) с необычными источниками.
3.  **Script Block Logging (Event ID 4104)**: Логирование исполняемых скриптблоков.
4.  **Network Traffic**: Мониторинг исходящих соединений на порты 5985/5986 с рабочих станций (должны идти только от серверов управления).

```powershell
# Пример правила Sigma для детекции подозрительного PSRemoting
title: Suspicious PowerShell Remoting via WinRM
id: 8f3a9c1d-2b4e-4f5a-9c8d-1e2f3a4b5c6d
description: Detects potential lateral movement using PowerShell Remoting
severity: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\WindowsPowerShell\v1.0\powershell.exe'
        CommandLine: '*-EncodedCommand*'
    condition: selection
falsepositives:
    - Administration, legitimate remote management
```

## Сквозной практический пример: Горизонтальное перемещение через WinRM

**Исходные условия:**
*   **Среда**: Домашняя лаборатория на базе Windows 10 (Client) и Windows Server 2019 (Server).
*   **Роль**: Тестировщик на проникновение, имеющий локальные права администратора на Client.
*   **Цель**: Выполнить команду на Server, используя учётные данные, полученные из памяти Client (имитация атаки с использованием Mimikatz или SharpHound).
*   **Инструменты**: PowerShell 5.1 (на Client), PowerShell 7 (на Server, для демонстрации кросс-версионности), WinRM.

**Шаг 1: Проверка доступности WinRM на целевом хосте**
Перед попыткой подключения необходимо убедиться, что WinRM слушает порт и доступен.

```powershell
# Проверка порта 5985 на целевом сервере
Test-NetConnection -ComputerName 192.168.1.50 -Port 5985

# Ожидаемый вывод:
# TcpTestSucceeded : True
# Если False, то WinRM отключён или заблокирован фаерволом
```

**Шаг 2: Подготовка учётных данных**
Предположим, что учётные данные `admin:Password123!` были получены ранее. Создаём объект PSCredential.

```powershell
$User = "LAB\admin"
$Pass = "Password123!" | ConvertTo-SecureString -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential($User, $Pass)
```

**Шаг 3: Выполнение команды через Invoke-Command (пакетный режим)**
Используем `Invoke-Command` для получения информации о системе на Server без создания интерактивной сессии. Это менее заметно для пользователя, чем `Enter-PSSession`.

```powershell
Invoke-Command -ComputerName 192.168.1.50 -Credential $Cred -ScriptBlock {
    Get-ComputerInfo | Select-Object CsName, OsVersion, CsProcessors
} -Authentication Negotiate

# Ожидаемый вывод:
# CsName       : SERVER01
# OsVersion    : 10.0.17763
# CsProcessors : Intel64 Family 6 Model 158 Stepping 9, GenuineIntel
```

**Шаг 4: Интерактивное перемещение через Enter-PSSession**
Если требуется более сложное взаимодействие, создаём интерактивную сессию.

```powershell
Enter-PSSession -ComputerName 192.168.1.50 -Credential $Cred -Authentication Negotiate

# Ожидаемый вывод:
# [SERVER01]: PS C:\Users\admin\Documents>

# Внутри сессии выполняем команду
whoami
# Вывод: lab\server01$ (или lab\admin, в зависимости от контекста)

# Выход из сессии
Exit-PSSession
```

**Шаг 5: Обход ограничения TrustedHosts (если не в домене)**
Если Client и Server не в одном домене, необходимо добавить Server в TrustedHosts на Client.

```powershell
# На Client
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.1.50" -Concatenate -Force

# Повторная попытка подключения
Enter-PSSession -ComputerName 192.168.1.50 -Credential $Cred
```

**Ожидаемый вывод:**
Пример демонстрирует, как легитимный инструмент администрирования может быть использован для горизонтального перемещения. Ключевым моментом является использование `-Authentication Negotiate` или `Kerberos` для обхода ограничений аутентификации и `-ScriptBlock` для скрытого выполнения команд. В реальной атаке вместо `Get-ComputerInfo` был бы запущен вредоносный бинарник или скрипт.

## Аналитический вывод

PowerShell Remoting, реализованный через `Enter-PSSession` и `Invoke-Command`, представляет собой мощный механизм горизонтального перемещения, который эффективно маскируется под легитимное административное действие. Архитектурная основа на протоколе WinRM (WS-Management) обеспечивает совместимость с доменными инфраструктурами и поддержку Kerberos, что делает трафик PSRemoting трудноотличимым от нормального административного трафика. Различие между `Enter-PSSession` (интерактивный доступ) и `Invoke-Command` (пакетное выполнение) определяет тактику применения: первое используется для ручного контроля, второе — для автоматизации и массового распространения.

Для специалистов по безопасности критически важно мониторить не только наличие подключений WinRM, но и контекст их возникновения: необычные источники IP, использование учётных данных с рабочих станций, а также логирование исполняемых скриптблоков (Event ID 4104). Обходные техники, такие как использование `TrustedHosts` или CredSSP, сами по себе являются индикаторами компрометации, так как в стандартной конфигурации они не требуются. Понимание внутренних механизмов делегирования и аутентификации позволяет не только эмулировать атаки, но и правильно настраивать политики безопасности, ограничивая доступ к WinRM только доверенными узлами управления.

## Источники

1.  [Enable-PSRemoting (Microsoft.PowerShell.Core)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enable-psremoting?view=powershell-7.6)
2.  [Invoke-Command (Microsoft.PowerShell.Core)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command?view=powershell-7.6)
3.  [New-PSSession (Microsoft.PowerShell.Core)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession?view=powershell-7.6)
4.  [About Remote Requirements (Microsoft Learn)](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_requirements)
5.  [PowerShell Remoting Over SSH (Microsoft Learn)](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/ssh-remoting-in-powershell-core)
6.  [SANS Institute: Month of PowerShell - PowerShell Remoting, Part 1](https://www.sans.org/blog/powershell-remoting-part-1)
7.  [Stack Overflow: Powershell remoting with ip-address as target](https://stackoverflow.com/questions/6587426/powershell-remoting-with-ip-address-as-target)
8.  [Spiceworks Community: New to Powershell...need to run commands on remote computers](https://community.spiceworks.com/t/new-to-powershell-need-to-run-commands-on-remote-computers/488491)
9.  [PowerShell Forums: Invoke-Command in PSSession](https://forums.powershell.org/t/invoke-command-in-pssession/6509)