# Получение начального доступа



## Теория

1. [Получение начального доступа](theory/001-poluchenie-nachalnogo-dostupa.md)
2. [Шеллы и удалённый доступ](theory/002-shelly-i-udalennyi-dostup.md)
3. [Bind Shell: модель, когда атакуемый хост слушает порт](theory/003-bind-shell-model-kogda-atakuemyi-host-slushaet-port.md)
4. [Reverse Shell: модель, когда атакуемый подключается к атакующему](theory/004-reverse-shell-model-kogda-atakuemyi-podklyuchaetsya-k-atakuyuschemu.md)
5. [Реализации reverse shell на Bash, Python и PowerShell](theory/005-realizatsii-reverse-shell-na-bash-python-i-powershell.md)
6. [Стабилизация интерактивного шелла через выделение PTY](theory/006-stabilizatsiya-interaktivnogo-shella-cherez-vydelenie-pty.md)
7. [Webshell](theory/007-webshell.md)
8. [Загрузка webshell через уязвимость file upload](theory/008-zagruzka-webshell-cherez-uyazvimost-file-upload.md)
9. [Обфускация webshell для обхода антивируса](theory/009-obfuskatsiya-webshell-dlya-obhoda-antivirusa.md)
10. [Шифрованные шеллы и техники сокрытия канала управления](theory/010-shifrovannye-shelly-i-tehniki-sokrytiya-kanala-upravleniya.md)
11. [Поиск и адаптация эксплоитов](theory/011-poisk-i-adaptatsiya-eksploitov.md)
12. [Публичные базы эксплоитов: Exploit-DB и аналоги](theory/012-publichnye-bazy-eksploitov-exploit-db-i-analogi.md)
13. [searchsploit как локальный поисковик по базе Exploit-DB](theory/013-searchsploit-kak-lokalnyi-poiskovik-po-baze-exploit-db.md)
14. [CVE Mitre и NVD как первичные источники данных об уязвимостях](theory/014-cve-mitre-i-nvd-kak-pervichnye-istochniki-dannyh-ob-uyazvimostyah.md)
15. [Адаптация публичного PoC под целевую среду](theory/015-adaptatsiya-publichnogo-poc-pod-tselevuyu-sredu.md)
16. [Опасные эксплоиты с риском DoS: согласование с заказчиком](theory/016-opasnye-eksploity-s-riskom-dos-soglasovanie-s-zakazchikom.md)
17. [Тестирование эксплоита в изолированной лаборатории перед прод-применением](theory/017-testirovanie-eksploita-v-izolirovannoi-laboratorii-pered-prod-primeneniem.md)
18. [Генерация пейлоада через msfvenom](theory/018-generatsiya-peiloada-cherez-msfvenom.md)
19. [Параметры msfvenom: тип payload, формат, LHOST и LPORT](theory/019-parametry-msfvenom-tip-payload-format-lhost-i-lport.md)
20. [Форматы вывода msfvenom: exe, dll, raw shellcode, ps1](theory/020-formaty-vyvoda-msfvenom-exe-dll-raw-shellcode-ps1.md)
21. [Staged и stageless payload: компромиссы выбора](theory/021-staged-i-stageless-payload-kompromissy-vybora.md)
22. [Encoders msfvenom и их ограничения против современных AV](theory/022-encoders-msfvenom-i-ih-ogranicheniya-protiv-sovremennyh-av.md)
23. [Генерация shellcode через donut для inline-доставки](theory/023-generatsiya-shellcode-cherez-donut-dlya-inline-dostavki.md)
24. [Обфускация пейлоада](theory/024-obfuskatsiya-peiloada.md)
25. [Упаковщики типа UPX как базовая обфускация payload](theory/025-upakovschiki-tipa-upx-kak-bazovaya-obfuskatsiya-payload.md)
26. [Обфускация PowerShell-скриптов через Invoke-Obfuscation](theory/026-obfuskatsiya-powershell-skriptov-cherez-invoke-obfuscation.md)
27. [Reflective loading: запуск payload в памяти без записи на диск](theory/027-reflective-loading-zapusk-payload-v-pamyati-bez-zapisi-na-disk.md)
28. [AMSI bypass перед загрузкой PowerShell-payload](theory/028-amsi-bypass-pered-zagruzkoi-powershell-payload.md)
29. [ScareCrow и аналогичные генераторы для обхода AV и EDR](theory/029-scarecrow-i-analogichnye-generatory-dlya-obhoda-av-i-edr.md)
30. [Доставка пейлоада](theory/030-dostavka-peiloada.md)
31. [Фишинг с вложением как массовый канал доставки payload](theory/031-fishing-s-vlozheniem-kak-massovyi-kanal-dostavki-payload.md)
32. [HTA и LNK файлы как контейнеры запуска payload](theory/032-hta-i-lnk-faily-kak-konteinery-zapuska-payload.md)
33. [Office-макросы VBA и legacy XLM как вектор доставки](theory/033-office-makrosy-vba-i-legacy-xlm-kak-vektor-dostavki.md)
34. [ISO и IMG обёртки для обхода Mark-of-the-Web](theory/034-iso-i-img-obertki-dlya-obhoda-mark-of-the-web.md)
35. [HTML smuggling: сборка payload в браузере жертвы](theory/035-html-smuggling-sborka-payload-v-brauzere-zhertvy.md)
36. [Drive-by downloads через уязвимости браузера](theory/036-drive-by-downloads-cherez-uyazvimosti-brauzera.md)

## Практика

1. [Практика 10 — Получение начального доступа](practice/01-praktika-shelly-i-udalennyi-dostup/README.md)
2. [Практика 11 — Получение начального доступа](practice/02-praktika-poisk-i-adaptatsiya-eksploitov/README.md)
3. [Практика 12 — Получение начального доступа](practice/03-praktika-generatsiya-peiloada-cherez-msfvenom/README.md)
4. [Практика 13 — Получение начального доступа](practice/04-praktika-obfuskatsiya-peiloada/README.md)
5. [Практика 14 — Получение начального доступа](practice/05-praktika-dostavka-peiloada/README.md)

## Исходные страницы

- [Теория](https://edu.innopoligon.ru/course/93/topic/297)
- [Практика](https://edu.innopoligon.ru/course/93/topic/298)
