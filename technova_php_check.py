#!/usr/bin/env python3
"""Technova PHP Check 1.0 — 22/10/2026. Python 3.8+, Linux/systemd.

Uso: python3 technova_php_check.py
     sudo python3 technova_php_check.py --apply
     python3 technova_php_check.py --self-test

Escopo: triagem das CVE-2026-109618 e CVE-2026-109619, nao auditoria geral.
Base: https://www.php.net/archive/2026.php
Limiares upstream: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.
Pacotes com backport exigem confirmacao do fornecedor. Um numero menor nao
comprova vulnerabilidade. Um numero maior so satisfaz esta referencia historica.

Diagnostico padrao: somente leitura local, sem atualizar metadados.
--apply: root + terminal interativo; backup de configuracoes; refresh, simulacao,
confirmacao humana, upgrade dos pacotes selecionados e reinicio de servicos.
Scripts dos pacotes podem reiniciar servicos durante a propria instalacao.
Nao troca repositorios/streams nem desativa SELinux, firewall ou verificacao GPG.
Nao migra versoes EOL. Nao instala PHP ausente. Nao cobre Windows, containers,
compilacoes manuais, paineis ou varias series PHP em paralelo automaticamente.
Revise o plano: dependencias tambem podem ser atualizadas. Garanta backup de
dados/aplicacoes e janela de manutencao; backup aqui e so de configuracoes.
Nao ha rollback automatico. Teste primeiro em homologacao.
Nao detecta invasao nem valida login/formularios ou todos os vhosts.
Saidas: 0=triagem/fluxo concluido, 1=erro, 2=analise manual/cancelamento.
Nunca interprete exit 0 como certificacao de seguranca.
Licenca: MIT (permissao de usar/modificar/distribuir; sem garantia).
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
os.environ['LC_ALL'] = 'C'

def run(args, check=True, capture=True):
    p = subprocess.run(args, text=True, stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.STDOUT if capture else None)
    if check and p.returncode:
        raise RuntimeError('Falhou: ' + ' '.join(args) + '\n' + (p.stdout or ''))
    return p

def version(text):
    m = re.search(r'(?<!\d)(\d+)\.(\d+)\.(\d+)', text)
    return tuple(map(int, m.groups())) if m else None

def status(v):
    if not v or v[:2] not in FIXED:
        return 'FORA DA MATRIZ: verificar fornecedor/ciclo de suporte.'
    if v[2] < FIXED[v[:2]]:
        return 'ABAIXO DO LIMIAR: potencialmente afetado; backport NAO verificado.'
    return 'LIMIAR UPSTREAM ATENDIDO para estas duas CVEs; processo web nao atestado.'

def inventory(family):
    if family == 'rpm':
        raw = run(['rpm', '-qa', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\n']).stdout
        return [tuple(x.split('\t', 1)) for x in raw.splitlines()
                if re.match(r'^(php|alt-php|ea-php)', x)]
    raw = run(['dpkg-query', '-W', '-f=${Package}\t${Version}\t${db:Status-Status}\n']).stdout
    return [(a, b) for line in raw.splitlines() if len(parts := line.split('\t')) == 3
            for a, b, state in [parts] if state == 'installed'
            and re.match(r'^(php|libapache2-mod-php)', a)]

def services():
    raw = run(['systemctl', 'list-units', '--type=service', '--state=running',
               '--no-legend', '--plain', '--no-pager']).stdout
    return [line.split()[0] for line in raw.splitlines() if line.split()
            and re.match(r'^(php.*fpm|httpd|apache2)\.service$', line.split()[0])]

def checks(units):
    for unit in units:
        if unit == 'php-fpm.service':
            run(['php-fpm', '-t'])
        elif re.fullmatch(r'php\d+\.\d+-fpm.service', unit):
            run(['php-fpm' + unit[3:-12], '-t'])
        elif unit == 'httpd.service':
            run(['httpd', '-t'])
        elif unit == 'apache2.service':
            run(['apache2ctl', 'configtest'])
        else:
            raise RuntimeError('Servico nao padrao: ' + unit)

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--apply', action='store_true')
    ap.add_argument('--self-test', action='store_true')
    args = ap.parse_args()
    if args.self_test:
        assert version('PHP 8.3.36 (cli)') == (8, 3, 36)
        for branch, patch in FIXED.items():
            assert status((*branch, patch)).startswith('LIMIAR')
            assert status((*branch, patch-1)).startswith('ABAIXO')
        assert status((8, 1, 99)).startswith('FORA')
        assert status((8, 6, 0)).startswith('FORA')
        assert status(None).startswith('FORA')
        assert 'php8.3-fpm.service'[3:-12] == '8.3'
        print('Autoteste: OK (classificacao de versoes e nomes de servico).')
        return 0
    if sys.platform != 'linux':
        print('SO fora do escopo: Linux necessario.'); return 2
    osinfo = Path('/etc/os-release').read_text()
    print('TECHNOVA | PHP CHECK 1.0 | referencia 22/10/2026')
    print(osinfo)
    family = 'rpm' if shutil.which('rpm') else 'deb' if shutil.which('dpkg-query') else None
    if not family:
        print('Gerenciador fora do escopo.'); return 2
    packages = inventory(family)
    for name, ver in packages:
        print(name, ver)
    runtimes = [(n, v) for n, v in packages
                if re.fullmatch(r'php(?:\d+\.\d+)?-(cli|common|fpm|cgi)', n)
                or n.startswith('libapache2-mod-php')]
    for name, ver in runtimes:
        print(name + ': ' + status(version(ver)))
    print('\nEscopo local: containers, vhosts, backports e processos externos nao verificados.')
    if not args.apply:
        print('Modo diagnostico: nenhuma alteracao aplicada. --apply habilita fluxo assistido.')
        return 0 if runtimes else 2
    if os.geteuid() != 0 or not sys.stdin.isatty():
        print('--apply exige root e terminal interativo.'); return 2
    if Path('/.dockerenv').exists() or Path('/run/.containerenv').exists():
        print('Container: corrigir imagem e reimplantar.'); return 2
    if not Path('/run/systemd/system').exists():
        print('Sem systemd ativo: procedimento manual.'); return 2
    branches = {version(v)[:2] for _, v in runtimes if version(v)}
    if not runtimes or len(branches) != 1 or not branches <= FIXED.keys():
        print('Runtime ausente, varias series ou versao fora da matriz: analise manual.'); return 2
    if any(re.match(r'^(alt-php|ea-php|php\d{2})', n) for n, _ in packages):
        print('Pacotes de painel/SCL: procedimento do fornecedor necessario.'); return 2
    if any(Path(p).exists() for p in ['/usr/local/cpanel', '/usr/local/psa', '/usr/local/bin/php', '/usr/local/sbin/php-fpm']):
        print('Painel ou instalacao local detectada: analise manual.'); return 2
    if all(status(version(v)).startswith('LIMIAR') for _, v in runtimes):
        print('Pacotes identificados ja atendem a referencia; nenhuma atualizacao executada.')
        print('Confirme separadamente a versao dos processos web em execucao.'); return 0
    units = services()
    if not units:
        print('Nenhum servico web padrao ativo identificado: analise manual.'); return 2
    checks(units)
    print('Servicos a reiniciar:', ', '.join(units))
    print('Confirme backup de dados e janela; scripts de pacotes podem reiniciar servicos.')
    if input('Digite PREPARAR para salvar configuracoes e consultar atualizacoes: ') != 'PREPARAR':
        return 2
    os.umask(0o077)
    dest = Path(tempfile.mkdtemp(prefix='technova-php-', dir='/root'))
    paths = ['/etc/php', '/etc/php.ini', '/etc/php.d', '/etc/php-fpm.conf',
             '/etc/php-fpm.d', '/etc/httpd', '/etc/apache2']
    with tarfile.open(dest / 'configuracoes.tar.gz', 'w:gz') as archive:
        for path in paths:
            if Path(path).exists(): archive.add(path, arcname=path.lstrip('/'))
    (dest / 'inventario-antes.txt').write_text(osinfo + '\n' + repr(packages) + '\n' + repr(units))
    print('Backup de configuracoes:', dest)
    if family == 'rpm':
        manager = shutil.which('dnf') or shutil.which('yum')
        if not manager: raise RuntimeError('DNF/YUM ausente.')
        names = [n for n, _ in packages if n == 'php' or n.startswith('php-')]
        run([manager, 'makecache'], capture=False)
        command = [manager, 'upgrade'] + names
        plan = run(command[:2] + ['--assumeno'] + names, check=False)
        # DNF returns nonzero when --assumeno cancels: always retain full plan.
        if 'Nothing to do' in (plan.stdout or ''):
            print(plan.stdout)
            print('Sem atualizacao disponivel. Correcao nao comprovada; consultar fornecedor.')
            return 2
        if 'Transaction Summary' not in (plan.stdout or '') or re.search(r'(?im)^.*(?:Error:|Problem:)', plan.stdout or ''):
            raise RuntimeError('Plano DNF/YUM ausente ou com erro:\n' + (plan.stdout or ''))
    else:
        branch = '.'.join(map(str, next(iter(branches))))
        names = [n for n, _ in packages if n.startswith('php' + branch + '-')
                 or n == 'libapache2-mod-php' + branch]
        run(['apt-get', 'update', '-o', 'APT::Update::Error-Mode=any'], capture=False)
        command = ['apt-get', '--no-remove', '--only-upgrade', 'install'] + names
        plan = run(command[:1] + ['--simulate'] + command[1:])
    if not names: raise RuntimeError('Nenhum pacote selecionado.')
    print(plan.stdout)
    (dest / 'plano.txt').write_text(plan.stdout or '')
    print('Revise o plano. Nao prossiga se houver troca de serie, remocoes ou erros.')
    print('Backport: confirme o aviso do fornecedor antes de decidir se precisa atualizar.')
    if input('Digite ATUALIZAR para executar o gerenciador interativo: ') != 'ATUALIZAR':
        return 2
    run(command, capture=False)  # No -y: package manager presents final transaction.
    after = inventory(family)
    (dest / 'inventario-depois.txt').write_text(repr(after))
    if after == packages:
        print('Nenhum pacote alterado. Correcao NAO comprovada; conferir fornecedor.'); return 2
    checks(units)
    for unit in units:
        run(['systemctl', 'restart', unit])
        run(['systemctl', 'is-active', '--quiet', unit])
    print('Atualizacao concluida; servicos reiniciados. Validar aplicacoes pelo navegador.')
    print('Versoes apos a transacao:')
    for name, ver in after:
        if any(name == n for n, _ in runtimes): print(name, ver, status(version(ver)))
    print('Nao comprova ausencia de invasao ou correcao de outros runtimes.')
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, OSError, KeyboardInterrupt, EOFError) as exc:
        print('\nINTERROMPIDO:', exc, file=sys.stderr)
        print('Se houve instalacao, conferir servicos e logs; sem rollback automatico.', file=sys.stderr)
        sys.exit(1)
