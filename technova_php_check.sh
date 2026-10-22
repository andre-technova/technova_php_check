#!/usr/bin/env bash
# Technova PHP Check 1.0 — Bash 4+, Linux/systemd — referencia: 22/10/2026
# Uso: bash technova_php_check.sh [--apply | --self-test | --help]
# Triagem especifica: CVE-2026-109618 e CVE-2026-109619.
# Fonte: https://www.php.net/archive/2026.php
# MIT: permitido usar, modificar e distribuir; sem garantia.
# Nao e auditoria de invasao nem certificado de seguranca.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 077
trap 'rc=$?; if (( rc != 2 )); then printf "\nERRO na linha %s. Se houve instalacao, confira servicos e logs. Sem rollback automatico.\n" "$LINENO" >&2; fi' ERR

help_text() {
    cat <<'EOF'
TECHNOVA PHP CHECK — Bash 4+, sem Python
  bash technova_php_check.sh              Diagnostico local, somente leitura
  sudo bash technova_php_check.sh --apply Atualizacao assistida
  bash technova_php_check.sh --self-test  Testes internos sem alterar pacotes

Linux: RPM com DNF/YUM ou Debian/Ubuntu com APT; --apply exige systemd.
Referencia historica: PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.
Backports precisam de confirmacao do fornecedor. Versao menor nao prova falha.
Versao acima do limiar nao garante ausencia de outras vulnerabilidades.
Atualizacao usa repositorios existentes; nao troca stream nem instala PHP ausente.
O operador revisa a transacao e confirma. Dependencias podem ser atualizadas.
Scripts de pacotes podem reiniciar servicos durante a instalacao.
Tenha backup dos dados e uma janela: a copia feita aqui e so de configuracoes.
Nao ha rollback automatico, teste funcional web ou verificacao de invasao.
Windows, containers, paineis, builds locais e multiplas series: analise manual.
Nao atesta o PHP em cada vhost nem processos antigos. Teste em homologacao.
Saida 0: fluxo concluido, NAO certificado de seguranca; 1: erro; 2: analise/cancelado.
EOF
}

classify() {
    local ver=$1 major minor patch threshold
    if [[ $ver =~ (^|[^0-9])([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
        major=${BASH_REMATCH[2]}; minor=${BASH_REMATCH[3]}; patch=${BASH_REMATCH[4]}
        case "$major.$minor" in
            8.2) threshold=35;; 8.3) threshold=36;; 8.4) threshold=27;; 8.5) threshold=12;;
            *) printf 'FORA_DA_MATRIZ'; return;;
        esac
        if (( 10#$patch >= threshold )); then printf 'LIMIAR_ATENDIDO'; else printf 'ABAIXO_DO_LIMIAR'; fi
    else printf 'INCONCLUSIVO'; fi
}

inventory() {
    if [[ $family == rpm ]]; then
        rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' |
            awk '$1 ~ /^(php|alt-php|ea-php)/' | sort
    else
        dpkg-query -W '-f=${Package}\t${Version}\t${db:Status-Status}\n' |
            awk -F '\t' '$3 == "installed" && $1 ~ /^(php|libapache2-mod-php)/ {print $1 "\t" $2}' | sort
    fi
}

validate_configs() {
    local unit
    for unit in "${units[@]}"; do
        case "$unit" in
            php-fpm.service) php-fpm -t;;
            httpd.service) httpd -t;;
            apache2.service) apache2ctl configtest;;
            *)
                if [[ $unit =~ ^php([0-9]+\.[0-9]+)-fpm\.service$ ]]; then
                    "php-fpm${BASH_REMATCH[1]}" -t
                else printf 'Servico nao padrao: %s\n' "$unit" >&2; return 1; fi;;
        esac
    done
}

main() {
    local mode=${1:---audit} family before after name ver state branch='' current
    local unsupported=0 parallel=0 all_fixed=1 runtime_count=0 manager answer backup plan code=0
    local -a names=() units=() paths=() command=()
    (( $# <= 1 )) || { help_text; return 2; }
    case "$mode" in
        --help|-h) help_text; return 0;;
        --self-test)
            [[ $(classify 8.2.34) == ABAIXO_DO_LIMIAR ]]
            [[ $(classify 8.2.35) == LIMIAR_ATENDIDO ]]
            [[ $(classify 8.3.32-1.module_php.8.3.el9.remi) == ABAIXO_DO_LIMIAR ]]
            [[ $(classify 8.3.36-1.module_php.8.3.el9.remi) == LIMIAR_ATENDIDO ]]
            [[ $(classify 8.4.26) == ABAIXO_DO_LIMIAR ]]
            [[ $(classify 8.4.27) == LIMIAR_ATENDIDO ]]
            [[ $(classify 8.5.11) == ABAIXO_DO_LIMIAR ]]
            [[ $(classify 8.5.12) == LIMIAR_ATENDIDO ]]
            [[ $(classify 8.1.99) == FORA_DA_MATRIZ ]]
            [[ $(classify 8.6.0) == FORA_DA_MATRIZ ]]
            [[ $(classify unknown) == INCONCLUSIVO ]]
            printf 'Autoteste: 11 casos OK. Nenhuma alteracao no sistema.\n'; return 0;;
        --audit|--apply) :;;
        *) help_text; return 2;;
    esac
    [[ $(uname -s) == Linux && -r /etc/os-release ]] || { printf 'SO fora do escopo.\n'; return 2; }
    printf 'TECHNOVA | PHP CHECK | referencia 22/10/2026\n\n'
    cat /etc/os-release
    if command -v rpm >/dev/null; then family=rpm
    elif command -v dpkg-query >/dev/null; then family=deb
    else printf 'Gerenciador fora do escopo.\n'; return 2; fi
    before=$(inventory)
    printf '\nPacotes instalados:\n%s\n\n' "${before:-Nenhum pacote PHP identificado.}"
    while IFS=$'\t' read -r name ver; do
        [[ -n $name ]] || continue
        [[ $name =~ ^(alt-php|ea-php|php[0-9]{2}) ]] && unsupported=1
        if [[ $name =~ ^php([0-9]+\.[0-9]+)?-(cli|common|fpm|cgi)$ || $name =~ ^libapache2-mod-php ]]; then
            runtime_count=$((runtime_count+1))
            state=$(classify "$ver")
            printf '%s: %s\n' "$name" "$state"
            [[ $state == LIMIAR_ATENDIDO ]] || all_fixed=0
            if [[ $state == FORA_DA_MATRIZ || $state == INCONCLUSIVO ]]; then unsupported=1; fi
            if [[ $ver =~ ([0-9]+\.[0-9]+)\.[0-9]+ ]]; then
                current=${BASH_REMATCH[1]}
                if [[ -n $branch && $branch != "$current" ]]; then parallel=1; fi
                branch=$current
            fi
        fi
    done <<< "$before"
    printf '\nABAIXO_DO_LIMIAR: potencialmente afetado; backport NAO verificado.\n'
    printf 'LIMIAR_ATENDIDO: referencia upstream satisfeita, sem atestar processos web.\n'
    printf 'Containers, outros binarios, todos os vhosts e invasoes nao verificados.\n'
    if [[ $mode != --apply ]]; then
        printf 'Diagnostico concluido; nenhuma alteracao aplicada.\n'
        if (( runtime_count == 0 )); then return 2; fi
        return 0
    fi
    [[ $EUID == 0 && -t 0 ]] || { printf '--apply exige root e terminal interativo.\n'; return 2; }
    [[ -d /run/systemd/system && ! -e /.dockerenv && ! -e /run/.containerenv ]] || {
        printf 'Sem systemd ou container detectado: analise manual.\n'; return 2;
    }
    for name in /usr/local/cpanel /usr/local/psa /usr/local/bin/php /usr/local/sbin/php-fpm; do
        [[ ! -e $name ]] || unsupported=1
    done
    if (( unsupported || parallel || runtime_count == 0 )); then
        printf 'Instalacao especial, varias series ou versao fora da matriz: analise manual.\n'; return 2
    fi
    if (( all_fixed )); then
        printf 'Pacotes identificados ja atendem a referencia. Nenhuma atualizacao necessaria neste escopo.\n'
        printf 'Confirme separadamente a versao dos processos em execucao.\n'; return 0
    fi
    plan=$(systemctl list-units --type=service --state=running --no-legend --plain --no-pager)
    while read -r name _; do
        if [[ $name =~ ^(php.*fpm|httpd|apache2)\.service$ ]]; then units+=("$name"); fi
    done <<< "$plan"
    (( ${#units[@]} )) || { printf 'Sem servico web padrao ativo: analise manual.\n'; return 2; }
    validate_configs
    printf '\nServicos a reiniciar: %s\n' "${units[*]}"
    printf 'Garanta backup de dados e janela. Scripts de pacotes podem reiniciar servicos.\n'
    read -r -p 'Digite PREPARAR para salvar configuracoes e consultar atualizacoes: ' answer
    [[ $answer == PREPARAR ]] || return 2
    backup=$(mktemp -d /root/technova-php-XXXXXXXX)
    for name in etc/php etc/php.ini etc/php.d etc/php-fpm.conf etc/php-fpm.d etc/httpd etc/apache2; do
        [[ ! -e /$name ]] || paths+=("$name")
    done
    (( ${#paths[@]} )) || { printf 'Configuracoes nao encontradas.\n'; return 2; }
    tar -czf "$backup/configuracoes.tar.gz" -C / "${paths[@]}"
    printf '%s\n' "$before" > "$backup/inventario-antes.txt"
    printf '%s\n' "${units[@]}" > "$backup/servicos.txt"
    printf 'Backup de configuracoes: %s\n' "$backup"
    while IFS=$'\t' read -r name ver; do
        if [[ $family == rpm ]]; then
            if [[ $name == php || $name == php-* ]]; then names+=("$name"); fi
        elif [[ $name == "php${branch}-"* || $name == "libapache2-mod-php${branch}" ]]; then
            names+=("$name")
        fi
    done <<< "$before"
    (( ${#names[@]} )) || { printf 'Nenhum pacote selecionado.\n'; return 2; }
    if [[ $family == rpm ]]; then
        if command -v dnf >/dev/null; then manager=dnf
        elif command -v yum >/dev/null; then manager=yum
        else printf 'DNF/YUM ausente.\n'; return 2; fi
        "$manager" makecache
        command=("$manager" upgrade "${names[@]}")
        "$manager" upgrade --assumeno "${names[@]}" > "$backup/plano.txt" 2>&1 || code=$?
        cat "$backup/plano.txt"
        if grep -q 'Nothing to do' "$backup/plano.txt"; then
            printf 'Sem atualizacao disponivel. Consulte o fornecedor; correcao nao comprovada.\n'; return 2
        fi
        if ! grep -q 'Transaction Summary' "$backup/plano.txt" || grep -Eq 'Error:|Problem:' "$backup/plano.txt"; then
            printf 'Plano ausente ou com erros (saida %s). Analise manual.\n' "$code"; return 2
        fi
    else
        apt-get update -o APT::Update::Error-Mode=any
        command=(apt-get --no-remove --only-upgrade install "${names[@]}")
        apt-get --simulate --no-remove --only-upgrade install "${names[@]}" > "$backup/plano.txt" 2>&1
        cat "$backup/plano.txt"
    fi
    printf '\nRevise o plano: nao prossiga com erros, remocoes ou troca de serie.\n'
    printf 'Se houver backport, confirme com o fornecedor se a atualizacao e necessaria.\n'
    read -r -p 'Digite ATUALIZAR para executar o gerenciador interativo: ' answer
    [[ $answer == ATUALIZAR ]] || return 2
    "${command[@]}"
    after=$(inventory)
    printf '%s\n' "$after" > "$backup/inventario-depois.txt"
    [[ $before != "$after" ]] || { printf 'Pacotes inalterados. Correcao nao comprovada.\n'; return 2; }
    validate_configs
    for name in "${units[@]}"; do
        systemctl restart "$name"
        systemctl is-active --quiet "$name"
        printf '%s: active\n' "$name"
    done
    printf '\nPacotes apos a transacao:\n%s\n' "$after"
    while IFS=$'\t' read -r name ver; do
        if [[ $name =~ ^php([0-9]+\.[0-9]+)?-(cli|common|fpm|cgi)$ || $name =~ ^libapache2-mod-php ]]; then
            printf '%s: %s\n' "$name" "$(classify "$ver")"
        fi
    done <<< "$after"
    printf '\nTransacao concluida e servicos reiniciados. Teste login/formularios/aplicacoes.\n'
    printf 'Nao comprova ausencia de invasao, backports ou outros runtimes corrigidos.\n'
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
