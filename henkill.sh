#!/bin/bash
#
#  Henkill 2.0 - firewall pessoal baseada em iptables
#
#  Copyright 2017 Whoami <whoami.a51@protonmail.com>   (script original)
#  Reescrito em 2026: regras isoladas em chains próprias, aplicação atômica,
#  compatível com Docker, IPv6 fechado, --open/--close/--unban, serviço systemd.
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#

VERSAO="2.0"

# ----------------------------------------------------------------------------
# Configuração (pode ser sobrescrita em /etc/henkill.conf)
# ----------------------------------------------------------------------------
CONF_FILE="/etc/henkill.conf"
VPN_IFACE_PADRAO="tun0"     # interface usada por padrão no --open (HTB/THM: tun0, WireGuard: wg0)
TRUSTED_IFACES=""           # interfaces com acesso total ao host. Ex: "docker0 br-+ virbr0"
PERMITIR_PING=0             # 1 = responde ping (limitado a 5/s)
LOG_LIMITE="5/min"          # limite dos logs de serviços (ftp/ssh/telnet/ping)
INSTALL_PATH="/usr/local/bin/henkill"
UNIT_PATH="/etc/systemd/system/henkill.service"

# shellcheck source=/dev/null
[[ -r $CONF_FILE ]] && . "$CONF_FILE"

# Chains próprias do Henkill (nada fora delas é apagado, então o Docker não é afetado)
CHAINS_V4="HK-IN HK-OUT HK-OPEN HK-SYN HK-SCAN"
CHAINS_V6="HK6-IN"

# ----------------------------------------------------------------------------
# Cores / mensagens (sem cores quando a saída não é um terminal, ex: systemd)
# ----------------------------------------------------------------------------
if [[ -t 1 ]]; then
    red=$'\e[0;91m'; green=$'\e[0;92m'; blue=$'\e[0;94m'
    white=$'\e[0;97m'; yellow=$'\e[0;93m'; endc=$'\e[0m'
    TTY=1
else
    red=""; green=""; blue=""; white=""; yellow=""; endc=""
    TTY=0
fi

info()  { printf '%s[INFO]%s %s\n'  "$blue"   "$endc" "$*"; }
ok()    { printf '%s[ OK ]%s %s\n'  "$green"  "$endc" "$*"; }
aviso() { printf '%s[AVISO]%s %s\n' "$yellow" "$endc" "$*"; }
erro()  { printf '%s[ERRO]%s %s\n'  "$red"    "$endc" "$*" >&2; }

banner() {
    [[ $TTY -eq 1 ]] || return 0
    printf '%s' "$blue"
    echo "+-------------------------------------------+"
    echo "| Henkill 2.0 - Configuração iptables       |"
    echo "| Copyright (C) 2017 Whoami                 |"
    echo "|                                           |"
    echo "| Contato: whoami.a51@protonmail.com        |"
    echo "+-------------------------------------------+"
    printf '%s\n' "$endc"
}

precisa_root() {
    if [[ $EUID -ne 0 ]]; then
        erro "Este comando precisa de root. Use: sudo $0 $*"
        exit 1
    fi
}

# ----------------------------------------------------------------------------
# Wrappers (-w espera o lock do xtables; importante com Docker rodando)
# ----------------------------------------------------------------------------
ipt()  { iptables  -w "$@"; }
ipt6() { ip6tables -w "$@"; }

tem_ipv6() {
    command -v ip6tables >/dev/null 2>&1 && ip6tables -w -L -n >/dev/null 2>&1
}

# ----------------------------------------------------------------------------
# Validações (tudo que vai para o iptables-restore passa por aqui)
# ----------------------------------------------------------------------------
valida_iface() {   # aceita nomes tipo tun0, wg0, br-+ ; "any" é tratado fora
    [[ $1 =~ ^[A-Za-z0-9_.:+-]{1,15}$ ]]
}

valida_porta() {   # 1-65535 ou intervalo 8000:8100
    local p=$1 a b
    [[ $p =~ ^[0-9]{1,5}(:[0-9]{1,5})?$ ]] || return 1
    a=${p%%:*}; b=${p##*:}
    (( a >= 1 && a <= 65535 && b >= 1 && b <= 65535 && a <= b ))
}

valida_origem() {  # IPv4 ou CIDR
    [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]
}

valida_config() {
    local i
    for i in $TRUSTED_IFACES; do
        valida_iface "$i" || { erro "TRUSTED_IFACES inválido: '$i'"; exit 1; }
    done
    valida_iface "$VPN_IFACE_PADRAO" || { erro "VPN_IFACE_PADRAO inválido: '$VPN_IFACE_PADRAO'"; exit 1; }
    [[ $LOG_LIMITE =~ ^[0-9]+/(sec|second|min|minute|hour|day)$ ]] \
        || { erro "LOG_LIMITE inválido: '$LOG_LIMITE' (ex: 5/min)"; exit 1; }
    [[ $PERMITIR_PING =~ ^[01]$ ]] || { erro "PERMITIR_PING deve ser 0 ou 1"; exit 1; }
}

# ----------------------------------------------------------------------------
# Conjunto de regras IPv4 (formato iptables-restore)
# ----------------------------------------------------------------------------
regras_v4() {
    local i svc proto nome
    cat <<EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
:HK-IN - [0:0]
:HK-OUT - [0:0]
:HK-OPEN - [0:0]
:HK-SYN - [0:0]
:HK-SCAN - [0:0]

# ---------- SAÍDA: tudo que você inicia é permitido ----------
-A HK-OUT -o lo -j ACCEPT
-A HK-OUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
-A HK-OUT -j DROP

# ---------- ENTRADA ----------
-A HK-IN -i lo -j ACCEPT
-A HK-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
EOF

    for i in $TRUSTED_IFACES; do
        echo "-A HK-IN -i $i -j ACCEPT"
    done

    cat <<EOF

# Portas abertas manualmente com --open (vem antes da blacklist)
-A HK-IN -j HK-OPEN

# Respostas DHCP (renovação de lease)
-A HK-IN -p udp --sport 67 --dport 68 -j ACCEPT

# Blacklist: reincidentes ficam 1h (5 hits) ou 24h (10 hits) em DROP
-A HK-IN -m recent --update --hitcount 10 --name SUSPEITO --seconds 86400 -j DROP
-A HK-IN -m recent --update --hitcount 5 --name SUSPEITO --seconds 3600 -j DROP
-A HK-IN -m recent --update --hitcount 10 --name SYN-DROP --seconds 86400 -j DROP
-A HK-IN -m recent --update --hitcount 5 --name SYN-DROP --seconds 3600 -j DROP
EOF

    # Logs (com limite) de tentativas em portas de serviços
    for svc in "20 ftp" "21 ftp" "22 ssh" "23 telnet"; do
        set -- $svc
        for proto in tcp udp; do
            echo "-A HK-IN -p $proto --dport $1 -m limit --limit $LOG_LIMITE --limit-burst 10 -j LOG --log-level warning --log-prefix \"[firewall] [$2] \""
        done
    done

    if [[ $PERMITIR_PING == 1 ]]; then
        echo "-A HK-IN -p icmp --icmp-type echo-request -m limit --limit 5/sec --limit-burst 10 -j ACCEPT"
    fi
    echo "-A HK-IN -p icmp -m limit --limit $LOG_LIMITE --limit-burst 10 -j LOG --log-level warning --log-prefix \"[firewall] [ping] \""

    cat <<EOF

# Scans (flags TCP anormais) -> chain HK-SCAN
-A HK-IN -p tcp --tcp-flags ALL NONE -j HK-SCAN
-A HK-IN -p tcp --tcp-flags ALL ALL -j HK-SCAN
-A HK-IN -p tcp --tcp-flags ALL FIN,PSH,URG -j HK-SCAN
-A HK-IN -p tcp --tcp-flags ALL FIN -j HK-SCAN
-A HK-IN -p tcp --tcp-flags ALL ACK -j HK-SCAN
-A HK-IN -p tcp --tcp-flags ALL SYN,ACK -j HK-SCAN
-A HK-IN -p tcp --tcp-flags SYN,FIN SYN,FIN -j HK-SCAN
-A HK-IN -p tcp --tcp-flags SYN,RST SYN,RST -j HK-SCAN

# Pacotes inválidos e novas conexões de entrada
-A HK-IN -m conntrack --ctstate INVALID -j DROP
-A HK-IN -p tcp --syn -m conntrack --ctstate NEW -j HK-SYN

# O que sobrar: loga, marca como SUSPEITO e descarta
-A HK-IN -m recent --update --name SUSPEITO -m limit --limit $LOG_LIMITE --limit-burst 3 -j LOG --log-level warning --log-prefix "[firewall] [suspeito] "
-A HK-IN -m limit --limit 10/min --limit-burst 3 -m recent --set --name SUSPEITO -j DROP
-A HK-IN -j DROP

# ---------- HK-SYN ----------
-A HK-SYN -m limit --limit 10/min --limit-burst 3 -j LOG --log-level warning --log-prefix "[firewall] [SYN: DROP] "
-A HK-SYN -m limit --limit 10/min --limit-burst 3 -m recent --set --name SYN-DROP -j DROP
-A HK-SYN -m limit --limit 1/min --limit-burst 1 -j LOG --log-level warning --log-prefix "[firewall] [SYN: FLOOD!] "
-A HK-SYN -j DROP

# ---------- HK-SCAN ----------
-A HK-SCAN -m limit --limit 10/min --limit-burst 3 -j LOG --log-level warning --log-prefix "[firewall] [SCANNER: DROP] "
-A HK-SCAN -m limit --limit 10/min --limit-burst 3 -m recent --set --name SUSPEITO -j DROP
-A HK-SCAN -m limit --limit 1/min --limit-burst 1 -j LOG --log-level warning --log-prefix "[firewall] [SCANNER: FLOOD!] "
-A HK-SCAN -j DROP
COMMIT
EOF
}

# ----------------------------------------------------------------------------
# Conjunto de regras IPv6: entrada fechada (só respostas + NDP), saída livre
# ----------------------------------------------------------------------------
regras_v6() {
    local t
    cat <<EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:HK6-IN - [0:0]
-A HK6-IN -i lo -j ACCEPT
-A HK6-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A HK6-IN -m conntrack --ctstate INVALID -j DROP
EOF
    # Descoberta de vizinhos / RA (sem isso o IPv6 local quebra).
    # O kernel já descarta ND/RA com hop limit != 255, então não é preciso '-m hl'.
    for t in 133 134 135 136 137; do
        echo "-A HK6-IN -p ipv6-icmp --icmpv6-type $t -j ACCEPT"
    done
    # Mensagens de erro (PMTUD etc.)
    for t in 1 2 3 4; do
        echo "-A HK6-IN -p ipv6-icmp --icmpv6-type $t -j ACCEPT"
    done
    cat <<EOF
-A HK6-IN -p udp --sport 547 --dport 546 -j ACCEPT
-A HK6-IN -j DROP
COMMIT
EOF
}

# ----------------------------------------------------------------------------
# Aplicação
# ----------------------------------------------------------------------------
carrega_modulos() {
    local m
    for m in ip_tables ip6_tables nf_conntrack xt_conntrack xt_recent xt_limit xt_LOG; do
        modprobe -q "$m" 2>/dev/null
    done
    return 0
}

# Cria as chains-base e garante os saltos INPUT/OUTPUT -> Henkill.
# Com a chain ainda vazia o salto é inofensivo, então não há janela sem proteção.
garante_estrutura() {
    local fn=$1 cin=$2 cout=$3
    [[ -n $cin  ]] && { $fn -N "$cin"  2>/dev/null; $fn -C INPUT  -j "$cin"  2>/dev/null || $fn -I INPUT  1 -j "$cin"  || return 1; }
    [[ -n $cout ]] && { $fn -N "$cout" 2>/dev/null; $fn -C OUTPUT -j "$cout" 2>/dev/null || $fn -I OUTPUT 1 -j "$cout" || return 1; }
    return 0
}

ativaprotecao() {
    sysctl -qw \
        net.ipv4.tcp_syncookies=1 \
        net.ipv4.icmp_ignore_bogus_error_responses=1 \
        net.ipv4.icmp_echo_ignore_broadcasts=1 \
        net.ipv4.conf.all.accept_redirects=0 \
        net.ipv4.conf.default.accept_redirects=0 \
        net.ipv4.conf.all.accept_source_route=0 \
        net.ipv4.conf.default.accept_source_route=0 \
        net.ipv6.conf.all.accept_redirects=0 \
        net.ipv6.conf.default.accept_redirects=0 2>/dev/null
    return 0
}

start() {
    precisa_root
    banner
    command -v iptables >/dev/null 2>&1 || { erro "iptables não encontrado (sudo pacman -S iptables)"; exit 1; }
    valida_config
    carrega_modulos

    garante_estrutura ipt HK-IN HK-OUT || { erro "Falha ao criar a estrutura IPv4"; exit 1; }
    if regras_v4 | iptables-restore --noflush --wait; then
        ok "Regras IPv4 aplicadas (atômico, Docker preservado)"
    else
        erro "iptables-restore falhou; nada foi alterado. Veja: $0 --rules"
        exit 1
    fi

    if tem_ipv6; then
        garante_estrutura ipt6 HK6-IN "" || aviso "Falha ao criar a estrutura IPv6"
        if regras_v6 | ip6tables-restore --noflush --wait \
           && [[ $(ipt6 -S INPUT | awk '/^-P/{print $3}') == DROP ]]; then
            ok "Regras IPv6 aplicadas (entrada fechada)"
        else
            erro "IPv6 NÃO foi fechado (ip6tables-restore falhou). O IPv6 continua aberto!"
            erro "Veja o erro com: $0 --rules | sed -n '/IPv6/,\$p' | sed 1d | sudo ip6tables-restore --test --noflush"
        fi
    else
        aviso "IPv6 indisponível no kernel/ip6tables; nada a fazer"
    fi

    ativaprotecao && ok "Proteções de kernel (syncookies, redirects, source route)"
    ok "Henkill ativo"
}

remove_estrutura() {
    local fn=$1 cin=$2 cout=$3 chains=$4 c
    $fn -P INPUT ACCEPT
    [[ -n $cout ]] && $fn -P OUTPUT ACCEPT
    [[ -n $cin  ]] && while $fn -C INPUT  -j "$cin"  2>/dev/null; do $fn -D INPUT  -j "$cin";  done
    [[ -n $cout ]] && while $fn -C OUTPUT -j "$cout" 2>/dev/null; do $fn -D OUTPUT -j "$cout"; done
    for c in $chains; do $fn -F "$c" 2>/dev/null; done
    for c in $chains; do $fn -X "$c" 2>/dev/null; done
}

stop() {
    precisa_root
    banner
    command -v iptables >/dev/null 2>&1 || { erro "iptables não encontrado"; exit 1; }
    remove_estrutura ipt HK-IN HK-OUT "$CHAINS_V4"
    ok "Regras IPv4 do Henkill removidas (INPUT/OUTPUT voltam a ACCEPT; FORWARD e Docker intactos)"
    if tem_ipv6; then
        remove_estrutura ipt6 HK6-IN "" "$CHAINS_V6"
        ok "Regras IPv6 do Henkill removidas"
    fi
}

restart() {
    start
}

# ----------------------------------------------------------------------------
# Portas temporárias, blacklist
# ----------------------------------------------------------------------------
uso_open() {
    cat <<EOF
Uso:
  $0 --open  <porta|inicio-fim> [tcp|udp] [interface|any] [ip-origem]
  $0 --close <porta|inicio-fim> [tcp|udp]

Exemplos:
  sudo $0 --open 4444                      # tcp, via $VPN_IFACE_PADRAO, de qualquer origem
  sudo $0 --open 8000 tcp tun0 10.10.10.5  # só o alvo 10.10.10.5 acessa
  sudo $0 --open 8000-8100 tcp any         # intervalo, qualquer interface
  sudo $0 --close 4444
As portas abertas valem até o próximo --start/--restart/--stop (ou reboot).
EOF
}

abrir() {
    precisa_root
    local porta=${1:-} proto=${2:-tcp} iface=${3:-$VPN_IFACE_PADRAO} origem=${4:-}
    [[ -n $porta ]] || { uso_open; exit 1; }
    porta=${porta//-/:}
    valida_porta "$porta" || { erro "Porta inválida: '$1'"; exit 1; }
    [[ $proto == tcp || $proto == udp ]] || { erro "Protocolo deve ser tcp ou udp"; exit 1; }
    if [[ $iface != any ]]; then
        valida_iface "$iface" || { erro "Interface inválida: '$iface'"; exit 1; }
    fi
    if [[ -n $origem ]]; then
        valida_origem "$origem" || { erro "IP de origem inválido: '$origem'"; exit 1; }
    fi
    ipt -n -L HK-OPEN >/dev/null 2>&1 || { erro "Henkill não está ativo. Rode: sudo $0 --start"; exit 1; }

    local args=()
    [[ -n $origem ]]     && args+=(-s "$origem")
    [[ $iface != any ]]  && args+=(-i "$iface")
    args+=(-p "$proto" --dport "$porta" -j ACCEPT)

    if ipt -C HK-OPEN "${args[@]}" 2>/dev/null; then
        aviso "Essa regra já existe"
    elif ipt -A HK-OPEN "${args[@]}"; then
        ok "Porta $porta/$proto aberta (iface: $iface${origem:+, origem: $origem})"
    else
        erro "Não foi possível adicionar a regra"
        exit 1
    fi
}

fechar() {
    precisa_root
    local porta=${1:-} proto=${2:-} r achou=0 regras=()
    [[ -n $porta ]] || { uso_open; exit 1; }
    porta=${porta//-/:}
    valida_porta "$porta" || { erro "Porta inválida: '$1'"; exit 1; }
    if [[ -n $proto && $proto != tcp && $proto != udp ]]; then
        erro "Protocolo deve ser tcp ou udp"; exit 1
    fi
    ipt -n -L HK-OPEN >/dev/null 2>&1 || { erro "Henkill não está ativo."; exit 1; }

    mapfile -t regras < <(ipt -S HK-OPEN | grep -E -- " -p ${proto:-(tcp|udp)} .*--dport ${porta} -j ACCEPT\$")
    for r in "${regras[@]}"; do
        [[ -n $r ]] || continue
        # shellcheck disable=SC2086
        ipt ${r/#-A/-D} && achou=1
    done
    if [[ $achou -eq 1 ]]; then
        ok "Porta $porta${proto:+/$proto} fechada"
    else
        aviso "Nenhuma regra aberta encontrada para a porta $porta${proto:+/$proto}"
    fi
}

unban() {
    precisa_root
    local alvo=${1:-} l f feito=0
    if [[ $alvo != all ]] && ! valida_origem "$alvo"; then
        erro "Uso: $0 --unban <ip|all>"; exit 1
    fi
    for l in SUSPEITO SYN-DROP; do
        f=/proc/net/xt_recent/$l
        [[ -w $f ]] || continue
        if [[ $alvo == all ]]; then echo "/" > "$f"; else echo "-$alvo" > "$f"; fi
        feito=1
    done
    if [[ $feito -eq 1 ]]; then
        ok "Blacklist atualizada ($alvo)"
    else
        aviso "Listas SUSPEITO/SYN-DROP não encontradas. O Henkill está ativo?"
    fi
}

bans() {
    precisa_root
    local l f ips
    for l in SUSPEITO SYN-DROP; do
        f=/proc/net/xt_recent/$l
        printf '%s%s%s\n' "$white" "$l" "$endc"
        if [[ -r $f ]]; then
            ips=$(sed -n 's/^src=\([0-9.]*\).*/\1/p' "$f")
            if [[ -n $ips ]]; then sed 's/^/  /' <<<"$ips"; else echo "  (vazia)"; fi
        else
            echo "  (lista inexistente)"
        fi
    done
}

# ----------------------------------------------------------------------------
# Informações
# ----------------------------------------------------------------------------
status() {
    precisa_root
    info "Checando se o iptables está configurado corretamente..."
    if ipt -C INPUT -j HK-IN 2>/dev/null && ipt -C OUTPUT -j HK-OUT 2>/dev/null; then
        ok "Firewall IPv4 está configurado"
        printf '  Políticas: INPUT=%s OUTPUT=%s FORWARD=%s\n' \
            "$(ipt -S INPUT   | awk '/^-P/{print $3}')" \
            "$(ipt -S OUTPUT  | awk '/^-P/{print $3}')" \
            "$(ipt -S FORWARD | awk '/^-P/{print $3}')"
        local abertas
        abertas=$(ipt -S HK-OPEN 2>/dev/null | grep '^-A')
        if [[ -n $abertas ]]; then
            echo "  Portas abertas:"; sed 's/^-A HK-OPEN /    /' <<<"$abertas"
        else
            echo "  Portas abertas: nenhuma"
        fi
    else
        erro "Firewall está desconfigurado (rode: sudo $0 --start)"
        return 1
    fi

    if tem_ipv6; then
        local pol6
        pol6=$(ipt6 -S INPUT | awk '/^-P/{print $3}')
        if ipt6 -C INPUT -j HK6-IN 2>/dev/null && [[ $pol6 == DROP ]]; then
            ok "Firewall IPv6 está configurado (INPUT=$pol6)"
        else
            erro "IPv6 ABERTO: política INPUT=$pol6 (rode: sudo $0 --restart)"
        fi
    fi
    systemctl is-enabled henkill.service >/dev/null 2>&1 \
        && ok "Inicia no boot (henkill.service habilitado)" \
        || info "Não inicia no boot (use: sudo $0 --install)"
}

list() {
    precisa_root
    info "Regras atuais (-v -n):"
    printf '%s' "$white"
    ipt -L -v -n --line-numbers
    printf '%s' "$endc"
}

mostra_regras() {
    echo "# ===== IPv4 ====="
    regras_v4
    echo
    echo "# ===== IPv6 ====="
    regras_v6
}

checkip() {
    info "Checando online IP público, espere..."
    local externo
    if ! externo="$(curl -s -m 10 https://ipinfo.io/geo)" || [[ -z $externo ]]; then
        erro "curl: falha na requisição HTTP"
        exit 1
    fi
    ok "IP Address Details:"
    printf '%s\n' "$externo" | tr -d '"{},' | sed 's/^ *//' | sed '/^$/d'
}

versao() {
    echo "henkill v$VERSAO"
    iptables --version 2>/dev/null
}

# ----------------------------------------------------------------------------
# Instalação como serviço (inicia no boot)
# ----------------------------------------------------------------------------
instalar() {
    precisa_root
    command -v systemctl >/dev/null 2>&1 || { erro "systemd não encontrado"; exit 1; }
    install -Dm755 "$(readlink -f "$0")" "$INSTALL_PATH" || { erro "Falha ao copiar para $INSTALL_PATH"; exit 1; }
    cat > "$UNIT_PATH" <<EOF
[Unit]
Description=Henkill - firewall iptables
Documentation=man:iptables(8)
Wants=network-pre.target
Before=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$INSTALL_PATH --start
ExecReload=$INSTALL_PATH --restart
ExecStop=$INSTALL_PATH --stop

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable henkill.service && ok "henkill.service habilitado (script em $INSTALL_PATH)"
    info "Config opcional em $CONF_FILE (VPN_IFACE_PADRAO, TRUSTED_IFACES, PERMITIR_PING, LOG_LIMITE)"
    info "Se você editar o script, rode --install de novo para atualizar a cópia em $INSTALL_PATH"
}

desinstalar() {
    precisa_root
    systemctl disable --now henkill.service 2>/dev/null
    rm -f "$UNIT_PATH" "$INSTALL_PATH"
    systemctl daemon-reload
    ok "Serviço removido. As regras do Henkill foram desativadas."
}

help() {
    banner
    printf '%s┌─╼%s %s%s%s %s╺─╸%s %s%s%s\n' "$white" "$endc" "$red" "${USER:-user}" "$endc" "$white" "$endc" "$red" "$(hostname)" "$endc"
    printf '%s└───╼%s %shenkill --argumento%s\n\n' "$white" "$endc" "$green" "$endc"
    printf '%sArgumentos:%s\n\n' "$green" "$endc"
    while IFS='@' read -r a d; do
        printf '%s%-22s%s %s%s%s\n' "$white" "$a" "$endc" "$green" "$d" "$endc"
    done <<'EOF'
--help@mostra esta mensagem de ajuda
--start@inicia o henkill e configura o iptables
--stop@remove só as regras do henkill (Docker intacto)
--restart@reaplica as regras (atômico, sem janela aberta)
--status@checa o status do henkill
--list@lista as regras (-v -n) de todas as chains
--rules@mostra as regras que seriam aplicadas (sem aplicar)
--open <porta> [...]@abre porta temporária (tcp|udp, iface, ip-origem)
--close <porta> [...]@fecha porta aberta com --open
--bans@lista IPs na blacklist (SUSPEITO / SYN-DROP)
--unban <ip|all>@remove IP (ou todos) da blacklist
--install@copia para /usr/local/bin e habilita no boot
--uninstall@remove o serviço
--checkip@checa online o IP público
--version@mostra a versão do henkill e do iptables
EOF
}

main() {
    case ${1:-} in
        --help|-h)   help ;;
        --start)     start ;;
        --stop)      stop ;;
        --restart)   restart ;;
        --status)    status ;;
        --list)      list ;;
        --rules)     mostra_regras ;;
        --open)      shift; abrir "$@" ;;
        --close)     shift; fechar "$@" ;;
        --bans)      bans ;;
        --unban)     shift; unban "$@" ;;
        --install)   instalar ;;
        --uninstall) desinstalar ;;
        --checkip)   checkip ;;
        --version)   versao ;;
        *)
            printf '%sHenkill v%s%s\n' "$white" "$VERSAO" "$endc"
            echo "Escrito por: Whoami <whoami.a51@protonmail.com>"
            echo
            echo "Tente '$0 --help' para mais informações."
            ;;
    esac
}

# Permite fazer 'source' do arquivo (testes) sem executar nada
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
