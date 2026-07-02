#!/bin/bash
set -eo pipefail

CHAIN="MTPR_SYNFIX"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() { echo -e "  ${GREEN}[+]${NC} $1"; }

if [ "$(id -u)" -ne 0 ]; then
    echo -e "  ${RED}[x]${NC} Требуются права root" >&2
    exit 1
fi

echo ""
log_info "Удаление MTPR_SYNFIX..."

# Отключаем от INPUT
if iptables -C INPUT -j "$CHAIN" 2>/dev/null; then
    iptables -D INPUT -j "$CHAIN"
    log_info "Цепочка отключена от INPUT"
fi

# Очищаем и удаляем цепочку
if iptables -L "$CHAIN" -n >/dev/null 2>&1; then
    iptables -F "$CHAIN"
    iptables -X "$CHAIN"
    log_info "Цепочка ${CHAIN} удалена"
fi

# Очищаем mangle
iptables -t mangle -F PREROUTING 2>/dev/null || true
log_info "mangle PREROUTING очищен"

echo ""
log_info "Готово. Правила удалены."
