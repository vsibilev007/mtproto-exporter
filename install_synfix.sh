#!/bin/bash
set -eo pipefail

# ── MTPR_SYNFIX — рекомендуемая схема ─────────────────────────
# Слой 1: u32 + limit 15/sec — iOS клиенты
# Слой 2: limit 54/min — non-iOS клиенты
# Слой 3: REJECT tcp-reset — превысившие лимит

CHAIN="MTPR_SYNFIX"
PORTS="${1:-443}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

log_info()  { echo -e "  ${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "  ${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "  ${RED}[x]${NC} $1" >&2; }

# Проверка root
if [ "$(id -u)" -ne 0 ]; then
    log_error "Требуются права root"
    exit 1
fi

# Определяем SSH порт
SSH_PORT=$(sshd -T 2>/dev/null | grep '^port ' | awk '{print $2}' | head -1)
[ -z "$SSH_PORT" ] && SSH_PORT=22

echo ""
echo -e "  ${GREEN}MTPR_SYNFIX — установка схемы${NC}"
echo -e "  SSH порт: ${SSH_PORT}"
echo -e "  Порты прокси: ${PORTS}"
echo ""

# Парсим порты
IFS=',' read -ra PORT_ARRAY <<< "$PORTS"

# Создаём цепочку
log_info "Создание цепочки ${CHAIN}..."
iptables -t filter -N "$CHAIN" 2>/dev/null || true
iptables -t filter -F "$CHAIN"

# SSH — первый приоритет
if ! iptables -C INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null; then
    iptables -I INPUT 1 -p tcp --dport "$SSH_PORT" -j ACCEPT
    log_info "SSH порт ${SSH_PORT} разрешён"
fi

# Подключаем цепочку к INPUT
if ! iptables -t filter -C INPUT -j "$CHAIN" 2>/dev/null; then
    iptables -t filter -I INPUT 2 -j "$CHAIN"
    log_info "Цепочка ${CHAIN} подключена к INPUT"
fi

# iOS маркировка в mangle (u32 отпечаток)
log_info "Добавление iOS u32 маркировки в mangle..."
iptables -t mangle -F PREROUTING 2>/dev/null || true
iptables -t mangle -A PREROUTING -m u32 \
    --u32 "32 & 0x00FFFFFF = 0x0002FF00 && \
           40 & 0xFF000000 = 0x02000000 && \
           44 & 0xFFFF0000 = 0x01030000 && \
           48 & 0xFFFFFF00 = 0x01010800 && \
           60 & 0xFFFFFFFF = 0x04020000" \
    -j MARK --set-mark 0x400

for PORT in "${PORT_ARRAY[@]}"; do
    PORT=$(echo "$PORT" | xargs)
    [ -z "$PORT" ] && continue

    log_info "Добавление правил для порта ${PORT}..."

    # Слой 1: iOS — ACCEPT без лимита (по маркеру)
    iptables -t filter -A "$CHAIN" -p tcp --dport "$PORT" --syn \
        -m mark --mark 0x400 \
        -j ACCEPT

    # Слой 2: non-iOS — limit 54/min per srcip
    iptables -t filter -A "$CHAIN" -p tcp --dport "$PORT" --syn \
        -m hashlimit \
        --hashlimit-name mtpr_${PORT} \
        --hashlimit-mode srcip \
        --hashlimit-upto 54/minute \
        --hashlimit-burst 1 \
        --hashlimit-htable-expire 60000 \
        --hashlimit-htable-size 32768 \
        -j ACCEPT

    # Слой 3: REJECT tcp-reset
    iptables -t filter -A "$CHAIN" -p tcp --dport "$PORT" --syn \
        -j REJECT --reject-with tcp-reset

    log_info "Порты ${PORT}: u32(iOS) → hashlimit(54/min) → REJECT"
done

# RETURN в конце цепочки
iptables -t filter -A "$CHAIN" -j RETURN

echo ""
log_info "Установка завершена. Текущие правила:"
echo ""
iptables -L "$CHAIN" -v -n
echo ""
iptables -t mangle -L PREROUTING -v -n | grep u32 || true
