# MTProto MEKO — Prometheus Exporter

Prometheus exporter для мониторинга iptables-цепочки **MTPR_SYNFIX** из проекта [MTPROTO_FIX_By_MEKO](https://github.com/Mekotofeuka/MTPROTO_FIX_By_MEKO).

Отслеживает SYN-трафик MTProto прокси: iOS/non-iOS классификацию, hashlimit, REJECT, conntrack-состояния.

## Что мониторится

| Слой | Правило | Описание |
|------|---------|----------|
| mangle | u32 → MARK 0x400 | iOS-клиенты маркируются по u32-отпечатку |
| filter | ACCEPT --mark 0x400 | iOS проходят без лимита |
| filter | hashlimit 54/min | non-iOS — лимит 54 SYN/мин на IP |
| filter | REJECT tcp-reset | превысившие лимит отбрасываются |

## Установка

### 1. Экспортер

```bash
git clone git@github.com:vsibilev007/mtproto-exporter.git
cd mtproto-exporter
sudo bash install.sh
```

### 2. iptables правила (если ещё не установлены)

```bash
sudo bash install_synfix.sh 443
```

### 3. Prometheus

Добавь в `prometheus.yml`:

```yaml
- job_name: mtproto_meko
  scrape_interval: 30s
  static_configs:
    - targets: ['127.0.0.1:9095']
```

### 4. Grafana

Dashboards → Import → Upload JSON → `grafana_dashboard.json`

## Метрики

### Iptables счётчики

| Метрика | Описание |
|---------|----------|
| `mtpr_synfix_ios_accept_packets_total` | iOS SYN (mark 0x400) |
| `mtpr_synfix_ios_accept_bytes_total` | iOS байт |
| `mtpr_synfix_limit_accept_packets_total` | non-iOS SYN (hashlimit) |
| `mtpr_synfix_limit_accept_bytes_total` | non-iOS байт |
| `mtpr_synfix_reject_packets_total` | REJECT SYN |
| `mtpr_synfix_reject_bytes_total` | REJECT байт |
| `mtpr_synfix_chain_packets_total` | пакетов суммарно |
| `mtpr_synfix_chain_bytes_total` | байт суммарно |
| `mtpr_synfix_return_packets_total` | RETURN |

### Pre-calculated rates

| Метрика | Описание |
|---------|----------|
| `mtpr_synfix_rate_ios_packets` | iOS SYN/сек |
| `mtpr_synfix_rate_ios_bytes` | iOS байт/сек |
| `mtpr_synfix_rate_limit_packets` | non-iOS SYN/сек |
| `mtpr_synfix_rate_limit_bytes` | non-iOS байт/сек |
| `mtpr_synfix_rate_reject_packets` | REJECT/сек |
| `mtpr_synfix_rate_reject_bytes` | REJECT байт/сек |

### Percentages

| Метрика | Описание |
|---------|----------|
| `mtpr_synfix_non_ios_pct` | доля non-iOS в % |
| `mtpr_synfix_ios_pct` | доля iOS в % |

### Conntrack

| Метрика | Описание |
|---------|----------|
| `mtpr_synfix_conntrack_established` | ESTABLISHED соединений |
| `mtpr_synfix_conntrack_time_wait` | TIME_WAIT соединений |
| `mtpr_synfix_conntrack_other` | другие состояния |
| `mtpr_synfix_active_ips` | всего уникальных IP |
| `mtpr_synfix_ip_conntrack_packets{ip="..."}` | пакеты по IP |
| `mtpr_synfix_ip_conntrack_bytes{ip="..."}` | байты по IP |
| `mtpr_synfix_ip_conntrack_state{ip="...", state="..."}` | состояние IP |

### System

| Метрика | Описание |
|---------|----------|
| `mtpr_synfix_chain_exists` | цепочка жива (1/0) |
| `mtpr_synfix_ssh_bypass_active` | SSH bypass (1/0) |

## Grafana дашборд

14 панелей:

- **Система**: Chain OK/DEAD, SSH bypass, IPs, REJECT alert, Conntrack Total, iOS vs non-iOS Ratio (donut)
- **Трафик**: пакеты/сек + байт/сек по категориям
- **Анализ**: REJECT %, non-iOS %, Hashlimit utilization
- **Счётчики**: абсолютные значения + conntrack состояния
- **Топ IP**: пакеты, байты, таблица состояний

## Запуск вручную

```bash
# Экспортер
python3 mtproto_exporter.py 443 9095

# С отладкой
python3 mtproto_exporter.py 443 9095 --debug
```

## Удаление

```bash
sudo bash uninstall.sh        # удаление экспортера
sudo bash remove_synfix.sh    # удаление iptables правил
```

## Требования

- Python 3.7+
- `prometheus_client` (`pip3 install prometheus_client`)
- `conntrack` (`apt install conntrack`)
- Ядро с `nf_conntrack` модулем
- `net.netfilter.nf_conntrack_acct=1` для per-IP статистики

## Лицензия

MIT
