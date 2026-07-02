#!/usr/bin/env python3
"""
Prometheus exporter for MTPROTO_FIX_By_MEKO iptables rules.
Monitors the MTPR_SYNFIX chain: mark 0x400 iOS rule, limit rule, REJECT stats, per-IP conntrack.
"""

from prometheus_client import start_http_server, Gauge
from collections import deque
import subprocess
import re
import time

# ── Iptables счётчики (абсолютные значения) ─────────────────────

chain_packets = Gauge(
    'mtpr_synfix_chain_packets_total',
    'Total packets processed by MTPR_SYNFIX chain'
)
chain_bytes = Gauge(
    'mtpr_synfix_chain_bytes_total',
    'Total bytes processed by MTPR_SYNFIX chain'
)

ios_packets = Gauge(
    'mtpr_synfix_ios_accept_packets_total',
    'iOS SYN packets accepted (mark 0x400)'
)
ios_bytes = Gauge(
    'mtpr_synfix_ios_accept_bytes_total',
    'iOS SYN bytes accepted'
)

limit_packets = Gauge(
    'mtpr_synfix_limit_accept_packets_total',
    'non-iOS SYN passed hashlimit (54/min per IP)'
)
limit_bytes = Gauge(
    'mtpr_synfix_limit_accept_bytes_total',
    'non-iOS SYN bytes passed hashlimit'
)

reject_packets = Gauge(
    'mtpr_synfix_reject_packets_total',
    'SYN rejected with tcp-reset'
)
reject_bytes = Gauge(
    'mtpr_synfix_reject_bytes_total',
    'SYN bytes rejected'
)

return_packets = Gauge(
    'mtpr_synfix_return_packets_total',
    'Packets hitting RETURN'
)

# ── Pre-calculated rates ( packets/sec, bytes/sec ) ─────────────

rate_ios_pkt = Gauge(
    'mtpr_synfix_rate_ios_packets',
    'iOS SYN packets/sec'
)
rate_ios_bps = Gauge(
    'mtpr_synfix_rate_ios_bytes',
    'iOS SYN bytes/sec'
)
rate_limit_pkt = Gauge(
    'mtpr_synfix_rate_limit_packets',
    'non-iOS SYN packets/sec via hashlimit'
)
rate_limit_bps = Gauge(
    'mtpr_synfix_rate_limit_bytes',
    'non-iOS SYN bytes/sec via hashlimit'
)
rate_reject_pkt = Gauge(
    'mtpr_synfix_rate_reject_packets',
    'REJECT packets/sec'
)
rate_reject_bps = Gauge(
    'mtpr_synfix_rate_reject_bytes',
    'REJECT bytes/sec'
)

# ── Percentages ─────────────────────────────────────────────────

non_ios_pct = Gauge(
    'mtpr_synfix_non_ios_pct',
    'non-iOS traffic percentage (limit+reject)/total'
)
ios_pct = Gauge(
    'mtpr_synfix_ios_pct',
    'iOS traffic percentage'
)

# ── Conntrack ───────────────────────────────────────────────────

conntrack_established = Gauge(
    'mtpr_synfix_conntrack_established',
    'ESTABLISHED connections on proxy port'
)
conntrack_time_wait = Gauge(
    'mtpr_synfix_conntrack_time_wait',
    'TIME_WAIT connections on proxy port'
)
conntrack_other = Gauge(
    'mtpr_synfix_conntrack_other',
    'Other state connections'
)

active_ips = Gauge(
    'mtpr_synfix_active_ips',
    'Total unique source IPs on proxy port'
)
non_ios_active_ips = Gauge(
    'mtpr_synfix_non_ios_active_ips',
    'Unique non-iOS IPs currently in conntrack'
)

ip_conntrack_pkts = Gauge(
    'mtpr_synfix_ip_conntrack_packets',
    'Packets from this IP',
    ['ip']
)
ip_conntrack_bytes = Gauge(
    'mtpr_synfix_ip_conntrack_bytes',
    'Bytes from this IP',
    ['ip']
)
ip_conntrack_state = Gauge(
    'mtpr_synfix_ip_conntrack_state',
    'Connection state (1=active)',
    ['ip', 'state']
)

# ── System ──────────────────────────────────────────────────────

chain_exists = Gauge(
    'mtpr_synfix_chain_exists',
    'MTPR_SYNFIX chain exists (1=yes)'
)
ssh_bypass_active = Gauge(
    'mtpr_synfix_ssh_bypass_active',
    'SSH bypass rule active (1=yes)'
)


# ── Helpers ─────────────────────────────────────────────────────

def _run(cmd, debug=False):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if debug and r.returncode != 0:
            print(f"  [DEBUG] {' '.join(cmd)} -> rc={r.returncode} stderr={r.stderr.strip()}")
        if r.returncode == 0:
            return r.stdout
    except FileNotFoundError:
        if debug:
            print(f"  [DEBUG] Command not found: {cmd[0]}")
    except Exception as e:
        if debug:
            print(f"  [DEBUG] {' '.join(cmd)} -> {e}")
    return None


def _parse_chain_rules(chain_name, debug=False):
    out = _run(['iptables', '-L', chain_name, '-v', '-n', '-x'], debug=debug)
    if not out:
        return []

    lines = out.splitlines()
    if debug:
        for line in lines:
            print(f"  RAW: {line}")

    rules = []
    # Match: pkts bytes target prot opt in out source destination [match...]
    # Use regex to find destination and take everything after it
    # pkts bytes target prot opt in out source destination [match...]
    hdr_re = re.compile(
        r'^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)'
    )
    for line in lines:
        if line.startswith('Chain') or line.startswith(' pkts') or not line.strip():
            continue
        m = hdr_re.match(line)
        if not m:
            continue
        try:
            pkts = int(m.group(1))
            byt = int(m.group(2))
        except ValueError:
            continue
        target = m.group(3)
        match = m.group(10).strip()
        rules.append({
            'pkts': pkts,
            'bytes': byt,
            'target': target,
            'match': match,
        })

    return rules


IP_RE = re.compile(r'src=([0-9a-fA-F:\.]+)')


def _get_own_ips():
    ips = set()
    out = _run(['hostname', '-I'])
    if out:
        for ip in out.split():
            ips.add(ip)
    return ips


def _parse_conntrack_per_ip(port, debug=False):
    stats = {}
    own_ips = _get_own_ips()

    out = _run(['conntrack', '-L', '-f', 'ipv4', '-p', 'tcp', '--dport', str(port), '-o', 'extended', '--any-nat'], debug=debug)
    if not out:
        out = _run(['conntrack', '-L', '-f', 'ipv4', '-p', 'tcp', '--dport', str(port)], debug=debug)

    if out:
        for line in out.splitlines():
            src_m = IP_RE.search(line)
            pkts_m = re.search(r'packets=(\d+)', line)
            bytes_m = re.search(r'bytes=(\d+)', line)
            state_m = re.search(r'(ESTABLISHED|TIME_WAIT|SYN_SENT|SYN_RECV|CLOSE_WAIT|FIN_WAIT)', line)

            if src_m:
                ip = src_m.group(1)
                if ':' in ip or ip in own_ips:
                    continue
                if ip not in stats:
                    stats[ip] = {'pkts': 0, 'bytes': 0, 'state': 'UNKNOWN'}
                if pkts_m:
                    stats[ip]['pkts'] += int(pkts_m.group(1))
                if bytes_m:
                    stats[ip]['bytes'] += int(bytes_m.group(1))
                if state_m:
                    stats[ip]['state'] = state_m.group(1)

    return stats


# ── State for sliding-window rate calculation ───────────────────
# Store last 6 samples (60 sec at 10s interval)
_history = deque(maxlen=6)


def collect(port=443, debug=False):
    global _prev, _prev_time

    if debug:
        print(f"\n[collect] port={port}")

    # Проверяем цепочку
    check = _run(['iptables', '-L', 'MTPR_SYNFIX', '-n'], debug=debug)
    if check is None:
        chain_exists.set(0)
        return
    chain_exists.set(1)

    # Парсим правила
    rules = _parse_chain_rules('MTPR_SYNFIX', debug=debug)

    if debug:
        print(f"[collect] parsed {len(rules)} rules")

    # Извлекаем счётчики
    c_ios_pkts = 0
    c_ios_bytes = 0
    c_limit_pkts = 0
    c_limit_bytes = 0
    c_reject_pkts = 0
    c_reject_bytes = 0
    c_return_pkts = 0

    for r in rules:
        match = r['match']
        target = r['target']

        if target == 'ACCEPT' and ('mark match' in match or 'u32' in match):
            c_ios_pkts = r['pkts']
            c_ios_bytes = r['bytes']
        elif target == 'ACCEPT' and 'limit:' in match:
            c_limit_pkts = r['pkts']
            c_limit_bytes = r['bytes']
        elif target == 'REJECT':
            c_reject_pkts = r['pkts']
            c_reject_bytes = r['bytes']
        elif target == 'RETURN':
            c_return_pkts = r['pkts']

    total = c_ios_pkts + c_limit_pkts + c_reject_pkts

    # Absolutes
    chain_packets.set(c_ios_pkts + c_limit_pkts + c_reject_pkts + c_return_pkts)
    chain_bytes.set(c_ios_bytes + c_limit_bytes + c_reject_bytes)
    ios_packets.set(c_ios_pkts)
    ios_bytes.set(c_ios_bytes)
    limit_packets.set(c_limit_pkts)
    limit_bytes.set(c_limit_bytes)
    reject_packets.set(c_reject_pkts)
    reject_bytes.set(c_reject_bytes)
    return_packets.set(c_return_pkts)

    # Rates — sliding window (60 sec)
    now = time.time()
    sample = {
        'time': now,
        'ios_pkts': c_ios_pkts, 'ios_bytes': c_ios_bytes,
        'limit_pkts': c_limit_pkts, 'limit_bytes': c_limit_bytes,
        'reject_pkts': c_reject_pkts, 'reject_bytes': c_reject_bytes,
    }
    _history.append(sample)

    if len(_history) >= 2:
        oldest = _history[0]
        dt = now - oldest['time']
        if dt > 0:
            rate_ios_pkt.set(max(0, c_ios_pkts - oldest['ios_pkts']) / dt)
            rate_ios_bps.set(max(0, c_ios_bytes - oldest['ios_bytes']) / dt)
            rate_limit_pkt.set(max(0, c_limit_pkts - oldest['limit_pkts']) / dt)
            rate_limit_bps.set(max(0, c_limit_bytes - oldest['limit_bytes']) / dt)
            rate_reject_pkt.set(max(0, c_reject_pkts - oldest['reject_pkts']) / dt)
            rate_reject_bps.set(max(0, c_reject_bytes - oldest['reject_bytes']) / dt)

    # Percentages
    if total > 0:
        non_ios_pct.set((c_limit_pkts + c_reject_pkts) / total * 100)
        ios_pct.set(c_ios_pkts / total * 100)
    else:
        non_ios_pct.set(0)
        ios_pct.set(0)

    # Conntrack
    per_ip = _parse_conntrack_per_ip(port, debug=debug)

    all_ips = set(per_ip.keys())
    active_ips.set(len(all_ips))
    non_ios_active_ips.set(len(all_ips))

    ip_conntrack_pkts.clear()
    ip_conntrack_bytes.clear()
    ip_conntrack_state.clear()

    established = 0
    time_wait = 0
    other_states = 0

    for ip, st in per_ip.items():
        ip_conntrack_pkts.labels(ip=ip).set(st['pkts'])
        ip_conntrack_bytes.labels(ip=ip).set(st['bytes'])

        state = st['state']
        if state == 'ESTABLISHED':
            established += 1
            ip_conntrack_state.labels(ip=ip, state='established').set(1)
        elif state == 'TIME_WAIT':
            time_wait += 1
            ip_conntrack_state.labels(ip=ip, state='time_wait').set(1)
        else:
            other_states += 1
            ip_conntrack_state.labels(ip=ip, state='other').set(1)

    conntrack_established.set(established)
    conntrack_time_wait.set(time_wait)
    conntrack_other.set(other_states)

    # SSH
    ssh_out = _run(['iptables', '-C', 'INPUT', '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'])
    ssh_bypass_active.set(1 if ssh_out is not None else 0)


if __name__ == '__main__':
    import sys

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 443
    listen_port = int(sys.argv[2]) if len(sys.argv) > 2 else 9095
    debug = '--debug' in sys.argv

    print(f"Starting MTProto MEKO exporter on :{listen_port}")
    print(f"Monitoring MTPR_SYNFIX chain for port {port}")
    if debug:
        print("Debug mode ON")

    start_http_server(listen_port)
    while True:
        try:
            collect(port, debug=debug)
        except Exception as e:
            print(f"Collect error: {e}")
            import traceback
            traceback.print_exc()
        time.sleep(10)
