# parse_pcap_pyshark.py
import os
import json
import argparse
import ipaddress
from collections import Counter, defaultdict

import pandas as pd
import matplotlib.pyplot as plt
import pyshark


def safe_str(x):
    try:
        return str(x)
    except Exception:
        return None


def get_ip(pkt):
    """Вернёт (src_ip, dst_ip, ip_version) или (None, None, None)."""
    try:
        if hasattr(pkt, "ip"):
            return pkt.ip.src, pkt.ip.dst, 4
        if hasattr(pkt, "ipv6"):
            return pkt.ipv6.src, pkt.ipv6.dst, 6
    except Exception:
        pass
    return None, None, None


def is_public_ip(ip_str: str) -> bool:
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global  # публичный/маршрутизируемый
    except Exception:
        return False


def field_values(layer, name: str):
    """
    Попытка достать значения полей DNS (A/AAAA/CNAME и т.п.).
    Возвращает список строк.
    """
    if layer is None:
        return []
    try:
        v = layer.get_field_value(name)
    except Exception:
        v = getattr(layer, name, None)

    if v is None:
        return []
    if isinstance(v, list):
        return [safe_str(x) for x in v if safe_str(x)]
    s = safe_str(v)
    return [s] if s else []


def parse_pcap(pcap_path: str, out_dir: str, dns_bucket: str = "1min"):
    os.makedirs(out_dir, exist_ok=True)

    dns_rows = []
    dhcp_rows = []
    arp_rows = []

    public_ip_counter = Counter()
    domain_counter = Counter()
    domain_to_ips = defaultdict(set)

    # keep_packets=False — меньше памяти
    cap = pyshark.FileCapture(pcap_path, keep_packets=False)

    try:
        for pkt in cap:
            t = getattr(pkt, "sniff_time", None)
            ts = t.isoformat() if t else None

            src_ip, dst_ip, _ = get_ip(pkt)

            # --- DNS ---
            if hasattr(pkt, "dns"):
                dns = pkt.dns
                is_resp = getattr(dns, "flags_response", None)  # '0' query, '1' response

                qry_name = safe_str(getattr(dns, "qry_name", None))
                qry_type = safe_str(getattr(dns, "qry_type", None))
                rcode = safe_str(getattr(dns, "flags_rcode", None))

                # Ответы (если это response)
                answers_a = field_values(dns, "a")
                answers_aaaa = field_values(dns, "aaaa")
                answers_cname = field_values(dns, "cname")
                answers = [x for x in (answers_a + answers_aaaa + answers_cname) if x]

                dns_rows.append({
                    "time": ts,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "is_response": safe_str(is_resp),
                    "qry_name": qry_name,
                    "qry_type": qry_type,
                    "rcode": rcode,
                    "answers": ";".join(answers) if answers else None
                })

                # Счётчики
                if qry_name and is_resp == "0":
                    domain_counter[qry_name] += 1

                for ans in answers_a + answers_aaaa:
                    if is_public_ip(ans):
                        public_ip_counter[ans] += 1
                        if qry_name:
                            domain_to_ips[qry_name].add(ans)

            # --- DHCP ---
            if hasattr(pkt, "bootp"):
                b = pkt.bootp

                # Тип сообщения
                msg_type = (
                        safe_str(getattr(b, "option_dhcp", None)) or
                        safe_str(getattr(b, "option_dhcp_message_type", None)) or
                        safe_str(getattr(b, "dhcp", None))
                )

                client_mac = (
                        safe_str(getattr(b, "chaddr", None)) or
                        safe_str(getattr(b, "hw_mac_addr", None)) or
                        safe_str(getattr(getattr(pkt, "eth", None), "src", None))
                )

                hostname = (
                        safe_str(getattr(b, "option_hostname", None)) or
                        safe_str(getattr(b, "hostname", None))
                )

                requested_ip = safe_str(getattr(b, "option_requested_ip_address", None))
                your_ip = safe_str(getattr(b, "yiaddr", None))  # offered/assigned IP
                server_ip = safe_str(getattr(b, "siaddr", None))

                dhcp_rows.append({
                    "time": ts,
                    "msg_type": msg_type,
                    "client_mac": client_mac,
                    "hostname": hostname,
                    "requested_ip": requested_ip,
                    "assigned_ip": your_ip,
                    "server_ip": server_ip,
                })

            # --- ARP ---
            if hasattr(pkt, "arp"):
                a = pkt.arp
                arp_rows.append({
                    "time": ts,
                    "opcode": safe_str(getattr(a, "opcode", None)),
                    "src_mac": safe_str(getattr(a, "src_hw_mac", None)),
                    "src_ip": safe_str(getattr(a, "src_proto_ipv4", None)),
                    "dst_mac": safe_str(getattr(a, "dst_hw_mac", None)),
                    "dst_ip": safe_str(getattr(a, "dst_proto_ipv4", None)),
                })

    finally:
        cap.close()

    # --- DataFrames + сохранение ---
    dns_df = pd.DataFrame(dns_rows)
    dhcp_df = pd.DataFrame(dhcp_rows)
    arp_df = pd.DataFrame(arp_rows)

    dns_csv = os.path.join(out_dir, "dns.csv")
    dhcp_csv = os.path.join(out_dir, "dhcp.csv")
    arp_csv = os.path.join(out_dir, "arp.csv")

    dns_df.to_csv(dns_csv, index=False)
    dhcp_df.to_csv(dhcp_csv, index=False)
    arp_df.to_csv(arp_csv, index=False)

    # --- Подозрительные публичные IP (просто внешний трафик) ---
    suspicious = []
    for ip, cnt in public_ip_counter.most_common():
        # какие домены приводили к этому IP
        domains = [d for d, ips in domain_to_ips.items() if ip in ips]
        suspicious.append({
            "ip": ip,
            "count_in_dns_answers": cnt,
            "domains": domains[:20]
        })

    suspicious_json = os.path.join(out_dir, "suspicious_public_ips.json")
    with open(suspicious_json, "w", encoding="utf-8") as f:
        json.dump(suspicious, f, ensure_ascii=False, indent=2)

    # --- График DNS queries по времени ---
    plot_path = os.path.join(out_dir, "dns_queries_over_time.png")
    if not dns_df.empty:
        # Берём только запросы, где есть qry_name
        q = dns_df[(dns_df["is_response"] == "0") & (dns_df["qry_name"].notna())].copy()
        if not q.empty:
            q["time"] = pd.to_datetime(q["time"], errors="coerce")
            q = q.dropna(subset=["time"]).set_index("time")

            counts = q["qry_name"].resample(dns_bucket).count()

            plt.figure()
            plt.plot(counts.index, counts.values)
            plt.title(f"DNS queries over time ({dns_bucket})")
            plt.xlabel("Time")
            plt.ylabel("DNS queries")
            plt.tight_layout()
            plt.savefig(plot_path, dpi=150)
            plt.close()

    # --- Мини-лог в консоль ---
    print("\n=== TOP DNS domains (queries) ===")
    for d, c in domain_counter.most_common(20):
        print(f"{c:6d}  {d}")

    print("\n=== Public IPs seen in DNS answers (top) ===")
    for ip, c in public_ip_counter.most_common(20):
        print(f"{c:6d}  {ip}")

    print(f"\nSaved:\n- {dns_csv}\n- {dhcp_csv}\n- {arp_csv}\n- {suspicious_json}\n- {plot_path if os.path.exists(plot_path) else '(no dns plot)'}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", help="Path to .pcap/.pcapng")
    ap.add_argument("--out", default="out", help="Output folder")
    ap.add_argument("--bucket", default="1min", help="DNS time bucket for plot (e.g. 10s, 1min, 5min)")
    args = ap.parse_args()

    parse_pcap(args.pcap, args.out, args.bucket)


if __name__ == "__main__":
    main()
