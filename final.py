"""
Cybersecurity mini-pipeline (data collection -> analysis -> response -> report/visualization)

pandas, requests, matplotlib

simple example logs generator class:

def main(out_path: str = "suricata_eve.json") -> None:
    events = []
    start = datetime.datetime(2026, 1, 12, 8, 0, 0)

    for i in range(40):
        ts = start + datetime.timedelta(seconds=i*2)
        events.append({
            "timestamp": iso(ts),
            "event_type": "dns",
            "src_ip": "10.0.0.10",
            "dest_ip": "8.8.8.8",
            "proto": "UDP",
            "dns": {"type": "query", "rrname": f"random{i}.example-bad.tld", "rrtype": "A"},
        })

    for i in range(10):
        ts = start + datetime.timedelta(seconds=120+i*10)
        events.append({
            "timestamp": iso(ts),
            "event_type": "dns",
            "src_ip": "10.0.0.11",
            "dest_ip": "1.1.1.1",
            "proto": "UDP",
            "dns": {"type": "query", "rrname": "example.com", "rrtype": "A"},
        })

    alerts = [
        ("10.0.0.10","185.199.108.153","ET TROJAN Possible C2 Traffic","A Network Trojan was detected",2),
        ("10.0.0.12","45.133.1.10","ET SCAN Nmap Scripting Engine User-Agent Detected","Attempted Information Leak",3),
        ("10.0.0.10","45.133.1.10","ET MALWARE Observed Malicious SSL Cert","Potentially Bad Traffic",1),
        ("10.0.0.11","93.184.216.34","ET POLICY Curl User-Agent Outbound","Not Suspicious Traffic",4),
        ("10.0.0.13","45.133.1.10","ET EXPLOIT Possible Apache 2.4.49 Path Traversal","Attempted Administrator Privilege Gain",1),
    ]
    for idx, (src,dst,sig,cat,sev) in enumerate(alerts):
        ts = start + datetime.timedelta(minutes=5, seconds=idx*20)
        events.append({
            "timestamp": iso(ts),
            "event_type": "alert",
            "src_ip": src,
            "dest_ip": dst,
            "proto": "TCP",
            "alert": {"signature": sig, "category": cat, "severity": sev},
        })

    p = Path(out_path)
    with p.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    print(f"Written {len(events)} events to {p.resolve()}")
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import requests
import matplotlib.pyplot as plt


# ---------------------------
# Configuration
# ---------------------------

@dataclass(frozen=True)
class Config:
    # Inputs
    suricata_eve_path: Path
    # Outputs
    out_dir: Path
    # Detection thresholds
    dns_burst_threshold: int = 25         # "Frequent DNS requests" per source IP
    alert_threshold: int = 2              # Alerts per (src or dest) IP to mark suspicious
    high_cvss_threshold: float = 8.0      # High severity vulnerability threshold
    # API keys / endpoints
    virustotal_api_key: Optional[str] = None
    vulners_api_key: Optional[str] = None


# ---------------------------
# Utilities
# ---------------------------

def read_line_delimited_json(path: Path) -> List[Dict[str, Any]]:
    """Read a Suricata EVE JSON file: one JSON document per line."""
    items: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON at {path}:{lineno}: {e}") from e
    return items


def ensure_out_dir(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)


# ---------------------------
# Data collection
# ---------------------------

def load_suricata_df(eve_path: Path) -> pd.DataFrame:
    records = read_line_delimited_json(eve_path)
    df = pd.json_normalize(records)
    # Normalize a few common columns to exist
    for col in ["timestamp", "event_type", "src_ip", "dest_ip", "proto"]:
        if col not in df.columns:
            df[col] = None
    return df


# ---------------------------
# VirusTotal (IP reputation)
# ---------------------------

def vt_lookup_ip(ip: str, api_key: Optional[str]) -> Dict[str, Any]:
    """
    Returns a normalized dict with reputation stats.
    If api_key is missing, returns a mocked response.
    """
    if not api_key:
        # MOCKED: deterministic-ish outcome for demo
        mocked = {
            "ip": ip,
            "last_analysis_stats": {
                "harmless": 70,
                "malicious": 0,
                "suspicious": 0,
                "undetected": 10,
                "timeout": 0,
            },
            "reputation": 0,
            "source": "mock",
        }
        # Mark some well-known "demo bad" IPs as malicious in the mock
        if ip in {"45.133.1.10"}:
            mocked["last_analysis_stats"]["malicious"] = 12
            mocked["reputation"] = -50
        return mocked

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    resp = requests.get(url, headers=headers, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    attrs = data.get("data", {}).get("attributes", {})
    return {
        "ip": ip,
        "last_analysis_stats": attrs.get("last_analysis_stats", {}),
        "reputation": attrs.get("reputation"),
        "source": "virustotal",
    }


# ---------------------------
# Vulners (vulnerability search)
# ---------------------------

def vulners_search(query: str, api_key: Optional[str]) -> List[Dict[str, Any]]:
    """
    Returns a list of normalized vulnerabilities:
        {"id": "...", "title": "...", "cvss": 9.8, "cve": "CVE-....", "href": "..."}
    If api_key is missing, returns a mocked response.
    """
    if not api_key:
        # MOCKED results for a few typical queries
        q = query.lower()
        vulns: List[Dict[str, Any]] = []
        if "apache" in q and "2.4.49" in q:
            vulns.append({
                "id": "VULNERS-MOCK-1",
                "title": "Apache HTTP Server 2.4.49 path traversal / RCE (demo)",
                "cvss": 9.8,
                "cve": "CVE-2021-41773",
                "href": "https://vulners.com/cve/CVE-2021-41773",
                "source": "mock",
            })
        if "openssl" in q and "1.0.2" in q:
            vulns.append({
                "id": "VULNERS-MOCK-2",
                "title": "OpenSSL 1.0.2 (demo high severity)",
                "cvss": 8.1,
                "cve": "CVE-2016-0800",
                "href": "https://vulners.com/cve/CVE-2016-0800",
                "source": "mock",
            })
        return vulns

    # Real API call (can be used if you provide VULNERS_API_KEY)
    url = "https://vulners.com/api/v3/search/lucene/"
    payload = {"query": query, "apiKey": api_key, "size": 20}
    resp = requests.post(url, json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    results: List[Dict[str, Any]] = []
    search_data = data.get("data", {}).get("search", [])
    for item in search_data:
        src = item.get("_source", {})
        cvss = None
        if isinstance(src.get("cvss"), dict):
            cvss = src["cvss"].get("score")
        elif isinstance(src.get("cvss"), (int, float)):
            cvss = float(src.get("cvss"))
        results.append({
            "id": src.get("id") or src.get("_id") or item.get("_id"),
            "title": src.get("title"),
            "cvss": cvss,
            "cve": src.get("cvelist", [None])[0] if isinstance(src.get("cvelist"), list) else None,
            "href": src.get("href"),
            "source": "vulners",
        })
    return results


# ---------------------------
# Threat analysis
# ---------------------------

def analyze_suricata(df: pd.DataFrame, cfg: Config) -> Dict[str, Any]:
    """Analyze Suricata events for alert concentration and DNS bursts."""
    out: Dict[str, Any] = {}

    alerts = df[df["event_type"] == "alert"].copy()
    if not alerts.empty:
        alerts["signature"] = alerts.get("alert.signature")
        alerts["category"] = alerts.get("alert.category")
        alerts["severity"] = alerts.get("alert.severity")
    out["alerts_df"] = alerts

    dns = df[df["event_type"] == "dns"].copy()
    if not dns.empty:
        dns["rrname"] = dns.get("dns.rrname")
        dns["rrtype"] = dns.get("dns.rrtype")
    out["dns_df"] = dns

    # Count alerts per IP (src and dest)
    if not alerts.empty:
        src_counts = alerts.groupby("src_ip").size().rename("alert_count").reset_index().rename(columns={"src_ip": "ip"})
        dst_counts = alerts.groupby("dest_ip").size().rename("alert_count").reset_index().rename(columns={"dest_ip": "ip"})
        alert_ip_counts = pd.concat([src_counts, dst_counts], ignore_index=True)
        alert_ip_counts = alert_ip_counts.groupby("ip", as_index=False)["alert_count"].sum()
    else:
        alert_ip_counts = pd.DataFrame(columns=["ip", "alert_count"])
    out["alert_ip_counts_df"] = alert_ip_counts

    # DNS bursts per src_ip
    if not dns.empty:
        dns_ip_counts = dns.groupby("src_ip").size().rename("dns_query_count").reset_index().rename(columns={"src_ip": "ip"})
    else:
        dns_ip_counts = pd.DataFrame(columns=["ip", "dns_query_count"])
    out["dns_ip_counts_df"] = dns_ip_counts

    suspicious_ips = set()
    if not alert_ip_counts.empty:
        suspicious_ips |= set(alert_ip_counts.loc[alert_ip_counts["alert_count"] >= cfg.alert_threshold, "ip"].tolist())
    if not dns_ip_counts.empty:
        suspicious_ips |= set(dns_ip_counts.loc[dns_ip_counts["dns_query_count"] >= cfg.dns_burst_threshold, "ip"].tolist())

    out["suspicious_ips_from_logs"] = sorted(suspicious_ips)
    return out


def enrich_with_virustotal(suspicious_ips: List[str], cfg: Config) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for ip in suspicious_ips:
        vt = vt_lookup_ip(ip, cfg.virustotal_api_key)
        stats = vt.get("last_analysis_stats", {}) or {}
        rows.append({
            "ip": ip,
            "vt_malicious": int(stats.get("malicious", 0) or 0),
            "vt_suspicious": int(stats.get("suspicious", 0) or 0),
            "vt_harmless": int(stats.get("harmless", 0) or 0),
            "vt_undetected": int(stats.get("undetected", 0) or 0),
            "vt_reputation": vt.get("reputation"),
            "vt_source": vt.get("source"),
        })
    return pd.DataFrame(rows)


def analyze_vulnerabilities(cfg: Config) -> pd.DataFrame:
    asset_inventory = [
        "Apache HTTP Server 2.4.49",
        "OpenSSL 1.0.2",
    ]
    rows: List[Dict[str, Any]] = []
    for asset in asset_inventory:
        vulns = vulners_search(asset, cfg.vulners_api_key)
        for v in vulns:
            rows.append({
                "asset": asset,
                "vuln_id": v.get("id"),
                "title": v.get("title"),
                "cve": v.get("cve"),
                "cvss": v.get("cvss"),
                "href": v.get("href"),
                "source": v.get("source"),
            })
    df = pd.DataFrame(rows)
    if not df.empty:
        df["cvss"] = pd.to_numeric(df["cvss"], errors="coerce")
    return df


# ---------------------------
# Response / notifications
# ---------------------------

def simulate_block_ip(ip: str) -> None:
    print(f"[RESPONSE] Simulating block of IP {ip}: iptables -A INPUT -s {ip} -j DROP  (SIMULATED)")


def notify_telegram(message: str, bot_token: Optional[str], chat_id: Optional[str]) -> None:
    """Sends Telegram if credentials exist; otherwise prints a mock notification."""
    if not bot_token or not chat_id:
        print(f"[NOTIFY] Telegram (mock): {message}")
        return
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    resp = requests.post(url, json={"chat_id": chat_id, "text": message}, timeout=20)
    resp.raise_for_status()
    print("[NOTIFY] Telegram sent.")


def notify_email(message: str, smtp_host: Optional[str], smtp_user: Optional[str], smtp_pass: Optional[str], to_addr: Optional[str]) -> None:
    """Email is mocked unless all SMTP settings are provided"""
    if not (smtp_host and smtp_user and smtp_pass and to_addr):
        print(f"[NOTIFY] Email (mock): to=<recipient> body={message}")
        return
    print("[NOTIFY] Email sending is disabled in this exercise; use the mock output.")


# ---------------------------
# Reporting / visualization
# ---------------------------

def save_json(path: Path, payload: Any) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def save_csv(df: pd.DataFrame, path: Path) -> None:
    df.to_csv(path, index=False, encoding="utf-8")


def plot_top_ips(ip_counts: pd.DataFrame, out_path: Path, top_n: int = 5) -> None:
    if ip_counts.empty:
        print("[PLOT] No IP counts available; skipping plot.")
        return
    top = ip_counts.sort_values("alert_count", ascending=False).head(top_n)
    plt.figure(figsize=(9, 4.5))
    plt.bar(top["ip"], top["alert_count"])
    plt.title(f"Top-{top_n} IPs by Suricata alert count")
    plt.xlabel("IP")
    plt.ylabel("Alert count")
    plt.xticks(rotation=25, ha="right")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()
    print(f"[PLOT] Saved: {out_path}")


# ---------------------------
# Main pipeline
# ---------------------------

def run(cfg: Config) -> None:
    ensure_out_dir(cfg.out_dir)

    print(f"[COLLECT] Loading Suricata logs: {cfg.suricata_eve_path}")
    df = load_suricata_df(cfg.suricata_eve_path)
    print(f"[COLLECT] Loaded {len(df)} events")

    print("[ANALYZE] Analyzing Suricata events (alerts + DNS)...")
    sur = analyze_suricata(df, cfg)

    suspicious_ips = sur["suspicious_ips_from_logs"]
    print(f"[ANALYZE] Suspicious IPs from logs: {suspicious_ips}")

    print("[ANALYZE] Enriching suspicious IPs with VirusTotal reputation...")
    vt_df = enrich_with_virustotal(suspicious_ips, cfg) if suspicious_ips else pd.DataFrame(columns=["ip"])

    print("[ANALYZE] Searching vulnerabilities via Vulners...")
    vulns_df = analyze_vulnerabilities(cfg)

    # Threat decision logic
    threats: List[str] = []

    # 1) Malicious IPs by VT
    malicious_ips: List[str] = []
    if not vt_df.empty:
        malicious_ips = vt_df.loc[vt_df["vt_malicious"] > 0, "ip"].tolist()
        for ip in malicious_ips:
            threats.append(f"VirusTotal flagged IP {ip} as malicious")

    # 2) DNS bursts (from logs)
    dns_bursts: List[str] = []
    dns_counts = sur["dns_ip_counts_df"]
    if isinstance(dns_counts, pd.DataFrame) and not dns_counts.empty:
        dns_bursts = dns_counts.loc[dns_counts["dns_query_count"] >= cfg.dns_burst_threshold, "ip"].tolist()
        for ip in dns_bursts:
            threats.append(f"DNS burst detected from {ip} (>= {cfg.dns_burst_threshold} queries)")

    # 3) High CVSS vulnerabilities
    if not vulns_df.empty and "cvss" in vulns_df.columns:
        high_vulns = vulns_df.loc[vulns_df["cvss"] >= cfg.high_cvss_threshold].copy()
        for _, row in high_vulns.iterrows():
            threats.append(f"High CVSS vulnerability on {row.get('asset')} ({row.get('cve')}, CVSS {row.get('cvss')})")

    # Respond
    if threats:
        print("\n[THREAT] Threats found:")
        for t in threats:
            print(f" - {t}")

        for ip in sorted(set(malicious_ips + dns_bursts)):
            simulate_block_ip(ip)

        notify_msg = "Threats detected:\n" + "\n".join(f"- {t}" for t in threats)
        notify_telegram(
            notify_msg,
            bot_token=os.getenv("TELEGRAM_BOT_TOKEN"),
            chat_id=os.getenv("TELEGRAM_CHAT_ID"),
        )
        notify_email(
            notify_msg,
            smtp_host=os.getenv("SMTP_HOST"),
            smtp_user=os.getenv("SMTP_USER"),
            smtp_pass=os.getenv("SMTP_PASS"),
            to_addr=os.getenv("ALERT_EMAIL_TO"),
        )
    else:
        print("[THREAT] No threats found based on current thresholds.")

    # Reporting
    print("\n[REPORT] Saving results...")
    save_csv(vt_df, cfg.out_dir / "suspicious_ips_with_vt.csv")
    save_csv(vulns_df, cfg.out_dir / "vulnerabilities.csv")

    report = {
        "suspicious_ips_from_logs": suspicious_ips,
        "threats": threats,
        "virustotal": vt_df.to_dict(orient="records") if not vt_df.empty else [],
        "vulnerabilities": vulns_df.to_dict(orient="records") if not vulns_df.empty else [],
        "dns_ip_counts": sur["dns_ip_counts_df"].to_dict(orient="records") if isinstance(sur["dns_ip_counts_df"], pd.DataFrame) else [],
        "alert_ip_counts": sur["alert_ip_counts_df"].to_dict(orient="records") if isinstance(sur["alert_ip_counts_df"], pd.DataFrame) else [],
    }
    save_json(cfg.out_dir / "report.json", report)

    plot_top_ips(sur["alert_ip_counts_df"], cfg.out_dir / "top5_ips.png", top_n=5)
    print(f"[DONE] Outputs written to: {cfg.out_dir}")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Cybersecurity pipeline demo (Suricata + VirusTotal + Vulners)")
    p.add_argument("--suricata-eve", default="data/suricata_eve.json", help="Path to Suricata EVE JSON file")
    p.add_argument("--out", default="results", help="Output directory")
    p.add_argument("--dns-burst-threshold", type=int, default=25, help="Threshold for DNS burst per IP")
    p.add_argument("--alert-threshold", type=int, default=2, help="Threshold for total alerts per IP")
    p.add_argument("--high-cvss", type=float, default=8.0, help="High severity CVSS threshold")
    return p


def main() -> None:
    args = build_arg_parser().parse_args()

    cfg = Config(
        suricata_eve_path=Path(args.suricata_eve),
        out_dir=Path(args.out),
        dns_burst_threshold=args.dns_burst_threshold,
        alert_threshold=args.alert_threshold,
        high_cvss_threshold=args.high_cvss,
        virustotal_api_key=os.getenv("VT_API_KEY"),
        vulners_api_key=os.getenv("VULNERS_API_KEY"),
    )
    run(cfg)


if __name__ == "__main__":
    main()