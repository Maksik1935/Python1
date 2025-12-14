
from __future__ import annotations

import argparse
import json
import math
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd

# --- plotting: seaborn optional ---
def _import_plotting():
    try:
        import seaborn as sns  # noqa
        import matplotlib.pyplot as plt  # noqa
        return "seaborn"
    except Exception:
        import matplotlib.pyplot as plt  # noqa
        return "matplotlib"


# -----------------------------
# Helpers
# -----------------------------
def first_scalar(v: Any) -> Any:
    """If v is list/tuple, take first element, else return v."""
    if isinstance(v, (list, tuple)) and v:
        return v[0]
    return v


def safe_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    v = first_scalar(v)
    try:
        s = str(v).strip().strip('"')
        return int(s)
    except Exception:
        return None


def get_any(d: Dict[str, Any], keys: Iterable[str]) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, "", []):
            return d[k]
    return None


def normalize_qname(q: str) -> str:
    q = q.strip().lower()
    if q.endswith("."):
        q = q[:-1]
    q = re.sub(r"\s+", "", q)
    return q


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def digits_ratio(s: str) -> float:
    if not s:
        return 0.0
    d = sum(ch.isdigit() for ch in s)
    return d / len(s)


def label_count(qname: str) -> int:
    return qname.count(".") + 1 if qname else 0


def longest_label_len(qname: str) -> int:
    if not qname:
        return 0
    return max((len(x) for x in qname.split(".")), default=0)


def get_base_domain(qname: str) -> str:
    """
    Извлекаем "базовый" домен.
    Пытаемся tldextract (если установлен)
    Иначе наивно: last 2 labels, с небольшой поддержкой multi-TLD
    """
    qname = normalize_qname(qname)
    if not qname or "." not in qname:
        return qname

    try:
        import tldextract  # type: ignore

        ext = tldextract.extract(qname)
        # domain + suffix, например example.com
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return qname
    except Exception:
        # грубая эвристика
        multi_suffix = {
            "co.uk", "org.uk", "ac.uk",
            "com.au", "net.au", "org.au",
            "co.jp", "ne.jp",
            "com.br", "com.mx",
            "co.in",
        }
        parts = qname.split(".")
        if len(parts) >= 3:
            last2 = ".".join(parts[-2:])
            last3 = ".".join(parts[-3:])
            if last2 in multi_suffix:
                return ".".join(parts[-3:])
            if last3.split(".", 1)[1] in multi_suffix:
                return last3
        return ".".join(parts[-2:])


# -----------------------------
# Loading
# -----------------------------
def load_events_from_file(path: Path) -> List[Dict[str, Any]]:
    """
    Возвращает список событий (dict).
    Если есть ключ 'result' — вытаскиваем его.
    """
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not text:
        return []

    # Try full JSON
    try:
        obj = json.loads(text)
        if isinstance(obj, list):
            out: List[Dict[str, Any]] = []
            for item in obj:
                if isinstance(item, dict) and "result" in item and isinstance(item["result"], dict):
                    out.append(item["result"])
                elif isinstance(item, dict):
                    out.append(item)
            return out
        if isinstance(obj, dict):
            if "result" in obj and isinstance(obj["result"], list):
                return [x.get("result", x) if isinstance(x, dict) else {"value": x} for x in obj["result"]]
            return [obj]
    except Exception:
        pass

    # Fallback: JSON lines
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict) and "result" in item and isinstance(item["result"], dict):
                out.append(item["result"])
            elif isinstance(item, dict):
                out.append(item)
        except Exception:
            continue
    return out


def expand_input_paths(inp: str) -> List[Path]:
    p = Path(inp)
    if p.is_dir():
        files = []
        for ext in ("*.json", "*.jsonl", "*.log"):
            files.extend(p.rglob(ext))
        return sorted(set(files))
    return [p]


def load_all_events(inp: str) -> List[Dict[str, Any]]:
    files = expand_input_paths(inp)
    all_events: List[Dict[str, Any]] = []
    for f in files:
        if f.exists() and f.is_file():
            all_events.extend(load_events_from_file(f))
    return all_events


# -----------------------------
# Classification
# -----------------------------
def is_wineventlog(ev: Dict[str, Any]) -> bool:
    st = str(get_any(ev, ["sourcetype", "_sourcetype", "source", "object"]) or "").lower()
    return "wineventlog" in st or "windows security auditing" in str(ev.get("SourceName", "")).lower()


def is_dns(ev: Dict[str, Any]) -> bool:
    st = str(get_any(ev, ["sourcetype", "_sourcetype", "source", "object"]) or "").lower()
    if "dns" in st:
        return True
    # по наличию типовых полей DNS
    for k in ("query", "qname", "query_name", "QueryName", "rrname", "question", "dns_query"):
        if k in ev:
            return True
    return False


def extract_event_id(ev: Dict[str, Any]) -> Optional[int]:
    # Splunk WinEventLog часто использует EventCode / signature_id
    return safe_int(get_any(ev, ["EventID", "EventCode", "signature_id", "SignatureID", "event_id"]))


def extract_win_signature(ev: Dict[str, Any]) -> str:
    s = get_any(ev, ["signature", "name", "subject", "TaskCategory", "Message"])
    s = first_scalar(s)
    if not s:
        return "Unknown"
    s = str(s).strip()
    # чтобы заголовок был коротким
    s = s.split("\n", 1)[0]
    return s[:120]


def extract_dns_qname(ev: Dict[str, Any]) -> Optional[str]:
    v = get_any(ev, ["query", "qname", "query_name", "QueryName", "rrname", "question_name", "dns_query"])
    v = first_scalar(v)
    if v:
        return normalize_qname(str(v))

    # попытка достать из _raw/Message (очень эвристично)
    raw = str(get_any(ev, ["_raw", "Message", "message"]) or "")
    m = re.search(r"\b([a-z0-9][a-z0-9\-_.]{2,253}\.[a-z]{2,63})\b", raw.lower())
    if m:
        return normalize_qname(m.group(1))
    return None


def extract_dns_qtype(ev: Dict[str, Any]) -> Optional[str]:
    v = get_any(ev, ["qtype", "query_type", "QueryType", "type", "rrtype"])
    v = first_scalar(v)
    if not v:
        return None
    s = str(v).strip().upper()
    # иногда type=Information у WinEventLog; для DNS берём только если похоже на qtype
    if re.fullmatch(r"[A-Z]{1,10}", s):
        return s
    return None


def extract_src(ev: Dict[str, Any]) -> str:
    v = get_any(ev, ["src_ip", "src", "client_ip", "ip", "host", "dvc", "ComputerName"])
    v = first_scalar(v)
    return str(v) if v else "unknown"


# -----------------------------
# WinEventLog suspiciousness
# -----------------------------
SUSPICIOUS_WINDOWS_EVENTIDS: Dict[int, str] = {
    # Logon/Auth
    4625: "Failed logon",
    4771: "Kerberos pre-auth failed",
    4768: "Kerberos TGT requested",
    4769: "Kerberos service ticket requested",
    4776: "NTLM authentication failed",
    4740: "Account locked out",
    4648: "Logon with explicit credentials",

    # Privilege / policy / clearing logs
    4672: "Special privileges assigned",
    4673: "Privileged service called",
    4674: "Operation on privileged object",
    4719: "Audit policy changed",
    4703: "User right adjusted",
    1102: "Audit log cleared",

    # Account / group management
    4720: "User account created",
    4722: "User account enabled",
    4723: "Attempt to change password",
    4724: "Attempt to reset password",
    4725: "User account disabled",
    4726: "User account deleted",
    4738: "User account changed",
    4728: "Member added to global group",
    4729: "Member removed from global group",
    4732: "Member added to local group",
    4733: "Member removed from local group",
    4756: "Member added to universal group",
    4757: "Member removed from universal group",

    # Execution / persistence
    4688: "Process created",
    4697: "Service installed",
    4698: "Scheduled task created",
    4699: "Scheduled task deleted",
    4700: "Scheduled task enabled",
    4701: "Scheduled task disabled",
    4702: "Scheduled task updated",

    # Service install (System log; иногда приходит как 7045)
    7045: "Service installed (System)",
}

REMOTE_LOGON_TYPES = {"3", "10", "11"}  # network / rdp / cachedinteractive


def analyze_wineventlog(events: List[Dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for ev in events:
        eid = extract_event_id(ev)
        if eid is None:
            continue

        # Основной критерий — EventID в списке
        suspicious = eid in SUSPICIOUS_WINDOWS_EVENTIDS

        # 4624 — успешные удалённые входы
        if eid == 4624:
            lt = first_scalar(ev.get("Logon_Type"))
            if lt is not None and str(lt) in REMOTE_LOGON_TYPES:
                suspicious = True

        if not suspicious:
            continue

        label = SUSPICIOUS_WINDOWS_EVENTIDS.get(eid, extract_win_signature(ev))
        rows.append(
            {
                "log_type": "WinEventLog",
                "event_id": eid,
                "label": f"{eid} — {label}",
                "src": extract_src(ev),
            }
        )

    df = pd.DataFrame(rows)
    if df.empty:
        return df

    top = (
        df.groupby(["log_type", "event_id", "label"], as_index=False)
        .size()
        .rename(columns={"size": "count"})
        .sort_values("count", ascending=False)
    )
    return top


# -----------------------------
# DNS suspiciousness
# -----------------------------
@dataclass(frozen=True)
class DNSHeuristicConfig:
    rare_max_global_count: int = 5           # домен считается "редким", если встречается <= этого числа раз глобально
    frequent_per_src_threshold: int = 3      # "часто" для конкретного src
    long_qname: int = 55
    many_labels: int = 6
    long_label: int = 20
    entropy_threshold: float = 3.6
    digits_ratio_threshold: float = 0.35


UNUSUAL_QTYPES = {"TXT", "NULL", "ANY"}  # можно расширять


def dns_suspicion_score(qname: str, qtype: Optional[str]) -> Tuple[int, List[str]]:
    """
    Возвращает (score, reasons).
    score — целое для простоты ранжирования.
    """
    reasons = []
    score = 0

    if not qname:
        return 0, reasons

    n_labels = label_count(qname)
    ll = longest_label_len(qname)

    if len(qname) >= 55:
        score += 2
        reasons.append("long_qname")

    if n_labels >= 6:
        score += 2
        reasons.append("many_labels")

    if ll >= 20:
        score += 2
        reasons.append("long_label")

    left = qname.split(".", 1)[0]
    ent = shannon_entropy(left)
    if len(left) >= 10 and ent >= 3.6:
        score += 3
        reasons.append("high_entropy_subdomain")

    dr = digits_ratio(left)
    if len(left) >= 10 and dr >= 0.35:
        score += 2
        reasons.append("digits_heavy_subdomain")

    if "xn--" in qname:
        score += 2
        reasons.append("punycode")

    if qtype and qtype in UNUSUAL_QTYPES:
        score += 2
        reasons.append(f"unusual_qtype={qtype}")

    return score, reasons


def analyze_dns(events: List[Dict[str, Any]], cfg: DNSHeuristicConfig = DNSHeuristicConfig()) -> pd.DataFrame:
    """
    Считаем глобальную частоту base_domain
    Ищем частые обращения к редким доменам на уровне src -> base_domain
    Добавляем score за странный поддомен (энтропия/длина/кол-во лейблов)
    Ранжируем base_domain по суммарному score или count
    """
    dns_rows = []
    for ev in events:
        qname = extract_dns_qname(ev)
        if not qname:
            continue
        qtype = extract_dns_qtype(ev)
        base = get_base_domain(qname)
        src = extract_src(ev)

        local_score, reasons = dns_suspicion_score(qname, qtype)
        dns_rows.append(
            {
                "log_type": "DNS",
                "src": src,
                "qname": qname,
                "base_domain": base,
                "qtype": qtype,
                "pattern_score": local_score,
                "reasons": ",".join(reasons),
            }
        )

    df = pd.DataFrame(dns_rows)
    if df.empty:
        return df

    # Глобальная частота доменов
    global_counts = df["base_domain"].value_counts().to_dict()

    # Частота доменов по src
    by_src_domain = (
        df.groupby(["src", "base_domain"], as_index=False)
        .size()
        .rename(columns={"size": "src_domain_count"})
    )

    # Признак "редкий домен"
    by_src_domain["global_count"] = by_src_domain["base_domain"].map(global_counts).fillna(0).astype(int)
    by_src_domain["is_rare"] = by_src_domain["global_count"] <= cfg.rare_max_global_count
    by_src_domain["is_frequent_for_src"] = by_src_domain["src_domain_count"] >= cfg.frequent_per_src_threshold

    # Скор за "часто + редкий"
    # Чем реже домен глобально, тем больше вес.
    by_src_domain["rare_freq_score"] = 0
    mask = by_src_domain["is_rare"] & by_src_domain["is_frequent_for_src"]
    by_src_domain.loc[mask, "rare_freq_score"] = (
            by_src_domain.loc[mask, "src_domain_count"] * (cfg.rare_max_global_count + 1 - by_src_domain.loc[mask, "global_count"])
    )

    # Суммируем pattern_score по домену (поддомены/энтропия/длина и т.п.)
    pattern_sum = df.groupby("base_domain", as_index=False)["pattern_score"].sum().rename(columns={"pattern_score": "pattern_score_sum"})
    total_queries = df.groupby("base_domain", as_index=False).size().rename(columns={"size": "count"})

    # Суммируем rare_freq_score по домену
    rare_freq_sum = by_src_domain.groupby("base_domain", as_index=False)["rare_freq_score"].sum()

    out = total_queries.merge(pattern_sum, on="base_domain", how="left").merge(rare_freq_sum, on="base_domain", how="left")
    out["pattern_score_sum"] = out["pattern_score_sum"].fillna(0).astype(int)
    out["rare_freq_score"] = out["rare_freq_score"].fillna(0).astype(int)

    # Итоговый score
    out["score"] = out["rare_freq_score"] + out["pattern_score_sum"]
    out["label"] = out["base_domain"]

    out = out.sort_values(["score", "count"], ascending=[False, False])
    out.insert(0, "log_type", "DNS")
    return out


# -----------------------------
# Plotting
# -----------------------------
def plot_top10(df: pd.DataFrame, value_col: str, label_col: str, title: str, out_png: Path) -> None:
    backend = _import_plotting()
    import matplotlib.pyplot as plt

    top10 = df.head(10).copy()
    if top10.empty:
        return

    top10 = top10.sort_values(value_col, ascending=True)  # для горизонтального bar

    plt.figure(figsize=(10, 6))
    if backend == "seaborn":
        import seaborn as sns

        sns.barplot(data=top10, x=value_col, y=label_col)
    else:
        plt.barh(top10[label_col], top10[value_col])

    plt.title(title)
    plt.xlabel(value_col)
    plt.ylabel(label_col)
    plt.tight_layout()
    out_png.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_png, dpi=160)
    plt.close()


def plot_combined(win_top: pd.DataFrame, dns_top: pd.DataFrame, out_png: Path) -> None:
    """
    Объединённая визуализация: берём топ из WinEventLog по count и DNS по score,
    нормализуем имена и рисуем один общий топ-10.
    """
    parts = []
    if not win_top.empty:
        w = win_top.copy()
        w["metric"] = w["count"].astype(float)
        w["item"] = w["label"].astype(str)
        w["type"] = "WinEventLog"
        parts.append(w[["type", "item", "metric"]])

    if not dns_top.empty:
        d = dns_top.copy()
        d["metric"] = d["score"].astype(float)
        d["item"] = d["label"].astype(str)
        d["type"] = "DNS"
        parts.append(d[["type", "item", "metric"]])

    if not parts:
        return

    combo = pd.concat(parts, ignore_index=True)
    combo["label"] = combo["type"] + ": " + combo["item"]
    combo = combo.sort_values("metric", ascending=False).head(10)

    plot_top10(combo, value_col="metric", label_col="label",
               title="Top-10 suspicious (WinEventLog count + DNS score)", out_png=out_png)


# -----------------------------
# Main
# -----------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Файл или директория с логами (json/jsonl)")
    ap.add_argument("--outdir", default="out", help="Куда сохранять результаты")
    ap.add_argument("--combined", action="store_true", help="Сделать объединённый график")
    ap.add_argument("--rare-max-global", type=int, default=5, help="DNS: домен редкий если global_count <= N")
    ap.add_argument("--freq-per-src", type=int, default=3, help="DNS: часто для src если src_domain_count >= N")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    events = load_all_events(args.input)
    if not events:
        raise SystemExit("Не удалось прочитать события из input.")

    win_events = [e for e in events if is_wineventlog(e)]
    dns_events = [e for e in events if is_dns(e)]

    # --- WinEventLog ---
    win_top = analyze_wineventlog(win_events)
    if not win_top.empty:
        win_top.to_csv(outdir / "wineventlog_suspicious_top.csv", index=False, encoding="utf-8")
        plot_top10(
            win_top,
            value_col="count",
            label_col="label",
            title="WinEventLog: Top-10 suspicious EventID (by count)",
            out_png=outdir / "wineventlog_top10.png",
        )
    else:
        print("WinEventLog: подозрительных событий по списку EventID не найдено.")

    # --- DNS ---
    cfg = DNSHeuristicConfig(
        rare_max_global_count=args.rare_max_global,
        frequent_per_src_threshold=args.freq_per_src,
    )
    dns_top = analyze_dns(dns_events, cfg=cfg)
    if not dns_top.empty:
        dns_top.to_csv(outdir / "dns_suspicious_top.csv", index=False, encoding="utf-8")
        plot_top10(
            dns_top,
            value_col="score",
            label_col="label",
            title="DNS: Top-10 suspicious domains (by score)",
            out_png=outdir / "dns_top10.png",
        )
    else:
        print("DNS: события не найдены (или не удалось извлечь query/qname).")

    # --- Combined ---
    if args.combined:
        plot_combined(win_top, dns_top, out_png=outdir / "combined_top10.png")

    print(f"Готово. Результаты в: {outdir.resolve()}")


if __name__ == "__main__":
    main()
