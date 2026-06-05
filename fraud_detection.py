"""
Défi — Détection de fraude financière.

Vous devez implémenter la fonction `detect_fraud`.
La fonction `load_transactions` vous est FOURNIE (ne la modifiez pas).
"""

import csv
import statistics
from datetime import datetime, timezone


SUSPICIOUS_THRESHOLD = 0.5
AMOUNT_FACTOR = 8.0
MIN_HISTORY_FOR_AMOUNT = 3
GEO_TIME_LIMIT_HOURS = 6.0
FREQUENCY_WINDOW_HOURS = 1.0
FREQUENCY_LIMIT = 5

CRITICAL_FIELDS = ("transaction_id", "user_id", "amount", "currency", "merchant")


def load_transactions(path):
    """Lit un fichier CSV de transactions et renvoie une liste de dicts."""
    transactions = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            transactions.append(_clean_row(row))
    return transactions


def _clean_row(row):
    def get(key):
        v = row.get(key)
        return v.strip() if isinstance(v, str) and v.strip() != "" else None

    amount_raw = get("amount")
    try:
        amount = float(amount_raw) if amount_raw is not None else None
    except ValueError:
        amount = None

    card_raw = get("card_present")
    if card_raw is None:
        card_present = None
    else:
        card_present = card_raw.lower() in ("true", "1", "yes", "oui")

    return {
        "transaction_id": get("transaction_id"),
        "timestamp": get("timestamp"),
        "user_id": get("user_id"),
        "amount": amount,
        "currency": get("currency"),
        "merchant": get("merchant"),
        "country": get("country"),
        "card_present": card_present,
    }


def _parse_timestamp(ts):
    if not ts or not isinstance(ts, str):
        return None
    try:
        normalized = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _hours_between(ts_a, ts_b):
    dt_a = _parse_timestamp(ts_a)
    dt_b = _parse_timestamp(ts_b)
    if dt_a is None or dt_b is None:
        return None
    return abs((dt_b - dt_a).total_seconds()) / 3600.0


def _check_missing_fields(tx, history=None):
    missing = [field for field in CRITICAL_FIELDS if tx.get(field) is None]
    if tx.get("country") is None:
        missing.append("country")
    if not missing:
        return None
    labels = ", ".join(sorted(set(missing)))
    return (0.85, f"Champs obligatoires manquants: {labels}")


def _check_invalid_amount(tx, history=None):
    amount = tx.get("amount")
    if amount is None or amount <= 0:
        return (0.9, "Montant nul ou négatif")
    return None


def _check_amount_anomaly(tx, history):
    amount = tx.get("amount")
    if amount is None or amount <= 0:
        return None

    valid_amounts = [
        h["amount"]
        for h in history
        if h.get("amount") is not None and h["amount"] > 0
    ]
    if len(valid_amounts) < MIN_HISTORY_FOR_AMOUNT:
        return None

    baseline = statistics.median(valid_amounts)
    if baseline <= 0:
        return None

    if amount > baseline * AMOUNT_FACTOR:
        return (0.9, "Montant très supérieur à l'habitude du client")

    return None


GEO_REASON = "Deux pays différents en trop peu de temps"


def _find_geo_conflict(tx, history):
    country = tx.get("country")
    timestamp = tx.get("timestamp")
    if not country or not timestamp:
        return None

    for past in reversed(history):
        past_country = past.get("country")
        past_ts = past.get("timestamp")
        if not past_country or not past_ts or past_country == country:
            continue

        hours = _hours_between(past_ts, timestamp)
        if hours is not None and hours < GEO_TIME_LIMIT_HOURS:
            return past
        break

    return None


def _check_geo_anomaly(tx, history):
    if _find_geo_conflict(tx, history) is not None:
        return (0.88, GEO_REASON)
    return None


def _apply_geo_flag(result):
    result["fraud_score"] = max(result.get("fraud_score", 0.0), 0.88)
    result["is_suspicious"] = result["fraud_score"] >= SUSPICIOUS_THRESHOLD
    if result.get("reason") == "Transaction conforme au profil du client":
        result["reason"] = GEO_REASON


def _check_frequency(tx, history):
    timestamp = tx.get("timestamp")
    if not timestamp:
        return None

    recent = 0
    for past in history:
        past_ts = past.get("timestamp")
        if not past_ts:
            continue
        hours = _hours_between(past_ts, timestamp)
        if hours is not None and hours <= FREQUENCY_WINDOW_HOURS:
            recent += 1

    if recent >= FREQUENCY_LIMIT:
        return (0.65, "Fréquence de transactions anormalement élevée")

    return None


def _check_card_not_present(tx, history):
    amount = tx.get("amount")
    if tx.get("card_present") is not False or amount is None or amount <= 0:
        return None

    valid_amounts = [
        h["amount"]
        for h in history
        if h.get("amount") is not None and h["amount"] > 0
    ]
    if len(valid_amounts) < MIN_HISTORY_FOR_AMOUNT:
        return None

    baseline = statistics.median(valid_amounts)
    if baseline > 0 and amount > baseline * AMOUNT_FACTOR:
        return (0.75, "Gros montant sans carte physique présente")

    return None


def _analyze(tx, history):
    signals = [
        signal
        for checker in (
            _check_missing_fields,
            _check_invalid_amount,
            lambda t, h: _check_amount_anomaly(t, h),
            lambda t, h: _check_geo_anomaly(t, h),
            lambda t, h: _check_frequency(t, h),
            lambda t, h: _check_card_not_present(t, h),
        )
        if (signal := checker(tx, history)) is not None
    ]

    if not signals:
        return {
            "transaction_id": tx.get("transaction_id"),
            "fraud_score": 0.0,
            "is_suspicious": False,
            "reason": "Transaction conforme au profil du client",
        }

    fraud_score = min(1.0, max(score for score, _ in signals))
    is_suspicious = fraud_score >= SUSPICIOUS_THRESHOLD
    reason = signals[0][1] if len(signals) == 1 else " ; ".join(dict.fromkeys(r for _, r in signals))

    return {
        "transaction_id": tx.get("transaction_id"),
        "fraud_score": round(fraud_score, 2),
        "is_suspicious": is_suspicious,
        "reason": reason,
    }


def detect_fraud(transactions):
    """Analyse une liste de transactions et renvoie un verdict pour chacune.

    Retour : list[dict] avec transaction_id, fraud_score (0-1),
    is_suspicious (bool), reason (str) — un résultat par transaction, même ordre.
    """
    results = []
    history_by_user = {}
    index_by_id = {}

    for tx in transactions:
        user_id = tx.get("user_id")
        history = history_by_user.get(user_id, [])
        result = _analyze(tx, history)
        results.append(result)

        conflict = _find_geo_conflict(tx, history)
        if conflict is not None:
            past_id = conflict.get("transaction_id")
            if past_id in index_by_id:
                _apply_geo_flag(results[index_by_id[past_id]])

        tid = tx.get("transaction_id")
        if tid is not None:
            index_by_id[tid] = len(results) - 1

        if user_id is not None:
            history_by_user.setdefault(user_id, []).append(tx)

    return results
