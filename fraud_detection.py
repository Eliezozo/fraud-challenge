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
EARLY_HISTORY_MAX = 2
EARLY_AMOUNT_FACTOR = 12.0
GEO_TIME_LIMIT_HOURS = 6.0
FREQUENCY_WINDOW_HOURS = 1.0
FREQUENCY_LIMIT = 5
DUPLICATE_WINDOW_HOURS = 0.5
REMOTE_PAYMENT_MIN_AMOUNT = 1000.0
NIGHT_MIN_AMOUNT = 200.0

CRITICAL_FIELDS = ("transaction_id", "user_id", "amount", "currency", "merchant")

HIGH_RISK_MERCHANT_KEYWORDS = (
    "bijouterie", "joaillerie", "jewelry", "casino", "crypto", "bitcoin",
    "western union", "moneygram", "or ", "gold", "pawn", "pret",
)

SUSPICIOUS_MERCHANT_KEYWORDS = ("?", "unknown", "inconnu", "test", "xxx")


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


def _build_user_groups(transactions):
    """Regroupe les transactions par client et mémorise l'ordre du fichier."""
    index_by_id = {}
    by_user = {}
    file_history_by_user = {}

    for index, tx in enumerate(transactions):
        tid = tx.get("transaction_id")
        if tid is not None:
            index_by_id[tid] = index

        user_id = tx.get("user_id")
        if user_id is None:
            continue

        by_user.setdefault(user_id, []).append(tx)
        file_history_by_user.setdefault(user_id, []).append(tx)

    return index_by_id, by_user, file_history_by_user


def _chronological_history(tx, user_txs, index_by_id):
    """Historique client antérieur à la transaction (timestamps désordonnés gérés)."""
    tid = tx.get("transaction_id")
    current_ts = _parse_timestamp(tx.get("timestamp"))
    current_index = index_by_id.get(tid)
    history = []

    for other in user_txs:
        other_id = other.get("transaction_id")
        if other_id == tid:
            continue

        other_ts = _parse_timestamp(other.get("timestamp"))
        if current_ts is not None and other_ts is not None:
            if other_ts < current_ts:
                history.append(other)
            elif other_ts == current_ts and current_index is not None:
                other_index = index_by_id.get(other_id)
                if other_index is not None and other_index < current_index:
                    history.append(other)
        elif current_ts is None and current_index is not None:
            other_index = index_by_id.get(other_id)
            if other_index is not None and other_index < current_index:
                history.append(other)

    return history


def _history_for(tx, by_user, file_history_by_user, index_by_id):
    user_id = tx.get("user_id")
    if user_id is None:
        return []

    user_txs = by_user.get(user_id, [])
    if _parse_timestamp(tx.get("timestamp")) is not None:
        return _chronological_history(tx, user_txs, index_by_id)

    tid = tx.get("transaction_id")
    current_index = index_by_id.get(tid)
    if current_index is None:
        return []

    return [
        other
        for other in file_history_by_user.get(user_id, [])
        if index_by_id.get(other.get("transaction_id"), current_index) < current_index
    ]


def _hour_of(tx):
    dt = _parse_timestamp(tx.get("timestamp"))
    return dt.hour if dt else None


def _valid_amounts(history):
    return [
        h["amount"]
        for h in history
        if h.get("amount") is not None and h["amount"] > 0
    ]


def _amount_baseline(history):
    valid = _valid_amounts(history)
    if len(valid) < MIN_HISTORY_FOR_AMOUNT:
        return None
    baseline = statistics.median(valid)
    return baseline if baseline > 0 else None


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
    baseline = _amount_baseline(history)
    if amount is None or amount <= 0 or baseline is None:
        return None
    if amount > baseline * AMOUNT_FACTOR:
        return (0.9, "Montant très supérieur à l'habitude du client")
    return None


def _check_early_amount_spike(tx, history):
    """Pic de montant alors que le client n'a que peu d'historique."""
    amount = tx.get("amount")
    valid = _valid_amounts(history)
    if amount is None or amount <= 0:
        return None
    if len(valid) < 1 or len(valid) > EARLY_HISTORY_MAX:
        return None

    baseline = statistics.median(valid)
    if baseline > 0 and amount > baseline * EARLY_AMOUNT_FACTOR:
        return (0.86, "Montant anormalement élevé pour un historique client limité")

    return None


def _check_amount_zscore(tx, history):
    """Écart statistique par rapport à l'historique (complète le ratio simple)."""
    amount = tx.get("amount")
    valid = _valid_amounts(history)
    if amount is None or amount <= 0 or len(valid) < MIN_HISTORY_FOR_AMOUNT:
        return None

    mean = statistics.mean(valid)
    try:
        stdev = statistics.stdev(valid)
    except statistics.StatisticsError:
        return None

    if stdev <= 0:
        return None

    zscore = (amount - mean) / stdev
    if zscore >= 4.0:
        return (0.82, "Montant statistiquement aberrant pour ce client")
    return None


GEO_REASON = "Deux pays différents en trop peu de temps"


def _find_geo_conflict(tx, history):
    country = tx.get("country")
    timestamp = tx.get("timestamp")
    if not country or not timestamp:
        return None

    closest = None
    closest_hours = None
    for past in history:
        past_country = past.get("country")
        past_ts = past.get("timestamp")
        if not past_country or not past_ts or past_country == country:
            continue

        hours = _hours_between(past_ts, timestamp)
        if hours is not None and hours < GEO_TIME_LIMIT_HOURS:
            if closest_hours is None or hours < closest_hours:
                closest = past
                closest_hours = hours

    return closest


def _check_geo_anomaly(tx, history):
    if _find_geo_conflict(tx, history) is not None:
        return (0.88, GEO_REASON)
    return None


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


def _check_velocity_amount(tx, history):
    """Somme des montants du client sur la dernière heure."""
    amount = tx.get("amount")
    timestamp = tx.get("timestamp")
    if amount is None or amount <= 0 or not timestamp:
        return None

    baseline = _amount_baseline(history)
    if baseline is None:
        return None

    rolling_sum = amount
    for past in history:
        past_amount = past.get("amount")
        past_ts = past.get("timestamp")
        if past_amount is None or past_amount <= 0 or not past_ts:
            continue
        hours = _hours_between(past_ts, timestamp)
        if hours is not None and hours <= FREQUENCY_WINDOW_HOURS:
            rolling_sum += past_amount

    if rolling_sum > baseline * AMOUNT_FACTOR * 2:
        return (0.67, "Volume de dépenses très élevé sur la dernière heure")

    return None


def _check_card_not_present(tx, history):
    amount = tx.get("amount")
    baseline = _amount_baseline(history)
    if tx.get("card_present") is not False or amount is None or amount <= 0 or baseline is None:
        return None
    if amount > baseline * AMOUNT_FACTOR:
        return (0.75, "Gros montant sans carte physique présente")
    return None


def _check_remote_high_payment(tx, history):
    """Paiement à distance (CNP) de montant élevé, même sans historique long."""
    amount = tx.get("amount")
    if tx.get("card_present") is not False or amount is None:
        return None
    if amount >= REMOTE_PAYMENT_MIN_AMOUNT:
        return (0.76, "Paiement à distance de montant très élevé")
    return None


def _check_night_transaction(tx, history):
    """Transactions nocturnes (0h-5h) avec montant significatif."""
    hour = _hour_of(tx)
    amount = tx.get("amount")
    if hour is None or amount is None or amount < NIGHT_MIN_AMOUNT:
        return None
    if 0 <= hour < 5:
        return (0.62, "Transaction effectuée en pleine nuit (0h-5h)")
    return None


def _check_high_risk_merchant(tx, history):
    merchant = (tx.get("merchant") or "").lower()
    amount = tx.get("amount") or 0
    if not any(keyword in merchant for keyword in HIGH_RISK_MERCHANT_KEYWORDS):
        return None
    if tx.get("card_present") is False or amount >= 500:
        return (0.78, "Commerçant à risque élevé (bijouterie, casino, transfert…)")
    return None


def _check_suspicious_merchant_name(tx, history):
    merchant = (tx.get("merchant") or "").lower()
    if any(keyword in merchant for keyword in SUSPICIOUS_MERCHANT_KEYWORDS):
        return (0.58, "Nom de commerçant suspect ou incomplet")
    return None


def _check_duplicate_transaction(tx, history):
    amount = tx.get("amount")
    merchant = tx.get("merchant")
    timestamp = tx.get("timestamp")
    if amount is None or not merchant or not timestamp:
        return None

    for past in history:
        if past.get("amount") != amount or past.get("merchant") != merchant:
            continue
        hours = _hours_between(past.get("timestamp"), timestamp)
        if hours is not None and hours <= DUPLICATE_WINDOW_HOURS:
            return (0.72, "Transaction dupliquée en très peu de temps")
    return None


def _check_currency_change_rapid(tx, history):
    """Changement de devise rapide, souvent corrélé à une fraude."""
    currency = tx.get("currency")
    timestamp = tx.get("timestamp")
    if not currency or not timestamp:
        return None

    for past in history:
        past_currency = past.get("currency")
        past_ts = past.get("timestamp")
        if not past_currency or past_currency == currency:
            continue
        hours = _hours_between(past_ts, timestamp)
        if hours is not None and hours < GEO_TIME_LIMIT_HOURS:
            return (0.66, "Changement de devise en peu de temps")

    return None


def _check_new_merchant_high_spend(tx, history):
    """Premier achat chez un commerçant inconnu avec montant élevé."""
    amount = tx.get("amount")
    merchant = (tx.get("merchant") or "").lower()
    baseline = _amount_baseline(history)
    if not merchant or amount is None or amount <= 0 or baseline is None:
        return None

    known_merchants = {(h.get("merchant") or "").lower() for h in history}
    if merchant in known_merchants:
        return None

    if amount > baseline * 5:
        return (0.64, "Premier achat chez un commerçant inconnu, montant élevé")

    return None


def _check_unusual_hour_for_client(tx, history):
    """Heure inhabituelle par rapport aux habitudes horaires du client."""
    hour = _hour_of(tx)
    if hour is None or len(history) < MIN_HISTORY_FOR_AMOUNT:
        return None

    past_hours = [_hour_of(h) for h in history]
    past_hours = [h for h in past_hours if h is not None]
    if len(past_hours) < MIN_HISTORY_FOR_AMOUNT:
        return None

    typical_start = min(past_hours)
    typical_end = max(past_hours)
    # Marge de 2 h autour de la plage habituelle observée
    if hour < typical_start - 2 or hour > typical_end + 2:
        amount = tx.get("amount")
        baseline = _amount_baseline(history)
        if amount and baseline and amount > baseline * 2:
            return (0.63, "Heure inhabituelle pour ce client, montant notable")

    return None


def _check_round_amount_spike(tx, history):
    """Montants ronds élevés (1000, 5000…) vs historique."""
    amount = tx.get("amount")
    baseline = _amount_baseline(history)
    if amount is None or baseline is None:
        return None
    if amount >= 1000 and amount % 100 == 0 and amount > baseline * AMOUNT_FACTOR:
        return (0.61, "Montant rond élevé, atypique pour ce client")
    return None


CHECKERS = (
    _check_missing_fields,
    _check_invalid_amount,
    _check_amount_anomaly,
    _check_early_amount_spike,
    _check_amount_zscore,
    _check_geo_anomaly,
    _check_frequency,
    _check_velocity_amount,
    _check_card_not_present,
    _check_remote_high_payment,
    _check_night_transaction,
    _check_high_risk_merchant,
    _check_suspicious_merchant_name,
    _check_duplicate_transaction,
    _check_currency_change_rapid,
    _check_new_merchant_high_spend,
    _check_unusual_hour_for_client,
    _check_round_amount_spike,
)


def _analyze(tx, history):
    signals = [
        signal
        for checker in CHECKERS
        if (signal := checker(tx, history)) is not None
    ]

    if not signals:
        return {
            "transaction_id": tx.get("transaction_id"),
            "fraud_score": 0.0,
            "is_suspicious": False,
            "reason": "Transaction conforme au profil du client",
        }

    signals.sort(key=lambda s: s[0], reverse=True)
    fraud_score = min(1.0, signals[0][0])
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
    index_by_id, by_user, file_history_by_user = _build_user_groups(transactions)
    results = []

    for tx in transactions:
        history = _history_for(tx, by_user, file_history_by_user, index_by_id)
        results.append(_analyze(tx, history))

    return results
