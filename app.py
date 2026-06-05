"""
Interface Streamlit — Hackathon INTELO2026
"""

from pathlib import Path

import pandas as pd
import streamlit as st

from fraud_detection import detect_fraud, load_transactions

SAMPLE_CSV = Path(__file__).parent / "data" / "sample_transactions.csv"


def _risk_label(score: float) -> str:
    if score >= 0.7:
        return "Élevé"
    if score >= 0.4:
        return "Modéré"
    return "Faible"


def _risk_color(score: float) -> str:
    if score >= 0.7:
        return "#e74c3c"
    if score >= 0.4:
        return "#f39c12"
    return "#1D9E75"


def render_interface(transactions: list[dict], results: list[dict]) -> None:
    tx_by_id = {t["transaction_id"]: t for t in transactions}
    rows = []
    for r in results:
        tx = tx_by_id.get(r["transaction_id"], {})
        rows.append({
            "ID": r["transaction_id"],
            "Client": tx.get("user_id", "—"),
            "Montant": tx.get("amount"),
            "Devise": tx.get("currency", "—"),
            "Pays": tx.get("country") or "—",
            "Commerçant": tx.get("merchant", "—"),
            "Score": r["fraud_score"],
            "Niveau": _risk_label(r["fraud_score"]),
            "Verdict": "Suspecte" if r["is_suspicious"] else "Conforme",
            "Raison": r["reason"],
        })

    df = pd.DataFrame(rows)
    alerts = sum(1 for r in results if r["is_suspicious"])
    avg_score = sum(r["fraud_score"] for r in results) / len(results) if results else 0.0

    col1, col2, col3 = st.columns(3)
    col1.metric("Transactions analysées", len(transactions))
    col2.metric("Alertes détectées", alerts)
    col3.metric("Score moyen de risque", f"{avg_score:.2f}")

    st.divider()

    filter_col1, filter_col2, filter_col3 = st.columns(3)
    with filter_col1:
        verdict_filter = st.selectbox(
            "Filtrer par verdict",
            ["Toutes", "Suspectes uniquement", "Conformes uniquement"],
        )
    with filter_col2:
        users = sorted({t.get("user_id") for t in transactions if t.get("user_id")})
        user_filter = st.selectbox("Filtrer par client", ["Tous"] + users)
    with filter_col3:
        risk_filter = st.selectbox("Filtrer par niveau de risque", ["Tous", "Élevé", "Modéré", "Faible"])

    filtered = df.copy()
    if verdict_filter == "Suspectes uniquement":
        filtered = filtered[filtered["Verdict"] == "Suspecte"]
    elif verdict_filter == "Conformes uniquement":
        filtered = filtered[filtered["Verdict"] == "Conforme"]
    if user_filter != "Tous":
        filtered = filtered[filtered["Client"] == user_filter]
    if risk_filter != "Tous":
        filtered = filtered[filtered["Niveau"] == risk_filter]

    st.subheader("Résultats de l'analyse")
    st.caption(f"{len(filtered)} transaction(s) affichée(s)")

    def _style_row(row):
        color = "#fdecea" if row["Verdict"] == "Suspecte" else "#eafaf1"
        return [f"background-color: {color}"] * len(row)

    display_cols = ["ID", "Client", "Montant", "Devise", "Pays", "Commerçant", "Score", "Verdict", "Raison"]
    st.dataframe(
        filtered[display_cols].style.apply(_style_row, axis=1),
        use_container_width=True,
        hide_index=True,
    )

    if alerts:
        st.subheader("Alertes par client")
        alert_counts = (
            filtered[filtered["Verdict"] == "Suspecte"]
            .groupby("Client")
            .size()
            .reset_index(name="Alertes")
        )
        if not alert_counts.empty:
            st.bar_chart(alert_counts.set_index("Client"))

    st.divider()
    st.subheader("Détail d'une transaction")
    ids = filtered["ID"].tolist() if not filtered.empty else df["ID"].tolist()
    if ids:
        selected_id = st.selectbox("Choisir une transaction", ids)
        selected_result = next(r for r in results if r["transaction_id"] == selected_id)
        selected_tx = tx_by_id.get(selected_id, {})
        score = selected_result["fraud_score"]
        st.markdown(
            f"**Verdict :** {'Transaction suspecte' if selected_result['is_suspicious'] else 'Transaction conforme'}  \n"
            f"**Score de risque :** :{('red' if score >= 0.7 else 'orange' if score >= 0.4 else 'green')}"
            f"[{score:.2f} — {_risk_label(score)}]"
        )
        st.info(selected_result["reason"])
        detail_cols = st.columns(4)
        detail_cols[0].write(f"**Client :** {selected_tx.get('user_id', '—')}")
        detail_cols[1].write(f"**Montant :** {selected_tx.get('amount')} {selected_tx.get('currency', '')}")
        detail_cols[2].write(f"**Pays :** {selected_tx.get('country') or '—'}")
        detail_cols[3].write(f"**Carte présente :** {'Oui' if selected_tx.get('card_present') else 'Non' if selected_tx.get('card_present') is False else '—'}")

    with st.expander("Comment le système décide ?"):
        st.markdown(
            """
            Notre détecteur analyse chaque transaction en la comparant à l'historique du client :

            - **Montant invalide** — montant nul, négatif ou manquant
            - **Champs manquants** — informations essentielles absentes (pays, client, etc.)
            - **Montant inhabituel** — dépense très supérieure à l'habitude du client
            - **Incohérence géographique** — deux pays différents en très peu de temps
            - **Fréquence anormale** — trop de transactions en peu de temps
            - **Sans carte physique** — gros montant sans présentation de la carte

            Une transaction est signalée lorsque le score de risque dépasse **0.5**.
            """
        )


def main() -> None:
    st.set_page_config(
        page_title="Détection de fraude — Hackathon INTELO2026",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("Détection de fraude financière")
    st.caption("Hackathon INTELO2026 — interface participant · évaluée par le jury")

    with st.sidebar:
        st.header("Charger des données")
        use_sample = st.toggle("Utiliser le fichier d'exemple", value=True)
        transactions: list[dict] = []

        if use_sample:
            transactions = load_transactions(str(SAMPLE_CSV))
            st.success(f"{len(transactions)} transactions (exemple)")
        else:
            uploaded = st.file_uploader("Importer un CSV", type=["csv"])
            if uploaded:
                tmp = Path(".streamlit_upload.csv")
                tmp.write_bytes(uploaded.getvalue())
                transactions = load_transactions(str(tmp))
                tmp.unlink(missing_ok=True)
                st.success(f"{len(transactions)} transactions importées")

        st.divider()
        st.markdown(
            "**Jury :** évaluez l'ergonomie et la clarté de l'écran principal, "
            "pas seulement le score des tests."
        )

    if not transactions:
        st.info("Chargez des transactions (barre latérale) puis lancez l'analyse.")
        return

    if st.button("Analyser", type="primary"):
        try:
            results = detect_fraud(transactions)
        except NotImplementedError:
            st.error("Implémentez d'abord `detect_fraud` dans `fraud_detection.py`.")
            return
        except Exception as e:
            st.error(f"Erreur : {e}")
            return

        render_interface(transactions, results)


if __name__ == "__main__":
    main()
