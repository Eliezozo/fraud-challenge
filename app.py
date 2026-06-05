"""
Interface Streamlit — Hackathon INTELO2026
"""

from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from fraud_detection import detect_fraud, load_transactions

SAMPLE_CSV = Path(__file__).parent / "data" / "sample_transactions.csv"

CLIENT_LABELS = {
    "U1": "Client U1 — habitudes régulières (~50 €)",
    "U2": "Client U2 — déplacement suspect FR → JP",
    "U3": "Client U3 — données incomplètes / montant négatif",
    "U4": "Client U4 — voyage hôtel (FR puis US, 3 jours)",
}


def _risk_label(score: float) -> str:
    if score >= 0.7:
        return "Élevé"
    if score >= 0.4:
        return "Modéré"
    return "Faible"


def _format_amount(amount, currency: str | None) -> str:
    if amount is None:
        return "Montant inconnu"
    cur = currency or ""
    return f"{amount:,.2f} {cur}".replace(",", " ").strip()


def _format_timestamp(ts: str | None) -> str:
    if not ts:
        return "Date inconnue"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%d/%m/%Y à %H:%M")
    except ValueError:
        return ts


def _format_card_present(value) -> str:
    if value is True:
        return "Oui — carte présente"
    if value is False:
        return "Non — paiement à distance"
    return "Non renseigné"


def _verdict_badge(is_suspicious: bool) -> str:
    return "🔴 Suspecte" if is_suspicious else "🟢 Conforme"


def _build_rows(transactions: list[dict], results: list[dict]) -> list[dict]:
    tx_by_id = {t["transaction_id"]: t for t in transactions}
    rows = []
    for r in results:
        tx = tx_by_id.get(r["transaction_id"], {})
        rows.append({
            "ID": r["transaction_id"],
            "Client": tx.get("user_id", "—"),
            "Date": _format_timestamp(tx.get("timestamp")),
            "Montant": _format_amount(tx.get("amount"), tx.get("currency")),
            "Montant brut": tx.get("amount"),
            "Devise": tx.get("currency", "—"),
            "Pays": tx.get("country") or "— (manquant)",
            "Commerçant": tx.get("merchant", "—"),
            "Carte": _format_card_present(tx.get("card_present")),
            "Score": r["fraud_score"],
            "Niveau": _risk_label(r["fraud_score"]),
            "Verdict": "Suspecte" if r["is_suspicious"] else "Conforme",
            "Raison": r["reason"],
            "is_suspicious": r["is_suspicious"],
        })
    return rows


def _render_step_header(step: int, title: str, done: bool) -> None:
    icon = "✅" if done else f"**{step}**"
    st.markdown(f"{icon} &nbsp; {title}")


def _render_transaction_detail(
    selected_id: str,
    transactions: list[dict],
    results: list[dict],
) -> None:
    tx_by_id = {t["transaction_id"]: t for t in transactions}
    result_by_id = {r["transaction_id"]: r for r in results}
    tx = tx_by_id.get(selected_id, {})
    result = result_by_id.get(selected_id, {})

    if not result:
        st.warning("Transaction introuvable.")
        return

    score = result["fraud_score"]
    is_suspicious = result["is_suspicious"]

    st.markdown(f"### {selected_id} — {_verdict_badge(is_suspicious)}")
    st.progress(min(max(score, 0.0), 1.0), text=f"Score de risque : {score:.2f} / 1.00 ({_risk_label(score)})")

    if is_suspicious:
        st.error(f"**Pourquoi cette alerte ?**  \n{result['reason']}")
    else:
        st.success(f"**Verdict**  \n{result['reason']}")

    st.markdown("#### Données de la transaction")
    info = [
        ("Client", tx.get("user_id", "—")),
        ("Date et heure", _format_timestamp(tx.get("timestamp"))),
        ("Montant", _format_amount(tx.get("amount"), tx.get("currency"))),
        ("Commerçant", tx.get("merchant", "—")),
        ("Pays", tx.get("country") or "— (manquant)"),
        ("Carte physique", _format_card_present(tx.get("card_present"))),
    ]
    for label, value in info:
        c1, c2 = st.columns([1, 2])
        c1.markdown(f"**{label}**")
        c2.write(value)

    client = tx.get("user_id")
    if client in CLIENT_LABELS:
        st.caption(f"Contexte client : {CLIENT_LABELS[client]}")


def render_interface(transactions: list[dict], results: list[dict]) -> None:
    rows = _build_rows(transactions, results)
    df = pd.DataFrame(rows)
    alerts = [r for r in rows if r["is_suspicious"]]
    conformes = len(rows) - len(alerts)
    avg_score = sum(r["Score"] for r in rows) / len(rows) if rows else 0.0

    st.markdown("---")
    st.markdown("### Résultats de l'analyse")
    st.caption(
        f"{len(rows)} transactions analysées · "
        f"{len(alerts)} alerte(s) · {conformes} transaction(s) conforme(s)"
    )

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total", len(rows), help="Nombre de lignes analysées dans le fichier CSV")
    m2.metric("Alertes", len(alerts), help="Transactions signalées comme suspectes (score ≥ 0,5)")
    m3.metric("Conformes", conformes, help="Transactions sans anomalie détectée")
    m4.metric("Risque moyen", f"{avg_score:.2f}", help="Score moyen sur l'ensemble du lot (0 = sûr, 1 = très risqué)")

    tab_overview, tab_alerts, tab_clients, tab_help = st.tabs([
        "📋 Vue d'ensemble",
        "🚨 Alertes",
        "👤 Par client",
        "❓ Comment lire cette page",
    ])

    with tab_overview:
        st.markdown(
            "**Utilisez les filtres ci-dessous** pour affiner le tableau, "
            "puis **cliquez sur une alerte** dans l'onglet « Alertes » pour voir l'explication détaillée."
        )

        f1, f2, f3 = st.columns(3)
        with f1:
            verdict_filter = st.radio(
                "Afficher",
                ["Toutes les transactions", "Uniquement les suspectes", "Uniquement les conformes"],
                horizontal=False,
                help="Filtre principal : limite les lignes visibles dans le tableau",
            )
        with f2:
            users = sorted({t.get("user_id") for t in transactions if t.get("user_id")})
            user_filter = st.selectbox(
                "Client",
                ["Tous les clients"] + users,
                help="Filtrer par identifiant client (colonne user_id du CSV)",
            )
        with f3:
            risk_filter = st.selectbox(
                "Niveau de risque",
                ["Tous les niveaux", "Élevé", "Modéré", "Faible"],
                help="Élevé ≥ 0,7 · Modéré ≥ 0,4 · Faible < 0,4",
            )

        filtered = df.copy()
        if verdict_filter == "Uniquement les suspectes":
            filtered = filtered[filtered["Verdict"] == "Suspecte"]
        elif verdict_filter == "Uniquement les conformes":
            filtered = filtered[filtered["Verdict"] == "Conforme"]
        if user_filter != "Tous les clients":
            filtered = filtered[filtered["Client"] == user_filter]
        if risk_filter != "Tous les niveaux":
            filtered = filtered[filtered["Niveau"] == risk_filter]

        st.caption(f"**{len(filtered)}** ligne(s) affichée(s) sur {len(df)}")

        display_cols = ["ID", "Client", "Date", "Montant", "Pays", "Commerçant", "Score", "Verdict", "Raison"]

        def _style_row(row):
            bg = "#fdecea" if row["Verdict"] == "Suspecte" else "#eafaf1"
            return [f"background-color: {bg}"] * len(row)

        st.dataframe(
            filtered[display_cols].style.apply(_style_row, axis=1),
            use_container_width=True,
            hide_index=True,
        )

        st.markdown(
            "🟥 **Rouge** = transaction suspecte · "
            "🟩 **Vert** = transaction conforme · "
            "Colonne **Raison** = explication en une phrase"
        )

    with tab_alerts:
        if not alerts:
            st.success("Aucune alerte détectée dans ce lot de transactions.")
        else:
            st.markdown(
                f"**{len(alerts)} transaction(s) à examiner.** "
                "Sélectionnez une alerte dans la liste pour afficher son explication complète."
            )

            alert_ids = [r["ID"] for r in alerts]
            selected_id = st.radio(
                "Choisir une alerte à inspecter",
                alert_ids,
                format_func=lambda tid: next(
                    f"{tid} — {r['Raison'][:60]}{'…' if len(r['Raison']) > 60 else ''}"
                    for r in alerts if r["ID"] == tid
                ),
                label_visibility="collapsed",
            )
            st.divider()
            _render_transaction_detail(selected_id, transactions, results)

    with tab_clients:
        st.markdown(
            "Vue regroupée par **client** (`user_id` dans le CSV). "
            "Chaque client affiche son historique et le nombre d'alertes le concernant."
        )
        users = sorted({t.get("user_id") for t in transactions if t.get("user_id")})
        selected_client = st.selectbox(
            "Sélectionner un client",
            users,
            format_func=lambda u: f"{u} — {CLIENT_LABELS.get(u, 'Profil non documenté')}",
        )

        client_rows = [r for r in rows if r["Client"] == selected_client]
        client_alerts = sum(1 for r in client_rows if r["is_suspicious"])

        c1, c2 = st.columns(2)
        c1.metric("Transactions du client", len(client_rows))
        c2.metric("Alertes sur ce client", client_alerts)

        if selected_client in CLIENT_LABELS:
            st.info(CLIENT_LABELS[selected_client])

        client_df = pd.DataFrame(client_rows)[
            ["ID", "Date", "Montant", "Pays", "Commerçant", "Score", "Verdict", "Raison"]
        ]
        st.dataframe(client_df, use_container_width=True, hide_index=True)

        client_alert_ids = [r["ID"] for r in client_rows if r["is_suspicious"]]
        if client_alert_ids:
            st.markdown("#### Détail d'une alerte de ce client")
            detail_id = st.selectbox(
                "Transaction à examiner",
                client_alert_ids,
                key=f"client_detail_{selected_client}",
            )
            _render_transaction_detail(detail_id, transactions, results)
        elif client_rows:
            st.success("Toutes les transactions de ce client sont conformes.")

    with tab_help:
        st.markdown(
            """
            ### Comment utiliser cette interface

            1. **Barre latérale (gauche)** — Choisissez le fichier CSV (exemple ou import).
            2. **Bouton « Lancer l'analyse »** — Le moteur examine toutes les transactions d'un coup.
            3. **Onglets (ci-dessus)** — Naviguez entre la vue globale, les alertes et la vue par client.

            ### Légende des scores

            | Score | Niveau | Signification |
            |-------|--------|---------------|
            | 0,00 – 0,39 | Faible | Comportement normal |
            | 0,40 – 0,69 | Modéré | Signal à surveiller |
            | 0,70 – 1,00 | Élevé | Forte probabilité de fraude |

            Une transaction est **signalée** lorsque son score atteint **0,5** ou plus.

            ### Règles appliquées par le moteur

            - **Montant invalide** — montant nul, négatif ou absent
            - **Données manquantes** — pays ou informations essentielles absentes
            - **Montant inhabituel** — dépense très supérieure à l'historique du client
            - **Incohérence géographique** — deux pays différents en moins de 6 heures
            - **Fréquence anormale** — trop de transactions en très peu de temps
            - **Paiement à distance** — gros montant sans carte physique

            ### Exemples dans le fichier fourni

            | ID | Client | Ce qu'il illustre |
            |----|--------|-------------------|
            | T-004 | U1 | Montant 4 800 € vs ~50 € habituels |
            | T-010 / T-011 | U2 | France puis Japon en 40 minutes |
            | T-020 | U3 | Montant négatif (-30 €) |
            | T-021 | U3 | Pays manquant |
            | T-030 / T-031 | U4 | Voyage hôtel légitime (3 jours entre FR et US) |
            """
        )


def main() -> None:
    st.set_page_config(
        page_title="Détection de fraude — Hackathon INTELO2026",
        page_icon="🛡️",
        layout="wide",
    )

    if "results" not in st.session_state:
        st.session_state.results = None
    if "transactions" not in st.session_state:
        st.session_state.transactions = []

    st.title("🛡️ Détection de fraude financière")
    st.markdown(
        "Analysez un fichier de transactions bancaires et identifiez "
        "celles qui présentent un risque de fraude."
    )

    with st.sidebar:
        st.header("Guide pas à pas")

        _render_step_header(1, "Charger un fichier CSV", bool(st.session_state.transactions))
        use_sample = st.toggle(
            "Utiliser le fichier d'exemple",
            value=True,
            help="10 transactions de démonstration (clients U1 à U4)",
        )

        loaded: list[dict] = []
        if use_sample:
            loaded = load_transactions(str(SAMPLE_CSV))
            st.success(f"✔ {len(loaded)} transactions chargées")
            st.caption("Fichier : `data/sample_transactions.csv`")
        else:
            uploaded = st.file_uploader(
                "Importer votre CSV",
                type=["csv"],
                help="Même format que l'exemple : transaction_id, timestamp, user_id, amount…",
            )
            if uploaded:
                tmp = Path(".streamlit_upload.csv")
                tmp.write_bytes(uploaded.getvalue())
                loaded = load_transactions(str(tmp))
                tmp.unlink(missing_ok=True)
                st.success(f"✔ {len(loaded)} transactions importées")

        st.divider()
        _render_step_header(2, "Lancer l'analyse", st.session_state.results is not None)

        analyze_disabled = len(loaded) == 0
        if analyze_disabled:
            st.info("Chargez d'abord un fichier CSV (étape 1).")

        analyze_clicked = st.button(
            "▶ Lancer l'analyse",
            type="primary",
            disabled=analyze_disabled,
            use_container_width=True,
            help="Exécute detect_fraud() sur l'ensemble des transactions chargées",
        )

        if analyze_clicked and loaded:
            try:
                st.session_state.transactions = loaded
                st.session_state.results = detect_fraud(loaded)
            except NotImplementedError:
                st.error("La fonction `detect_fraud` n'est pas encore implémentée.")
            except Exception as exc:
                st.error(f"Erreur lors de l'analyse : {exc}")

        if st.session_state.results is not None:
            alert_count = sum(1 for r in st.session_state.results if r["is_suspicious"])
            st.success(f"Analyse terminée — {alert_count} alerte(s)")

        st.divider()
        _render_step_header(
            3,
            "Explorer les résultats (onglets)",
            st.session_state.results is not None,
        )
        st.caption("Utilisez les onglets dans la zone principale après l'analyse.")

        if st.button("↺ Réinitialiser", use_container_width=True):
            st.session_state.results = None
            st.session_state.transactions = []
            st.rerun()

    if not st.session_state.transactions and not loaded:
        st.info("👈 **Commencez par l'étape 1** dans la barre latérale : chargez un fichier CSV.")
        st.markdown(
            """
            #### À quoi sert cette application ?

            Cet outil lit des transactions bancaires (format CSV) et signale celles
            qui semblent suspectes : montant anormal, pays incohérent, données manquantes, etc.

            **Pour démarrer :** activez le fichier d'exemple dans la barre latérale,
            puis cliquez sur **Lancer l'analyse**.
            """
        )
        return

    if st.session_state.results is None:
        st.warning(
            "Fichier chargé. Cliquez sur **▶ Lancer l'analyse** dans la barre latérale "
            "pour afficher les résultats."
        )
        with st.expander("Aperçu des données chargées (avant analyse)"):
            preview = loaded if loaded else st.session_state.transactions
            st.dataframe(pd.DataFrame(preview), use_container_width=True, hide_index=True)
        return

    render_interface(st.session_state.transactions, st.session_state.results)


if __name__ == "__main__":
    main()
