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
    "U2": "Client U2 — café en FR (normal), puis JP en 40 min (suspect)",
    "U3": "Client U3 — données incomplètes / montant négatif",
    "U4": "Client U4 — voyage hôtel (FR puis US, 3 jours)",
}


def _risk_label(score: float) -> str:
    if score >= 0.7:
        return "Élevé"
    if score >= 0.4:
        return "Modéré"
    return "Faible"


def _prepare_display_df(df: pd.DataFrame, max_reason_len: int = 50) -> pd.DataFrame:
    """Formate le tableau pour une lecture claire (compatible thème sombre)."""
    out = df.copy()
    out["Statut"] = out["Verdict"].map({
        "Suspecte": "🔴 Suspecte",
        "Conforme": "🟢 Conforme",
    })
    out["Score"] = out["Score"].apply(lambda s: round(float(s), 2))
    out["Raison (résumé)"] = out["Raison"].apply(
        lambda r: (r[:max_reason_len] + "…") if isinstance(r, str) and len(r) > max_reason_len else r
    )
    return out[
        ["ID", "Statut", "Client", "Date", "Montant", "Pays", "Commerçant", "Score", "Raison (résumé)"]
    ]


def _render_transactions_table(df: pd.DataFrame) -> None:
    """Affiche un tableau lisible sans surcouche pandas (évite le contraste illisible)."""
    if df.empty:
        st.info("Aucune transaction à afficher.")
        return
    display_df = _prepare_display_df(df)
    st.dataframe(
        display_df,
        width="stretch",
        hide_index=True,
        column_config={
            "ID": st.column_config.TextColumn("ID", width="small"),
            "Statut": st.column_config.TextColumn("Statut", width="medium"),
            "Client": st.column_config.TextColumn("Client", width="small"),
            "Date": st.column_config.TextColumn("Date", width="medium"),
            "Montant": st.column_config.TextColumn("Montant", width="medium"),
            "Pays": st.column_config.TextColumn("Pays", width="small"),
            "Commerçant": st.column_config.TextColumn("Commerçant", width="medium"),
            "Score": st.column_config.NumberColumn("Score", format="%.2f", width="small"),
            "Raison (résumé)": st.column_config.TextColumn(
                "Raison (résumé)",
                width="large",
                help="Texte abrégé — voir l'onglet Alertes pour l'explication complète",
            ),
        },
    )


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

    with st.container(border=True):
        st.markdown("### 📊 Résultats de l'analyse")
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

        if filtered.empty:
            st.info("Aucune transaction ne correspond aux filtres sélectionnés.")
        else:
            _render_transactions_table(filtered)

        st.caption(
            "🔴 = suspecte · 🟢 = conforme · "
            "Raison complète disponible dans l'onglet **Alertes**"
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
            ["ID", "Client", "Date", "Montant", "Pays", "Commerçant", "Score", "Verdict", "Raison"]
        ]
        _render_transactions_table(client_df)

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

            ### Règles appliquées par le moteur (17 facteurs)

            **Données & montants**
            - Montant nul, négatif ou absent
            - Champs essentiels manquants (pays, client, devise…)
            - Montant très supérieur à l'historique du client (×8)
            - Écart statistique (z-score) par rapport à l'historique
            - Montant rond élevé (ex. 5 000 €) atypique pour le client

            **Comportement & localisation**
            - Deux pays différents en moins de 6 heures
            - Changement de devise rapide (< 6 h)
            - Trop de transactions en 1 heure (≥ 5)
            - Volume total dépensé en 1 heure anormalement élevé

            **Contexte de paiement**
            - Gros montant sans carte physique présente
            - Paiement à distance ≥ 1 000 € (même sans historique)
            - Transaction nocturne (0h–5h) avec montant ≥ 200 €
            - Heure inhabituelle pour le client + montant notable

            **Commerçant & doublons**
            - Commerçant à risque (bijouterie, casino, crypto…)
            - Nom de commerçant suspect (?, unknown, test…)
            - Transaction dupliquée (même montant + commerçant en < 30 min)
            - Premier achat chez un commerçant inconnu, montant élevé

            ### Exemples dans le fichier fourni

            | ID | Client | Ce qu'il illustre |
            |----|--------|-------------------|
            | T-004 | U1 | Montant 4 800 € vs ~50 € habituels |
            | T-010 | U2 | Café en France — transaction conforme |
            | T-011 | U2 | Japon 40 min après — incohérence géographique |
            | T-020 | U3 | Montant négatif (-30 €) |
            | T-021 | U3 | Pays manquant |
            | T-030 / T-031 | U4 | Voyage hôtel légitime (3 jours entre FR et US) |
            """
        )


def _load_transactions_from_sidebar(use_sample: bool, uploaded) -> list[dict]:
    if use_sample:
        return load_transactions(str(SAMPLE_CSV))
    if uploaded is not None:
        tmp = Path(".streamlit_upload.csv")
        tmp.write_bytes(uploaded.getvalue())
        transactions = load_transactions(str(tmp))
        tmp.unlink(missing_ok=True)
        return transactions
    return []


def _run_analysis(transactions: list[dict]) -> None:
    st.session_state.transactions = transactions
    st.session_state.results = detect_fraud(transactions)
    st.session_state.analyzed = True


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
    if "analyzed" not in st.session_state:
        st.session_state.analyzed = False
    if "data_source" not in st.session_state:
        st.session_state.data_source = None

    st.title("🛡️ Détection de fraude financière")
    st.markdown(
        "Analysez un fichier de transactions bancaires et identifiez "
        "celles qui présentent un risque de fraude."
    )

    with st.sidebar:
        st.header("Guide pas à pas")

        _render_step_header(1, "Charger un fichier CSV", True)
        use_sample = st.toggle(
            "Utiliser le fichier d'exemple",
            value=True,
            help="10 transactions de démonstration (clients U1 à U4)",
        )

        uploaded = None
        if not use_sample:
            uploaded = st.file_uploader(
                "Importer votre CSV",
                type=["csv"],
                help="Même format que l'exemple : transaction_id, timestamp, user_id, amount…",
            )

        loaded = _load_transactions_from_sidebar(use_sample, uploaded)
        source_label = "sample" if use_sample else (uploaded.name if uploaded else "none")
        source_key = f"{source_label}_{len(loaded)}"

        if loaded:
            st.success(f"✔ {len(loaded)} transactions chargées")
            if use_sample:
                st.caption("Fichier : `data/sample_transactions.csv`")
        else:
            st.info("Importez un CSV ou activez le fichier d'exemple.")

        if source_key != st.session_state.data_source:
            st.session_state.data_source = source_key
            st.session_state.transactions = loaded
            st.session_state.results = None
            st.session_state.analyzed = False

        st.divider()
        _render_step_header(2, "Lancer l'analyse", st.session_state.analyzed)

        if st.button(
            "▶ Lancer l'analyse",
            type="primary",
            disabled=len(loaded) == 0,
            use_container_width=True,
            key="sidebar_analyze",
        ):
            try:
                _run_analysis(loaded)
                st.rerun()
            except NotImplementedError:
                st.error("La fonction `detect_fraud` n'est pas encore implémentée.")
            except Exception as exc:
                st.error(f"Erreur lors de l'analyse : {exc}")

        if st.session_state.results is not None:
            alert_count = sum(1 for r in st.session_state.results if r["is_suspicious"])
            st.success(f"Analyse terminée — {alert_count} alerte(s)")

        st.divider()
        _render_step_header(3, "Consulter les résultats", st.session_state.analyzed)
        st.caption("Les résultats s'affichent dans la zone principale →")

        if st.button("↺ Réinitialiser", use_container_width=True):
            st.session_state.results = None
            st.session_state.transactions = []
            st.session_state.analyzed = False
            st.session_state.data_source = None
            st.rerun()

    if not loaded:
        st.info("👈 **Commencez par l'étape 1** dans la barre latérale : chargez un fichier CSV.")
        return

    # Analyse automatique du fichier d'exemple pour afficher les résultats immédiatement
    if use_sample and loaded and st.session_state.results is None:
        try:
            _run_analysis(loaded)
            st.rerun()
        except Exception:
            pass

    action_col, status_col = st.columns([1, 3])
    with action_col:
        if st.button(
            "▶ Lancer l'analyse",
            type="primary",
            disabled=len(loaded) == 0,
            key="main_analyze",
            use_container_width=True,
        ):
            try:
                _run_analysis(loaded)
                st.rerun()
            except NotImplementedError:
                st.error("La fonction `detect_fraud` n'est pas encore implémentée.")
            except Exception as exc:
                st.error(f"Erreur lors de l'analyse : {exc}")

    with status_col:
        if st.session_state.results is None:
            st.warning(
                "**Étape 2 —** Cliquez sur **Lancer l'analyse** pour afficher les résultats ci-dessous."
            )
        else:
            alert_count = sum(1 for r in st.session_state.results if r["is_suspicious"])
            st.success(
                f"**Analyse terminée** — {len(st.session_state.results)} transactions · "
                f"**{alert_count} alerte(s)** · résultats affichés ci-dessous"
            )

    if st.session_state.results is None:
        with st.expander("Aperçu des données chargées (avant analyse)", expanded=True):
            st.dataframe(pd.DataFrame(loaded), width="stretch", hide_index=True)
        return

    render_interface(st.session_state.transactions, st.session_state.results)


if __name__ == "__main__":
    main()
