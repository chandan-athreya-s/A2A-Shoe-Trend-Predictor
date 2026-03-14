import os, json
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from dotenv import load_dotenv
from serpapi import GoogleSearch
from openai import AzureOpenAI
from auth import show_auth_page, logout   

load_dotenv()
client = AzureOpenAI(
    api_version=os.getenv("AZURE_OPENAI_API_VERSION"),
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    api_key=os.getenv("AZURE_OPENAI_API_KEY"),
)
DEPLOYMENT  = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME")
SERPAPI_KEY = os.getenv("SERPAPI_KEY")

SHOES = ["Nike Air Force 1", "Adidas Stan Smith", "New Balance 574",
         "Converse Chuck Taylor", "Puma Suede Classic"]


AGENTS = {
    "orchestrator": "You are the Orchestrator. Given shoe trend data, output ONLY JSON: "
                    '{"trend_task":"...","forecast_task":"..."} with a 1-sentence task per agent.',
    "trend":        "You are TrendAgent. Analyse the sneaker search trend data statistically. "
                    "Highlight peaks, dips, and momentum in 2 short paragraphs.",
    "forecast":     "You are ForecastAgent. Predict next-quarter sales outlook for both shoes "
                    "based on the trend data. Be directional (e.g. 'up ~10%'). 2 short paragraphs.",
    "synthesizer":  "You are the Synthesizer. Merge TrendAgent and ForecastAgent outputs into "
                    "a 2-paragraph final brief: (1) trend summary, (2) outlook & recommendation.",
}

def call_agent(role: str, message: str) -> str:
    res = client.chat.completions.create(
        model=DEPLOYMENT,
        messages=[{"role": "system", "content": AGENTS[role]},
                  {"role": "user",   "content": message}],
        max_tokens=350, temperature=0.4,
    )
    return res.choices[0].message.content.strip()

def fetch_trend(keyword: str) -> pd.DataFrame:
    data = GoogleSearch({"engine": "google_trends", "q": keyword,
                         "data_type": "TIMESERIES", "date": "today 12-m",
                         "api_key": SERPAPI_KEY}).get_dict()
    rows = [{"date": p["date"], "value": p["values"][0].get("extracted_value", 0)}
            for p in data.get("interest_over_time", {}).get("timeline_data", [])]
    return pd.DataFrame(rows)

def build_chart(shoe_a, df_a, shoe_b, df_b) -> go.Figure:
    fig = go.Figure()
    for shoe, df, color, fill in [(shoe_a, df_a, "#4F8EF7", "rgba(79,142,247,0.12)"),
                                   (shoe_b, df_b, "#F76A4F", "rgba(247,106,79,0.12)")]:
        vals = df["value"].astype(int)
        fig.add_trace(go.Scatter(x=df["date"], y=vals, name=shoe,
                                 mode="lines", line=dict(color=color, width=2.5),
                                 fill="tozeroy", fillcolor=fill,
                                 hovertemplate="%{x} — <b>%{y}</b><extra>" + shoe + "</extra>"))
        pk = vals.idxmax()
        fig.add_trace(go.Scatter(x=[df.loc[pk, "date"]], y=[vals[pk]], mode="markers+text",
                                 marker=dict(color=color, size=11, symbol="star"),
                                 text=[f" Peak {vals[pk]}"], textposition="middle right",
                                 textfont=dict(color=color), showlegend=False, hoverinfo="skip"))
    fig.update_layout(hovermode="x unified", height=380,
                      plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                      xaxis=dict(showgrid=False, tickangle=-40, tickfont=dict(size=10)),
                      yaxis=dict(title="Interest (0–100)", gridcolor="rgba(180,180,180,0.15)"),
                      legend=dict(orientation="h", y=1.05),
                      margin=dict(l=50, r=20, t=40, b=50))
    return fig

def run_pipeline(shoe_a, df_a, shoe_b, df_b):
    summary = (f"{shoe_a}: avg={df_a['value'].mean():.1f}, peak={df_a['value'].max()}, "
               f"series={df_a['value'].astype(int).tolist()}\n"
               f"{shoe_b}: avg={df_b['value'].mean():.1f}, peak={df_b['value'].max()}, "
               f"series={df_b['value'].astype(int).tolist()}")
    raw = call_agent("orchestrator", summary)
    try:    tasks = json.loads(raw.strip("```json").strip("```"))
    except: tasks = {"trend_task": f"Analyse trends for {shoe_a} vs {shoe_b}.",
                     "forecast_task": f"Forecast {shoe_a} vs {shoe_b}."}
    log = [("Orchestrator", f"Delegating — TrendAgent: *{tasks['trend_task']}* | "
                               f"ForecastAgent: *{tasks['forecast_task']}*")]
    trend_out    = call_agent("trend",    f"{tasks['trend_task']}\n\n{summary}")
    forecast_out = call_agent("forecast", f"{tasks['forecast_task']}\n\n{summary}")
    log += [("TrendAgent", trend_out), ("🔮 ForecastAgent", forecast_out)]
    brief = call_agent("synthesizer",
                       f"TrendAgent:\n{trend_out}\n\nForecastAgent:\n{forecast_out}")
    log.append(("Synthesizer", brief))
    return log, brief

# ── App entry point ────────────────────────────────────────────────────────────
st.set_page_config(page_title="Shoe Popularity Predictor", page_icon="👟", layout="wide")

# Gate: show auth page until logged in
if not show_auth_page():
    st.stop()

# ── Main app (only reached after login) ───────────────────────────────────────
st.title("Shoe Popularity Predictor")
st.caption(f"Logged in as **{st.session_state['username']}**")

if st.button("Logout", type="secondary"):
    logout()                            # ← deletes session token from DuckDB

st.divider()

col1, col2 = st.columns(2)
shoe_a = col1.selectbox("Shoe 1", SHOES)
shoe_b = col2.selectbox("Shoe 2", [s for s in SHOES if s != shoe_a])

if st.button("Analyze"):
    with st.spinner("Fetching trend data…"):
        df_a, df_b = fetch_trend(shoe_a), fetch_trend(shoe_b)
    if df_a.empty or df_b.empty:
        st.error("No data returned. Check your SerpAPI key."); st.stop()

    st.plotly_chart(build_chart(shoe_a, df_a, shoe_b, df_b), use_container_width=True)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric(f"{shoe_a.split()[0]} avg",  int(df_a["value"].mean()))
    c2.metric(f"{shoe_b.split()[0]} avg",  int(df_b["value"].mean()))
    c3.metric(f"{shoe_a.split()[0]} peak", int(df_a["value"].max()))
    c4.metric(f"{shoe_b.split()[0]} peak", int(df_b["value"].max()))
    st.divider()

    st.subheader("A2A Agent Pipeline")
    st.caption("Orchestrator → [TrendAgent · ForecastAgent] → Synthesizer")
    with st.spinner("Running agents…"):
        log, brief = run_pipeline(shoe_a, df_a, shoe_b, df_b)

    with st.expander("Agent Message Log", expanded=True):
        for agent, msg in log:
            st.markdown(f"**{agent}**"); st.markdown(msg); st.markdown("---")

    st.subheader("Final Brief"); st.info(brief)