import streamlit as st
import pandas as pd
from datetime import datetime

st.set_page_config(
    page_title="5G Threat Detection",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Real-Time 5G Network Threat Detection")
st.caption("IDP Review Prototype | Threat Detection and Automated Response")

st.warning(
    "Prototype: This demonstration uses synthetic network-flow data "
    "and rule-based detection. Mitigation is simulated and does not "
    "block traffic on a real network."
)


def create_sample_data():
    return pd.DataFrame([
        {
            "Flow ID": "F001",
            "Source IP": "10.0.0.12",
            "Destination IP": "10.0.0.20",
            "Protocol": "TCP",
            "Packets": 120,
            "Bytes": 84000,
            "Duration": 12.4,
            "SYN Rate": 8
        },
        {
            "Flow ID": "F002",
            "Source IP": "10.0.0.15",
            "Destination IP": "10.0.0.21",
            "Protocol": "TCP",
            "Packets": 950,
            "Bytes": 120000,
            "Duration": 2.1,
            "SYN Rate": 180
        },
        {
            "Flow ID": "F003",
            "Source IP": "10.0.0.18",
            "Destination IP": "10.0.0.22",
            "Protocol": "UDP",
            "Packets": 720,
            "Bytes": 480000,
            "Duration": 3.0,
            "SYN Rate": 0
        },
        {
            "Flow ID": "F004",
            "Source IP": "10.0.0.12",
            "Destination IP": "10.0.0.25",
            "Protocol": "TCP",
            "Packets": 85,
            "Bytes": 41000,
            "Duration": 18.0,
            "SYN Rate": 4
        },
        {
            "Flow ID": "F005",
            "Source IP": "10.0.0.19",
            "Destination IP": "10.0.0.23",
            "Protocol": "TCP",
            "Packets": 600,
            "Bytes": 76000,
            "Duration": 1.8,
            "SYN Rate": 125
        },
        {
            "Flow ID": "F006",
            "Source IP": "10.0.0.24",
            "Destination IP": "10.0.0.20",
            "Protocol": "UDP",
            "Packets": 70,
            "Bytes": 22000,
            "Duration": 9.5,
            "SYN Rate": 0
        },
        {
            "Flow ID": "F007",
            "Source IP": "10.0.0.27",
            "Destination IP": "10.0.0.22",
            "Protocol": "UDP",
            "Packets": 1100,
            "Bytes": 710000,
            "Duration": 2.5,
            "SYN Rate": 0
        }
    ])


def detect_threat(row):
    if row["SYN Rate"] >= 100:
        return "High", "High SYN rate detected"

    if row["Packets"] >= 800 and row["Duration"] <= 4:
        return "High", "High packet count in short duration"

    if row["Bytes"] >= 400000 and row["Duration"] <= 4:
        return "Medium", "High data volume in short duration"

    return "Low", "No detection rule triggered"


if "flows" not in st.session_state:
    st.session_state.flows = create_sample_data()

if "blocked" not in st.session_state:
    st.session_state.blocked = set()

if "response_log" not in st.session_state:
    st.session_state.response_log = []


df = st.session_state.flows.copy()

results = df.apply(
    detect_threat,
    axis=1,
    result_type="expand"
)

df["Severity"] = results[0]
df["Detection Reason"] = results[1]

df["Status"] = df["Source IP"].apply(
    lambda ip: "Simulated Blocked"
    if ip in st.session_state.blocked
    else "Observed"
)


total_flows = len(df)

high_threats = len(
    df[df["Severity"] == "High"]
)

medium_threats = len(
    df[df["Severity"] == "Medium"]
)

blocked_sources = len(st.session_state.blocked)


st.subheader("Security Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Flows",
    total_flows
)

col2.metric(
    "High-Severity Threats",
    high_threats
)

col3.metric(
    "Medium-Severity Threats",
    medium_threats
)

col4.metric(
    "Simulated Blocked Sources",
    blocked_sources
)


st.divider()

st.subheader("1. Network Traffic Monitoring")

st.write(
    "Monitoring network-flow features including packet count, "
    "data volume, protocol, duration and SYN rate."
)

display_columns = [
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Packets",
    "Bytes",
    "Duration",
    "SYN Rate",
    "Severity",
    "Detection Reason",
    "Status"
]

st.dataframe(
    df[display_columns],
    use_container_width=True,
    hide_index=True
)


st.divider()

st.subheader("2. Threat Detection and Assessment")

suspicious = df[
    df["Severity"].isin(["High", "Medium"])
]

if suspicious.empty:

    st.success("No suspicious flows detected.")

else:

    options = [
        f'{row["Source IP"]} | '
        f'{row["Severity"]} | '
        f'{row["Detection Reason"]}'
        for _, row in suspicious.iterrows()
    ]

    selected = st.selectbox(
        "Select a suspicious source",
        options
    )

    selected_ip = selected.split(" | ")[0]

    col1, col2 = st.columns(2)

    with col1:

        if st.button(
            "Simulate Block Source",
            type="primary",
            use_container_width=True
        ):

            if selected_ip not in st.session_state.blocked:

                st.session_state.blocked.add(
                    selected_ip
                )

                st.session_state.response_log.append({
                    "Time": datetime.now().strftime("%H:%M:%S"),
                    "Action": "SIMULATED BLOCK",
                    "Source IP": selected_ip,
                    "Result": "Removed from simulated post-response view"
                })

            st.rerun()

    with col2:

        if st.button(
            "Reset Simulation",
            use_container_width=True
        ):

            st.session_state.blocked.clear()
            st.session_state.response_log.clear()

            st.rerun()


st.divider()

st.subheader("3. Automated Response Verification")

suspicious_before = df[
    df["Severity"].isin(["High", "Medium"])
]

suspicious_after = suspicious_before[
    ~suspicious_before["Source IP"].isin(
        st.session_state.blocked
    )
]

before_count = len(suspicious_before)
after_count = len(suspicious_after)

if before_count > 0:

    reduction = round(
        ((before_count - after_count) / before_count) * 100,
        1
    )

else:

    reduction = 0


col1, col2, col3 = st.columns(3)

col1.metric(
    "Suspicious Flows Before Response",
    before_count
)

col2.metric(
    "Suspicious Flows Remaining",
    after_count
)

col3.metric(
    "Simulated Reduction",
    f"{reduction}%"
)

st.caption(
    "The reduction represents the demonstration's simulated results. "
    "It does not measure actual network traffic suppression."
)


st.divider()

st.subheader("4. Response Log")

if st.session_state.response_log:

    log_df = pd.DataFrame(
        st.session_state.response_log
    )

    st.dataframe(
        log_df,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No response actions performed yet. "
        "Select a suspicious source and simulate a block."
    )


st.divider()

st.subheader("5. Closed-Loop Security Workflow")

st.markdown("""
**Monitor → Detect → Assess → Respond → Verify → Adapt**

1. **Monitor:** Collect network-flow features.
2. **Detect:** Identify suspicious traffic using detection rules.
3. **Assess:** Assign severity and record the detection reason.
4. **Respond:** Simulate blocking a suspicious source.
5. **Verify:** Recalculate suspicious flows remaining after mitigation.
6. **Adapt:** Refine the detection rules and integrate a trained model
   in a future version.
""")


with st.expander("View Detection Rules"):

    st.markdown("""
    - **High:** SYN rate is at least 100.
    - **High:** Packet count is at least 800 and duration is at most
      4 seconds.
    - **Medium:** Byte count is at least 400,000 and duration is at
      most 4 seconds.
    - **Low:** None of the above rules are triggered.

    These thresholds are illustrative and have not been validated
    against real 5G network traffic.
    """)


st.divider()

st.subheader("6. Export Results")

export_df = df.copy()

st.download_button(
    label="Download Detection Results CSV",
    data=export_df.to_csv(index=False).encode("utf-8"),
    file_name="5g_threat_detection_results.csv",
    mime="text/csv"
)

st.success(
    "Prototype ready. Demonstrate detection, simulated response "
    "and verification to your guide."
)
