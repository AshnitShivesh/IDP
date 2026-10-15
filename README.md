PROJECT TITLE
Real-Time 5G Network Threat Detection and Automated Security Response System

PROJECT DESCRIPTION
This prototype demonstrates network-flow monitoring, rule-based threat
detection, threat severity assessment, simulated mitigation, and
post-response verification.

TECHNOLOGIES
Python
Streamlit
Pandas

REQUIREMENTS
Python 3
Internet connection for initial package installation

INSTALLATION INSTRUCTIONS

1. Extract all project files into one folder.

2. Open PowerShell inside the project folder.

3. Create a virtual environment:

py -m venv .venv

4. Activate the virtual environment:

.\.venv\Scripts\Activate.ps1

5. Install the required packages:

python -m pip install --upgrade pip

pip install -r requirements.txt

6. Run the application:

python -m streamlit run app.py

7. Open the following address in your browser if it does not open
automatically:

http://localhost:8501

DEMONSTRATION STEPS

1. Display the network-flow records.
2. Explain the detection severity and reasons.
3. Select a suspicious source IP address.
4. Click Simulate Block Source.
5. Show the response log.
6. Compare suspicious flows before and after the simulated response.
7. Download the detection results CSV.
8. Click Reset Simulation to repeat the demonstration.

CURRENT LIMITATIONS

The prototype uses synthetic network-flow records.
Detection is rule-based, not machine learning.
No real 5G network is connected.
No actual network traffic is blocked.
The displayed reduction is simulated.

FUTURE ENHANCEMENTS

1. Integrate a labelled network intrusion dataset.
2. Train and evaluate a machine learning classifier.
3. Compare detection-only, static-response and closed-loop approaches.
4. Evaluate detection performance and response latency.
5. Test mitigation in an isolated network testbed.
6. Explore integration with a 5G-oriented traffic monitoring system.
