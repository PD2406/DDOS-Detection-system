# DDOS-Detection-system
# 🚀 DDoS Detection and Mitigation System using Machine Learning

## 📌 Project Overview
This project implements an **intelligent DDoS detection and mitigation system** using **Machine Learning and Deep Learning techniques**.  
The system monitors network traffic in real time, analyzes patterns, detects malicious activities such as **SYN Flood, UDP Flood, HTTP Flood**, and triggers mitigation actions.

The goal is to enhance **network security, availability, and resilience** against Distributed Denial of Service (DDoS) attacks.

---

## 🎯 Objectives
- Detect DDoS attacks in real-time
- Classify normal vs malicious traffic
- Support multiple attack types
- Improve detection accuracy using ML models
- Provide live monitoring through a dashboard
- Enable automated mitigation actions

---

## 🛠️ Technologies Used
- **Programming Language:** Python  
- **Machine Learning:** Random Forest, XGBoost  
- **Deep Learning:** LSTM (for traffic sequence analysis)  
- **Frameworks & Libraries:**  
  - Scikit-learn  
  - NumPy  
  - Pandas  
  - PyTorch / TensorFlow (if applicable)  
- **Backend:** FastAPI  
- **Dashboard:** Streamlit  
- **Environment:** Virtual Environment (venv)

---
## ⚙️ How the System Works
1. **Traffic Monitoring** – Captures live or simulated network traffic  
2. **Feature Extraction** – Calculates metrics like packets/sec, bytes/sec  
3. **ML Analysis** – Random Forest & XGBoost classify traffic  
4. **LSTM Analysis** – Detects time-based attack patterns  
5. **Decision Engine** – Confirms attack confidence  
6. **Mitigation** – Blocks IP / limits traffic  
7. **Dashboard** – Displays real-time status and alerts  

---

## 🚨 Attack Types Detected
- SYN Flood
- UDP Flood
- HTTP Flood
- ICMP Flood
- Traffic Anomalies
