# NetSentinel
is a modular Python project that captures, parses, and analyzes network traffic to detect suspicious activity using custom security logic. This tool is designed to simulate real-world SOC responsibilities and demonstrate technical proficiency in packet-level traffic analysis and network threat detection.

---

## Project Objectives

This project is built to:

- Develop and demonstrate a deep understanding of OSI Layers 2–4.
- Apply practical security detection logic to raw packet data.
- Automate core SOC functions such as port scan detection and known-malicious IP alerting.
- Integrate real-time or batch traffic analysis using modern packet manipulation libraries.
- Lay the foundation for future dashboard development using Flask or other frameworks.'


### Key Questions (For the Analyst Mindset)
	1.	What would I want a tool to instantly tell me during an incident—without needing to open Wireshark or grep logs for 20 minutes?
Think: Could NetSentinel surface obvious IOCs, highlight weird DNS, or tell me if someone’s doing a slow port scan right now?
	2.	How can I reduce alert fatigue by only triggering when traffic breaks known baselines or hits real intel feeds?
Think: Are we building something that cuts through the noise and says, “Hey, this matters”?
	3.	Could I hand this tool off to a Tier 1 analyst and expect them to catch something important without extra training?
Think: Is it simple enough to use—but powerful enough to actually help?
	4.	If I were defending a small network alone, what kind of automated insights would give me peace of mind?
Think: Can this act like a basic guardian—logging and alerting even while I’m off shift?

**For Recruiters and Mentors:**
- Does this project demonstrate initiative, technical depth, and security awareness?
- Is the code modular, testable, documented, and reflective of production-ready thinking?

---

### Libraries

| Library    | Purpose                                                           |
| ---------- | ----------------------------------------------------------------- |
| `scapy`    | For live packet capture, protocol dissection, and packet crafting |
| `pyshark`  | For parsing large `.pcap` files using the Wireshark engine        |
| `flask`    | (Optional) Web UI for alert viewing and traffic dashboards        |
| `dotenv`   | Securely manage configuration settings and sensitive variables    |
| `requests` | Retrieve threat intel feeds or APIs (optional)                    |
