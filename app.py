import streamlit as st
import pandas as pd
import plotly.express as px
import sqlite3
from datetime import datetime
import hashlib

def get_db():
    return sqlite3.connect("joval_portal.db", check_same_thread=False)

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS companies (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE)""")
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT, role TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS risks (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER, title TEXT, description TEXT, category TEXT,
                 likelihood TEXT, impact TEXT, status TEXT, submitted_by TEXT, submitted_date TEXT, risk_score INTEGER, approver_email TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS evidence (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, risk_id INTEGER, company_id INTEGER, file_name TEXT, upload_date TEXT, uploaded_by TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS nist_controls (
                 id TEXT PRIMARY KEY, name TEXT, description TEXT, status TEXT, notes TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS playbook_steps (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, playbook_name TEXT, step TEXT, checked INTEGER, notes TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendors (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, risk_level TEXT, last_assessment TEXT, company_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vendor_questionnaire (
                 vendor_id INTEGER, question TEXT, answer TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS custom_reports (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, filters TEXT, created_by TEXT, created_date TEXT)""")

    companies = ["Joval Wines", "Joval Family Wines", "BNV", "BAM"]
    c.executemany("INSERT OR IGNORE INTO companies (name) VALUES (?)", [(c,) for c in companies])

    hashed = hashlib.sha256("admin123".encode()).hexdigest()
    for i, comp in enumerate(companies, 1):
        c.execute("INSERT OR IGNORE INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)",
                  (f"admin@{comp.lower().replace(' ', '')}.com.au", hashed, "Admin", i))
        c.execute("INSERT OR IGNORE INTO users (email, password, role, company_id) VALUES (?, ?, ?, ?)",
                  (f"approver@{comp.lower().replace(' ', '')}.com.au", hashed, "Approver", i))

    nist_data = [
        ("ID.SC-02", "Supply Chain Risk", "Establish and maintain a supply chain risk management program that identifies, assesses, and mitigates risks associated with third-party suppliers and vendors. Conduct regular risk assessments, require security attestations (e.g., SOC 2), and maintain vendor contracts with security clauses. Review SBOMs and enforce SLAs.", "Partial", "Annual review in progress", 1),
        ("PR.AC-01", "Identity Management", "Implement identity and access management controls including unique user IDs, multi-factor authentication (MFA), and role-based access control (RBAC). Regularly review user access and disable inactive accounts within 24 hours.", "Implemented", "Okta SSO + MFA enforced", 1),
        ("PR.DS-05", "Data Encryption", "Encrypt sensitive data at rest using AES-256 and in transit using TLS 1.3. Implement key management with rotation every 90 days and hardware security modules (HSM) where applicable.", "Implemented", "Azure Key Vault", 1),
        ("DE.CM-01", "Continuous Monitoring", "Deploy SIEM with 24/7 monitoring, log retention for 12 months, and automated alerting. Correlate logs from endpoints, network, and cloud.", "Implemented", "Splunk + CrowdStrike", 1),
        ("RS.MI-01", "Incident Response Plan", "Maintain a documented, tested incident response plan with defined roles, communication protocols, and escalation paths. Conduct tabletop exercises quarterly and full drills annually.", "Partial", "Last test: Q3 2025", 1),
        ("RC.RP-01", "Recovery Planning", "Define RPO < 4 hours and RTO < 8 hours. Maintain offsite backups with air-gapped storage and test restores quarterly.", "Implemented", "Veeam + AWS S3", 1),
        ("PR.MA-01", "Maintenance", "Implement patch management with critical patches applied within 7 days. Use vulnerability scanning and CIS benchmarks.", "Implemented", "Tenable + Ansible", 1),
        ("PR.AT-01", "Awareness Training", "Conduct mandatory security awareness training annually and phishing simulations quarterly. Track completion rates > 95%.", "Implemented", "KnowBe4", 1),
        ("ID.RA-05", "Threat Identification", "Subscribe to threat intelligence feeds and integrate with SIEM. Conduct threat modeling for new systems.", "Partial", "Pilot phase", 1),
        ("PR.IP-01", "Baseline Configuration", "Maintain hardened system images using CIS benchmarks. Use configuration management tools.", "Implemented", "Ansible Tower", 1),
        ("DE.AE-01", "Anomalous Activity", "Deploy UEBA to detect insider threats and lateral movement. Set behavioral baselines.", "Partial", "Pilot with 100 users", 1),
        ("RS.CO-02", "Coordination", "Establish cross-functional incident response team with clear RACI. Conduct joint drills with IT, Legal, PR.", "Implemented", "Quarterly", 1)
    ]
    c.executemany("INSERT OR IGNORE INTO nist_controls VALUES (?, ?, ?, ?, ?, ?)", nist_data)

    playbooks = {
        "Ransomware Response": [
            "Immediately isolate affected systems by disabling network connectivity (Wi-Fi, Ethernet, VPN)",
            "Preserve forensic evidence: capture full memory dump and disk image using FTK Imager",
            "Activate Incident Response Team via Slack #ir-alert and notify CISO within 15 minutes",
            "Engage external legal counsel to determine APRA/ASIC mandatory breach reporting requirements",
            "Restore critical systems from verified, offline backup in isolated environment",
            "Conduct root cause analysis using 5-Whys and update detection rules"
        ],
        "Phishing Attack": [
            "Quarantine malicious email across all mailboxes using Microsoft 365 Defender",
            "Reset passwords for affected users and enforce MFA re-authentication via Okta",
            "Scan all endpoints for malware using CrowdStrike Falcon Complete",
            "Deploy targeted phishing simulation to impacted department within 48 hours",
            "Update phishing filters in Proofpoint and add sender domains to blocklist"
        ],
        "Data Exfiltration": [
            "Block all egress traffic at firewall level except approved IPs and cloud services",
            "Preserve network packet captures (PCAP) for 90 days in secure storage",
            "Initiate digital forensics investigation with external IR firm (Mandiant)",
            "Notify APRA within 72 hours if PII or financial data is confirmed exfiltrated",
            "Implement DLP policy with content inspection and automated blocking"
        ],
        "Insider Threat": [
            "Place suspected employee on immediate administrative leave with pay",
            "Revoke all access tokens, VPN, physical badges, and corporate devices",
            "Preserve HR records, access logs, email, and OneDrive activity for 12 months",
            "Conduct exit interview and full device return inspection with IT",
            "Review and enforce least privilege access policies across all systems"
        ],
        "DDoS Attack": [
            "Activate Cloudflare DDoS mitigation rules and enable 'I'm Under Attack' mode",
            "Engage ISP for upstream traffic scrubbing and BGP rerouting",
            "Monitor traffic patterns in real-time using Datadog and Splunk",
            "Failover to secondary data center with geo-redundant DNS (Route 53)",
            "Conduct post-event capacity planning and load testing"
        ],
        "Physical Breach": [
            "Lock down facility and activate all CCTV recording in high-res mode",
            "Notify law enforcement and preserve scene for physical investigation",
            "Preserve access card logs and video footage for 30 days",
            "Conduct full physical security audit with third-party assessor",
            "Update badge access policies and implement mantraps at server room"
        ],
        "Cloud Misconfiguration": [
            "Revoke public access to exposed S3 bucket and enable 'Block Public Access'",
            "Enable AWS CloudTrail, GuardDuty, and Security Hub across all accounts",
            "Scan all cloud accounts for open ports and weak IAM policies using Prowler",
            "Implement CIS AWS Foundations benchmark via Terraform",
            "Train DevOps team on secure Infrastructure as Code practices"
        ],
        "Zero-Day Exploit": [
            "Deploy virtual patching via Imperva WAF rule to block exploit pattern",
            "Isolate vulnerable systems in containment VLAN with no internet access",
            "Monitor exploit attempts in SIEM with custom YARA signatures",
            "Apply vendor patch within 24 hours of release (emergency change)",
            "Update vulnerability management process with zero-day protocol"
        ],
        "Credential Stuffing": [
            "Enforce MFA for all external-facing applications immediately",
            "Block IPs with >10 failed login attempts per hour using Cloudflare",
            "Reset passwords for any accounts with breached credentials from HaveIBeenPwned",
            "Enable dark web monitoring via Recorded Future for corporate emails",
            "Implement CAPTCHA and bot detection on all login pages"
        ],
        "Supply Chain Attack": [
            "Isolate compromised vendor software from production environment",
            "Scan all systems for IOCs using VirusTotal and custom YARA rules",
            "Notify affected vendors and activate joint response team",
            "Review third-party risk program and update vendor SLAs with security clauses",
            "Update vendor onboarding checklist with SBOM requirement"
        ],
        "Backup Failure": [
            "Restore from secondary offsite backup location (AWS Glacier Deep Archive)",
            "Initiate root cause analysis on primary backup system (Veeam)",
            "Test restored data integrity and application functionality in staging",
            "Update backup configuration and monitoring alerts in PRTG",
            "Conduct full backup verification drill within 7 days"
        ],
        "API Abuse": [
            "Implement rate limiting and API key rotation every 30 days",
            "Audit API logs for anomalous access patterns using Splunk",
            "Revoke compromised API keys and regenerate with new secrets",
            "Enable API gateway with WAF and threat detection (Apigee)",
            "Document API usage policy and monitoring dashboard"
        ]
    }
    for name, steps in playbooks.items():
        for step in steps:
            c.execute("INSERT OR IGNORE INTO playbook_steps (playbook_name, step, checked, notes) VALUES (?, ?, ?, ?)",
                      (name, step, 0, ""))

    risks = [
        (1, "Phishing Campaign Targeting Finance", "Multiple users reported emails requesting wire transfer changes", "DETECT", "High", "High", "Pending Approval", "finance@jovalwines.com.au", "2025-10-01", 9),
        (2, "Unencrypted Laptop Lost in Transit", "Employee reported missing device with customer PII", "PROTECT", "Medium", "High", "Mitigated", "it@jovalfamilywines.com.au", "2025-09-28", 6),
        (3, "Suspicious Login from Russia", "MFA bypass attempt on CEO account at 3 AM", "IDENTIFY", "High", "Medium", "Pending Approval", "ciso@bnv.com.au", "2025-10-03", 6),
        (4, "Vendor Portal Exposed to Public", "Shodan scan revealed open admin interface", "PROTECT", "High", "High", "Open", "security@bam.com.au", "2025-10-02", 9)
    ]
    c.executemany("INSERT OR IGNORE INTO risks (company_id, title, description, category, likelihood, impact, status, submitted_by, submitted_date, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", risks)

    vendors = [(1, "Pallet Co", "Medium", "2025-09-15", 1), (2, "Reefer Tech", "High", "2025-08-20", 1)]
    c.executemany("INSERT OR IGNORE INTO vendors VALUES (?, ?, ?, ?, ?)", vendors)
    questions = [
        (1, "Does your organization have a formal information security program?", ""),
        (1, "Is the program aligned with NIST CSF, ISO 27001, or similar?", ""),
        (1, "Do you conduct regular third-party penetration testing?", ""),
        (2, "Do you encrypt data in transit and at rest?", ""),
        (2, "Are access controls based on least privilege?", "")
    ]
    c.executemany("INSERT OR IGNORE INTO vendor_questionnaire VALUES (?, ?, ?)", questions)

    conn.commit()
    conn.close()

init_db()

st.set_page_config(page_title="Joval Risk Portal", layout="wide")
st.markdown('<div style="background:#1a1a1a;color:white;padding:2rem;text-align:center"><h1>JOVAL WINES</h1><p>Risk Management Portal v15.0</p></div>', unsafe_allow_html=True)

if "user" not in st.session_state:
    with st.sidebar.form("login"):
        st.markdown("### Login")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        if st.form_submit_button("Login"):
            conn = get_db()
            c = conn.cursor()
            hashed = hashlib.sha256(password.encode()).hexdigest()
            c.execute("SELECT * FROM users WHERE email=? AND password=?", (email, hashed))
            user = c.fetchone()
            conn.close()
            if user:
                st.session_state.user = user
                st.rerun()
            else:
                st.error("Invalid")
    st.stop()

user = st.session_state.user
company_id = user[4]
conn = get_db()
c = conn.cursor()
c.execute("SELECT name FROM companies WHERE id=?", (company_id,))
company_name = c.fetchone()[0]

with st.sidebar:
    st.markdown(f"**{user[1].split('@')[0]}** • {user[3]} • {company_name}")
    for p in ["Dashboard", "Log a new Risk", "NIST Controls", "Evidence Vault", "Playbooks", "Reports", "Vendor Risk", "Admin Panel"]:
        if st.button(p): st.session_state.page = p; st.rerun()
page = st.session_state.get("page", "Dashboard")

if page == "Dashboard":
    col1, col2, col3 = st.columns(3)
    with col1: st.button("96% Compliance", key="c1"); st.markdown('<div style="background:white;padding:1rem;border-radius:8px;text-align:center"><h2>96%</h2><p>Compliance</p></div>', unsafe_allow_html=True)
    with col2: st.button("4 Risks", key="c2"); st.markdown('<div style="background:white;padding:1rem;border-radius:8px;text-align:center"><h2>4</h2><p>Risks</p></div>', unsafe_allow_html=True)
    with col3: st.button("42 Files", key="c3"); st.markdown('<div style="background:white;padding:1rem;border-radius:8px;text-align:center"><h2>42</h2><p>Evidence</p></div>', unsafe_allow_html=True)

    for i, comp in enumerate(["Joval Wines", "Joval Family Wines", "BNV", "BAM"]):
        with st.expander(f"RACI Matrix – {comp}"):
            fig = px.imshow(pd.DataFrame([["A","R","C","I"]], columns=["IT","Ops","Sec","Fin"]), color_continuous_scale="Greys")
            st.plotly_chart(fig, key=f"raci_{i}")

    risks = pd.read_sql("SELECT id, title, status, risk_score FROM risks", conn)
    st.markdown("### Active Risks")
    for _, r in risks.iterrows():
        if st.button(f"{r['title']} - {r['status']} (Score: {r['risk_score']})", key=f"risk_{r['id']}"):
            st.session_state.selected_risk = r['id']
            st.session_state.page = "Log a new Risk"
            st.rerun()

elif page == "Log a new Risk":
    if st.session_state.get("selected_risk"):
        c.execute("SELECT * FROM risks WHERE id=?", (st.session_state.selected_risk,))
        risk = c.fetchone()
        with st.form("edit"):
            status = st.selectbox("Status", ["Open", "Pending Approval", "Mitigated", "Closed"], index=["Open", "Pending Approval", "Mitigated", "Closed"].index(risk[7]))
            if st.form_submit_button("Update"):
                c.execute("UPDATE risks SET status=? WHERE id=?", (status, risk[0]))
                conn.commit()
                st.success("Updated")
                st.session_state.selected_risk = None
    else:
        with st.form("new"):
            company_sel = st.selectbox("Company", ["Joval Wines", "Joval Family Wines", "BNV", "BAM"])
            title = st.text_input("Title")
            desc = st.text_area("Description")
            category = st.selectbox("Category", ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"])
            likelihood = st.selectbox("Likelihood", ["Low", "Medium", "High"])
            impact = st.selectbox("Impact", ["Low", "Medium", "High"])
            if st.form_submit_button("Submit"):
                score = {"Low":1, "Medium":2, "High":3}[likelihood] * {"Low":1, "Medium":2, "High":3}[impact]
                c.execute("SELECT id FROM companies WHERE name=?", (company_sel,))
                cid = c.fetchone()[0]
                c.execute("INSERT INTO risks (company_id, title, description, category, likelihood, impact, status, submitted_by, submitted_date, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                          (cid, title, desc, category, likelihood, impact, "Pending Approval", user[1], datetime.now().strftime("%Y-%m-%d"), score))
                conn.commit()
                st.success("Submitted")

st.markdown("© 2025 Joval Wines | v15.0 | GitHub Deployed")
