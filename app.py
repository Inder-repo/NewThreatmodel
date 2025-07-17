import streamlit as st
import base64
import json
import re

# Streamlit UI
st.title("Threat Modeling Application")

# Initialize session state
if 'step' not in st.session_state:
    st.session_state.step = 1
if 'text_input' not in st.session_state:
    st.session_state.text_input = ""
if 'diagram' not in st.session_state:
    st.session_state.diagram = None
if 'data_flows' not in st.session_state:
    st.session_state.data_flows = []
if 'trust_boundaries' not in st.session_state:
    st.session_state.trust_boundaries = []
if 'threat_model' not in st.session_state:
    st.session_state.threat_model = None
if 'error' not in st.session_state:
    st.session_state.error = ""

def analyze_threats():
    """Perform comprehensive STRIDE-based threat analysis with detailed mitigations."""
    threats = []

    # Helper function to add threats
    def add_threat(threat_type, description, stride, mitigation, asvs, samm):
        threats.append({
            "type": threat_type,
            "description": description,
            "stride": stride,
            "mitigation": mitigation,
            "asvs": asvs,
            "samm": samm
        })

    # Analyze system description for common components and vulnerabilities
    text_input = st.session_state.text_input.lower()
    components = {
        "web": "web application" in text_input or "website" in text_input,
        "api": "api" in text_input or "endpoint" in text_input,
        "database": "database" in text_input or "db" in text_input,
        "cloud": "cloud" in text_input or "aws" in text_input or "azure" in text_input,
        "authentication": "login" in text_input or "password" in text_input or "credential" in text_input,
        "third_party": "third party" in text_input or "external" in text_input
    }

    # STRIDE: Spoofing
    if components["authentication"] or components["api"]:
        add_threat(
            "Spoofing",
            "Attackers may impersonate legitimate users or services to gain unauthorized access.",
            "Spoofing",
            "Implement multi-factor authentication (MFA), use strong session management, and validate API tokens with short expiration times.",
            "V2.1.1 - Verify strong authentication controls; V2.7.1 - Verify session management.",
            "Threat Assessment Level 1 - Identify authentication risks; Governance Level 2 - Define authentication policies."
        )

    # STRIDE: Tampering
    if components["database"] or components["web"]:
        add_threat(
            "Tampering",
            "Data integrity may be compromised due to insufficient input validation or lack of integrity checks.",
            "Tampering",
            "Implement strict input validation, use parameterized queries for databases, and apply cryptographic hashing (e.g., SHA-256) for data integrity.",
            "V5.1.3 - Verify input validation; V5.3.4 - Verify secure database queries.",
            "Secure Architecture Level 1 - Define security requirements; Design Level 2 - Implement integrity controls."
        )

    # STRIDE: Repudiation
    if components["authentication"] or components["web"]:
        add_threat(
            "Repudiation",
            "Actions may not be traceable due to insufficient logging or audit trails.",
            "Repudiation",
            "Implement comprehensive logging of all security-relevant events, ensure logs are tamper-proof, and enable centralized log monitoring.",
            "V7.1.1 - Verify logging controls; V7.2.1 - Verify log integrity.",
            "Security Operations Level 2 - Enable audit logging; Incident Management Level 2 - Monitor logs."
        )

    # STRIDE: Information Disclosure
    if components["database"] or components["cloud"]:
        add_threat(
            "Information Disclosure",
            "Sensitive data may be exposed due to improper access controls or unencrypted storage/transmission.",
            "Information Disclosure",
            "Encrypt sensitive data at rest (e.g., AES-256) and in transit (e.g., TLS 1.3), enforce least privilege access controls, and use secure key management.",
            "V4.1.3 - Verify access controls; V9.1.1 - Verify secure communication.",
            "Secure Architecture Level 2 - Standardize security controls; Implementation Level 2 - Secure data handling."
        )

    # STRIDE: Denial of Service
    if components["api"] or components["web"]:
        add_threat(
            "Denial of Service",
            "System availability may be impacted by resource exhaustion or flooding attacks.",
            "Denial of Service",
            "Implement rate limiting, use Web Application Firewalls (WAF), enable auto-scaling, and deploy DDoS protection (e.g., AWS Shield).",
            "V1.10.1 - Verify anti-DoS controls; V13.1.1 - Verify API security.",
            "Incident Management Level 2 - Implement proactive monitoring; Operations Level 2 - Ensure availability."
        )

    # STRIDE: Elevation of Privilege
    if components["third_party"] or components["cloud"]:
        add_threat(
            "Elevation of Privilege",
            "Attackers may gain unauthorized privileges due to misconfigured roles or third-party vulnerabilities.",
            "Elevation of Privilege",
            "Enforce least privilege, implement role-based access control (RBAC), regularly audit third-party components, and apply security patches promptly.",
            "V4.2.1 - Verify RBAC; V14.2.3 - Verify dependency management.",
            "Secure Architecture Level 2 - Implement RBAC; Implementation Level 2 - Manage dependencies."
        )

    # Analyze data flows
    for flow in st.session_state.data_flows:
        data_type = flow.get('dataType', '').lower()
        source = flow.get('source', '').lower()
        destination = flow.get('destination', '').lower()

        # Spoofing in data flows
        if 'user' in source or 'client' in source:
            add_threat(
                "Spoofing",
                f"Unauthorized access in data flow from {source} to {destination}.",
                "Spoofing",
                "Validate source identity with strong authentication (e.g., OAuth 2.0, JWT) and ensure secure session handling.",
                "V2.1.2 - Verify identity validation; V2.7.3 - Verify session binding.",
                "Threat Assessment Level 1 - Identify authentication risks; Governance Level 2 - Enforce identity policies."
            )

        # Tampering in data flows
        add_threat(
            "Tampering",
            f"Data integrity risk in flow from {source} to {destination}.",
            "Tampering",
            "Use digital signatures or HMAC for data integrity, and validate all inputs at the destination.",
            "V5.1.4 - Verify data integrity; V5.2.2 - Verify input sanitization.",
            "Design Level 2 - Implement integrity controls; Verification Level 1 - Validate inputs."
        )

        # Information Disclosure in sensitive data flows
        if 'pii' in data_type or 'sensitive' in data_type or 'confidential' in data_type:
            add_threat(
                "Information Disclosure",
                f"Sensitive data ({data_type}) exposed in flow from {source} to {destination}.",
                "Information Disclosure",
                "Encrypt data in transit with TLS 1.3, mask sensitive data in logs, and restrict access to authorized entities only.",
                "V9.1.2 - Verify encryption in transit; V4.1.4 - Verify access restrictions.",
                "Implementation Level 2 - Secure data handling; Operations Level 2 - Protect sensitive data."
            )

        # Denial of Service in data flows
        if 'api' in destination or 'server' in destination:
            add_threat(
                "Denial of Service",
                f"Potential DoS attack targeting {destination} in data flow.",
                "Denial of Service",
                "Implement rate limiting, use circuit breakers, and monitor traffic patterns for anomalies.",
                "V1.10.2 - Verify rate limiting; V13.1.2 - Verify API resilience.",
                "Incident Management Level 2 - Monitor for DoS; Operations Level 2 - Ensure availability."
            )

    # Analyze trust boundaries
    for boundary in st.session_state.trust_boundaries:
        name = boundary.get('name', '').lower()
        description = boundary.get('description', '').lower()

        # Spoofing across trust boundaries
        if 'boundary' in name or 'dmz' in name:
            add_threat(
                "Spoofing",
                f"Cross-boundary spoofing possible in {name}.",
                "Spoofing",
                "Enforce strict boundary authentication (e.g., mutual TLS, API gateway authentication) and validate all cross-boundary requests.",
                "V2.1.3 - Verify boundary authentication; V13.2.1 - Verify API security.",
                "Threat Assessment Level 2 - Model boundary risks; Governance Level 2 - Define boundary policies."
            )

        # Tampering within trust boundaries
        if 'database' in name or 'server' in name:
            add_threat(
                "Tampering",
                f"Data tampering within {name} due to weak internal controls.",
                "Tampering",
                "Implement integrity checks (e.g., checksums), use secure coding practices, and validate data within the boundary.",
                "V5.1.3 - Verify input validation; V5.3.5 - Verify secure coding.",
                "Design Level 2 - Implement integrity controls; Verification Level 2 - Validate boundary controls."
            )

        # Elevation of Privilege within trust boundaries
        add_threat(
            "Elevation of Privilege",
            f"Privilege escalation within {name} due to misconfigured access controls.",
            "Elevation of Privilege",
            "Implement RBAC, segregate duties within the boundary, and regularly audit permissions.",
            "V4.2.2 - Verify segregation of duties; V4.2.1 - Verify RBAC.",
            "Secure Architecture Level 2 - Implement RBAC; Governance Level 2 - Audit permissions."
        )

    # Analyze diagram (simulate component detection based on user input)
    if st.session_state.diagram:
        # Assume diagram contains common components based on text input
        diagram_components = []
        if components["web"]:
            diagram_components.append("Web Application")
        if components["database"]:
            diagram_components.append("Database")
        if components["api"]:
            diagram_components.append("API")
        if components["cloud"]:
            diagram_components.append("Cloud Service")

        for component in diagram_components:
            # Spoofing in diagram components
            add_threat(
                "Spoofing",
                f"Impersonation of {component} in diagram.",
                "Spoofing",
                f"Secure {component} with strong authentication (e.g., OAuth, certificates) and validate all interactions.",
                "V2.1.1 - Verify authentication controls; V13.2.2 - Verify API authentication.",
                "Threat Assessment Level 1 - Identify component risks; Governance Level 2 - Enforce authentication."
            )

            # Information Disclosure in diagram
            add_threat(
                "Information Disclosure",
                f"Data exposure in {component} due to unencrypted channels or misconfiguration.",
                "Information Disclosure",
                f"Encrypt all data flows to/from {component} and restrict access to authorized entities.",
                "V9.1.1 - Verify secure communication; V4.1.3 - Verify access controls.",
                "Implementation Level 2 - Secure data flows; Operations Level 2 - Protect components."
            )

            # Denial of Service in diagram
            add_threat(
                "Denial of Service",
                f"Resource exhaustion targeting {component} in diagram.",
                "Denial of Service",
                f"Implement rate limiting and auto-scaling for {component}, and use WAF for protection.",
                "V1.10.1 - Verify anti-DoS controls; V13.1.1 - Verify API resilience.",
                "Incident Management Level 2 - Monitor components; Operations Level 2 - Ensure availability."
            )

    return {"threats": threats}

def step_1():
    st.header("Step 1: Provide System Details")
    st.session_state.text_input = st.text_area(
        "Describe your system architecture (e.g., components, technologies, third-party services)",
        st.session_state.text_input,
        height=200
    )
    uploaded_file = st.file_uploader("Upload a Data Flow Diagram (e.g., PNG, JPG)", type=["png", "jpg", "jpeg"])
    if uploaded_file:
        st.session_state.diagram = base64.b64encode(uploaded_file.read()).decode('utf-8')
        st.image(uploaded_file, caption="Uploaded Data Flow Diagram")
    if st.button("Next"):
        if st.session_state.text_input or st.session_state.diagram:
            st.session_state.step = 2
            st.rerun()
        else:
            st.session_state.error = "Please provide a system description or diagram."

def step_2():
    st.header("Step 2: Define Data Flows and Trust Boundaries")
    
    st.subheader("Data Flows")
    with st.container():
        source = st.text_input("Data Flow Source (e.g., User, API)", key="data_flow_source")
        destination = st.text_input("Data Flow Destination (e.g., Database, Service)", key="data_flow_destination")
        data_type = st.text_input("Data Type (e.g., PII, Public, Confidential)", key="data_flow_type")
        if st.button("Add Data Flow"):
            if source and destination and data_type:
                st.session_state.data_flows.append({"source": source, "destination": destination, "dataType": data_type})
                st.success("Data Flow added!")
                st.rerun()
            else:
                st.session_state.error = "Please fill in all data flow fields."
    
    if st.session_state.data_flows:
        st.write("**Current Data Flows:**")
        for flow in st.session_state.data_flows:
            st.write(f"{flow['source']} → {flow['destination']} ({flow['dataType']})")

    st.subheader("Trust Boundaries")
    with st.container():
        name = st.text_input("Trust Boundary Name (e.g., Web Server Boundary, DMZ)", key="boundary_name")
        description = st.text_input("Trust Boundary Description", key="boundary_description")
        if st.button("Add Trust Boundary"):
            if name and description:
                st.session_state.trust_boundaries.append({"name": name, "description": description})
                st.success("Trust Boundary added!")
                st.rerun()
            else:
                st.session_state.error = "Please fill in all trust boundary fields."
    
    if st.session_state.trust_boundaries:
        st.write("**Current Trust Boundaries:**")
        for boundary in st.session_state.trust_boundaries:
            st.write(f"{boundary['name']}: {boundary['description']}")

    if st.button("Analyze Threats"):
        if st.session_state.data_flows or st.session_state.trust_boundaries:
            with st.spinner("Analyzing threats..."):
                st.session_state.threat_model = analyze_threats()
                st.session_state.step = 3
                st.rerun()
        else:
            st.session_state.error = "Please add at least one data flow or trust boundary."

def step_3():
    st.header("Step 3: Threat Model Results")
    if st.session_state.threat_model:
        st.subheader("Identified Threats")
        for threat in st.session_state.threat_model["threats"]:
            st.markdown(f"**{threat['type']}** (STRIDE: {threat['stride']})")
            st.markdown(f"- **Description**: {threat['description']}")
            st.markdown(f"- **Mitigation**: {threat['mitigation']}")
            st.markdown(f"- **OWASP ASVS**: {threat['asvs']}")
            st.markdown(f"- **OWASP SAMM**: {threat['samm']}")
            st.markdown("---")
    if st.button("Start Over"):
        st.session_state.step = 1
        st.session_state.text_input = ""
        st.session_state.diagram = None
        st.session_state.data_flows = []
        st.session_state.trust_boundaries = []
        st.session_state.threat_model = None
        st.session_state.error = ""
        st.rerun()
    if st.session_state.error:
        st.error(st.session_state.error)

# Render the current step
if st.session_state.step == 1:
    step_1()
elif st.session_state.step == 2:
    step_2()
elif st.session_state.step == 3:
    step_3()
