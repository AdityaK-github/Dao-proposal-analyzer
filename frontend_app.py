"""
DAO Guardian - Immersive Web Frontend
=====================================
An interactive dashboard for analyzing DAO proposals and smart contracts
"""

import streamlit as st
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import standalone analysis functions (no agent initialization)
from analysis_functions import (
    fetch_snapshot_proposal, 
    analyze_proposal_with_llm,
    fetch_contract_source_code, 
    analyze_contract_security
)

# Page configuration
st.set_page_config(
    page_title="DAO Guardian",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        padding: 1rem 0;
    }
    .card {
        padding: 1.5rem;
        border-radius: 0.5rem;
        background-color: #f0f2f6;
        margin: 1rem 0;
    }
    .success-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #d4edda;
        border-left: 4px solid #28a745;
        margin: 1rem 0;
    }
    .warning-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #fff3cd;
        border-left: 4px solid #ffc107;
        margin: 1rem 0;
    }
    .danger-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #f8d7da;
        border-left: 4px solid #dc3545;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown('<div class="main-header">🛡️ DAO Guardian</div>', unsafe_allow_html=True)
st.markdown('<p style="text-align: center; color: #666; font-size: 1.2rem;">AI-Powered DAO Proposal & Smart Contract Security Analysis</p>', unsafe_allow_html=True)

# Status banner
st.info("ℹ️ **Note**: If Etherscan API is rate-limited, the system will use demo contracts to showcase security analysis capabilities. Proposal analysis from Snapshot is fully functional!", icon="ℹ️")

# Sidebar
with st.sidebar:
    st.image("https://via.placeholder.com/300x100/667eea/ffffff?text=DAO+Guardian", width="stretch")
    st.markdown("---")
    st.markdown("### 🔍 Analysis Tools")
    analysis_mode = st.radio(
        "Select Analysis Mode",
        ["📊 Proposal Analysis", "🔒 Contract Security", "🎯 Complete Analysis"],
        index=2
    )
    st.markdown("---")
    st.markdown("### ℹ️ About")
    st.info("""
    **DAO Guardian** uses AI agents to:
    - Analyze DAO proposals from Snapshot
    - Scan smart contracts for vulnerabilities
    - Provide risk assessments
    - Detect 20+ vulnerability patterns
    """)
    st.markdown("---")
    st.markdown("### 💡 Quick Tips")
    st.success("""
    **Finding Proposals:**
    1. Visit [snapshot.org](https://snapshot.org)
    2. Find a proposal you want to analyze
    3. Copy the ID from the URL
    4. Paste it in the input field
    
    **Example:** `0xf06f3ad...` (66 chars)
    """)
    st.markdown("---")
    st.markdown("### 🤖 Powered By")
    st.markdown("- 🧠 **Groq** (Llama 3.3 70B)")
    st.markdown("- 📊 **Snapshot** GraphQL API")
    st.markdown("- 🔐 **Etherscan** API")
    st.markdown("- 🦾 **uAgents** Framework")

# Main content area
if analysis_mode == "📊 Proposal Analysis":
    st.header("📊 DAO Proposal Analysis")
    st.markdown("Analyze governance proposals from Snapshot to assess risks and provide recommendations.")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        proposal_id = st.text_input(
            "Proposal ID (Snapshot)",
            placeholder="0xf06f3ad61f9f77c8ed362dd54913cc44d030841eebebfffce4dd6605b1b0e6f3",
            help="Enter the full proposal ID hash from Snapshot"
        )
    
    with col2:
        analyze_btn = st.button("🔍 Analyze Proposal", width="stretch", type="primary")
    
    # Quick example buttons
    st.caption("📌 **Try an example:**")
    col_ex1, col_ex2, col_ex3 = st.columns(3)
    with col_ex1:
        if st.button("ENS Proposal", width="stretch"):
            proposal_id = "0xf06f3ad61f9f77c8ed362dd54913cc44d030841eebebfffce4dd6605b1b0e6f3"
            st.rerun()
    with col_ex2:
        if st.button("Find on Snapshot", width="stretch"):
            st.markdown("[🔗 Open Snapshot.org](https://snapshot.org)")
    with col_ex3:
        st.markdown("")  # Placeholder for alignment
    
    if analyze_btn and proposal_id:
        with st.spinner("🔄 Fetching proposal from Snapshot..."):
            try:
                proposal_data = fetch_snapshot_proposal(proposal_id)
                
                # Check for errors
                if proposal_data and "error" in proposal_data:
                    st.error(f"❌ {proposal_data['error']}")
                    st.info("💡 **Tips:**\n- Make sure the proposal ID is correct (64 hex characters)\n- Try finding proposals at https://snapshot.org\n- Example working ID: `0xf06f3ad61f9f77c8ed362dd54913cc44d030841eebebfffce4dd6605b1b0e6f3`")
                elif proposal_data and proposal_data.get('title'):
                    st.success("✅ Proposal fetched successfully!")
                    
                    # Display proposal info
                    st.markdown("### Proposal Details")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Title", proposal_data.get('title', 'N/A')[:30] + "...")
                    with col2:
                        st.metric("DAO", proposal_data.get('space', {}).get('name', 'N/A'))
                    with col3:
                        st.metric("State", proposal_data.get('state', 'N/A'))
                    
                    # Analyze with LLM
                    with st.spinner("🧠 Analyzing with AI..."):
                        analysis_result = analyze_proposal_with_llm(proposal_data)
                        
                        # Display analysis
                        st.markdown("### 🤖 AI Analysis")
                        st.markdown(analysis_result.get('analysis', 'No analysis available'))
                        
                        # Risk score
                        risk_score = analysis_result.get('risk_score', 0)
                        st.markdown(f"### Risk Score: {risk_score}/10")
                        st.progress(risk_score / 10)
                        
                        if risk_score >= 7:
                            st.markdown(f'<div class="danger-box">⚠️ <strong>High Risk</strong>: {analysis_result.get("recommendation", "Exercise caution")}</div>', unsafe_allow_html=True)
                        elif risk_score >= 4:
                            st.markdown(f'<div class="warning-box">⚠️ <strong>Medium Risk</strong>: {analysis_result.get("recommendation", "Review carefully")}</div>', unsafe_allow_html=True)
                        else:
                            st.markdown(f'<div class="success-box">✅ <strong>Low Risk</strong>: {analysis_result.get("recommendation", "Appears safe")}</div>', unsafe_allow_html=True)
                else:
                    st.error("❌ Could not fetch proposal. Please check the Proposal ID.")
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")

elif analysis_mode == "🔒 Contract Security":
    st.header("🔒 Smart Contract Security Analysis")
    st.markdown("Scan Ethereum smart contracts for common vulnerabilities and security issues.")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        contract_address = st.text_input(
            "Contract Address",
            placeholder="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            help="Enter the Ethereum contract address"
        )
    
    with col2:
        scan_btn = st.button("🔍 Scan Contract", width="stretch", type="primary")
    
    # Quick example buttons
    st.caption("📌 **Try an example:**")
    col_ex1, col_ex2, col_ex3 = st.columns(3)
    with col_ex1:
        if st.button("USDC Contract", key="usdc", width="stretch"):
            contract_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            st.rerun()
    with col_ex2:
        if st.button("DAI Contract", key="dai", width="stretch"):
            contract_address = "0x6B175474E89094C44Da98b954EedeAC495271d0F"
            st.rerun()
    with col_ex3:
        st.markdown("")  # Placeholder
    
    if scan_btn and contract_address:
        with st.spinner("🔄 Fetching contract source from Etherscan..."):
            try:
                contract_info = fetch_contract_source_code(contract_address)
                
                if contract_info and contract_info.get('source_code'):
                    # Check if it's demo data
                    is_demo = 'api_error' in contract_info or 'error' in contract_info
                    
                    if is_demo:
                        st.warning(f"⚠️ Using demo contract data (API issue: {contract_info.get('api_error', contract_info.get('error', 'Unknown'))})")
                    else:
                        st.success(f"✅ Contract fetched: {contract_info.get('contract_name', 'Unknown')}")
                    
                    st.info(f"**Contract Name:** {contract_info.get('contract_name', 'Unknown')}")
                    
                    # Analyze security
                    with st.spinner("🔐 Scanning for vulnerabilities..."):
                        security_result = analyze_contract_security(contract_info['source_code'], contract_info)
                        
                        # Security grade
                        grade = security_result.get('grade', 'F')
                        st.markdown(f"### Security Grade: {grade}")
                        
                        grade_colors = {'A': 'success-box', 'B': 'success-box', 'C': 'warning-box', 'D': 'danger-box', 'F': 'danger-box'}
                        box_class = grade_colors.get(grade, 'warning-box')
                        st.markdown(f'<div class="{box_class}"><strong>Grade {grade}</strong>: {security_result.get("summary", "Analysis complete")}</div>', unsafe_allow_html=True)
                        
                        # Vulnerabilities
                        vulns = security_result.get('vulnerabilities', [])
                        counts = security_result.get('vulnerability_counts', {})
                        
                        st.markdown(f"### 🔍 Security Analysis Results")
                        st.markdown(f"**Total Issues Found:** {len(vulns)}")
                        
                        if vulns:
                            # Show counts by severity
                            col1, col2, col3, col4 = st.columns(4)
                            with col1:
                                st.metric("🔴 Critical", counts.get('critical', 0))
                            with col2:
                                st.metric("🟠 High", counts.get('high', 0))
                            with col3:
                                st.metric("🟡 Medium", counts.get('medium', 0))
                            with col4:
                                st.metric("🟢 Low", counts.get('low', 0))
                            
                            st.markdown("---")
                            st.markdown("### 📋 Detailed Vulnerability Report")
                            
                            # Group vulnerabilities by category
                            vulns_by_category = {}
                            for vuln in vulns:
                                category = vuln.get('category', 'Other')
                                if category not in vulns_by_category:
                                    vulns_by_category[category] = []
                                vulns_by_category[category].append(vuln)
                            
                            # Category icons
                            category_icons = {
                                'Reentrancy Attacks': '🔄',
                                'Access Control': '🔐',
                                'Error Handling': '⚠️',
                                'Contract Destruction': '💥',
                                'Randomness & Time': '🎲',
                                'Arithmetic': '➕',
                                'Storage Issues': '💾',
                                'Code Quality': '✨',
                                'Input Validation': '✅',
                                'Deprecated': '⛔',
                                'Denial of Service': '🚫',
                                'Other': '📋'
                            }
                            
                            # Display by category
                            for category, category_vulns in sorted(vulns_by_category.items()):
                                category_icon = category_icons.get(category, '📋')
                                st.markdown(f"#### {category_icon} {category} ({len(category_vulns)} issue{'s' if len(category_vulns) > 1 else ''})")
                                
                                for i, vuln in enumerate(category_vulns, 1):
                                    severity = vuln.get('severity', 'UNKNOWN')
                                    severity_icon = {
                                        'CRITICAL': '🔴',
                                        'HIGH': '🟠',
                                        'MEDIUM': '🟡',
                                        'LOW': '🟢'
                                    }.get(severity, '⚪')
                                    
                                    # Determine box color based on severity
                                    box_class = {
                                        'CRITICAL': 'danger-box',
                                        'HIGH': 'danger-box',
                                        'MEDIUM': 'warning-box',
                                        'LOW': 'success-box'
                                    }.get(severity, 'warning-box')
                                    
                                    with st.expander(f"{severity_icon} **{vuln.get('type', 'Unknown')}** (Line {vuln.get('line', '?')}) - {severity} Severity", expanded=(i == 1 and len(category_vulns) <= 3)):
                                        st.markdown(f'<div class="{box_class}">', unsafe_allow_html=True)
                                        st.markdown(f"**🎯 Issue:** {vuln.get('description', 'N/A')}")
                                        st.markdown(f"**📖 Details:** {vuln.get('details', 'N/A')}")
                                        st.markdown(f"**💡 Recommendation:** {vuln.get('recommendation', 'N/A')}")
                                        st.markdown('</div>', unsafe_allow_html=True)
                                        
                                        if vuln.get('code'):
                                            st.markdown("**📍 Affected Code:**")
                                            st.code(vuln.get('code'), language="solidity")
                                        
                                        if vuln.get('context'):
                                            st.markdown("**📄 Code Context:**")
                                            st.code(vuln.get('context'), language="solidity")
                                
                                st.markdown("")  # Spacing between categories
                        else:
                            st.success("✅ No major vulnerabilities detected! Contract follows security best practices.")
                else:
                    st.error("❌ Could not fetch contract. Please check the address.")
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")

else:  # Complete Analysis
    st.header("🎯 Complete DAO Analysis")
    st.markdown("Perform a comprehensive analysis of both the proposal and associated smart contract.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        proposal_id = st.text_input(
            "Proposal ID",
            placeholder="0xf06f3ad61f9f77c8ed362dd54913cc44d030841eebebfffce4dd6605b1b0e6f3"
        )
    
    with col2:
        contract_address = st.text_input(
            "Contract Address (optional)",
            placeholder="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        )
    
    analyze_complete_btn = st.button("🚀 Run Complete Analysis", width="stretch", type="primary")
    
    if analyze_complete_btn and proposal_id:
        proposal_result = None
        contract_result = None
        
        # Proposal Analysis
        st.markdown("## 📊 Proposal Analysis")
        with st.spinner("Analyzing proposal..."):
            try:
                proposal_data = fetch_snapshot_proposal(proposal_id)
                
                if proposal_data and "error" in proposal_data:
                    st.error(f"❌ {proposal_data['error']}")
                elif proposal_data and proposal_data.get('title'):
                    analysis_result = analyze_proposal_with_llm(proposal_data)
                    proposal_result = {
                        'data': proposal_data,
                        'analysis': analysis_result
                    }
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("### Proposal Info")
                        st.write(f"**Title**: {proposal_data.get('title', 'N/A')}")
                        st.write(f"**DAO**: {proposal_data.get('space', {}).get('name', 'N/A')}")
                        st.write(f"**State**: {proposal_data.get('state', 'N/A')}")
                    
                    with col2:
                        st.markdown("### Risk Assessment")
                        risk_score = analysis_result.get('risk_score', 0)
                        st.metric("Risk Score", f"{risk_score}/10")
                        st.progress(risk_score / 10)
                    
                    st.markdown("### Analysis")
                    st.info(analysis_result.get('analysis', 'No analysis available'))
                else:
                    st.error("Could not fetch proposal")
            except Exception as e:
                st.error(f"Proposal analysis error: {str(e)}")
        
        # Contract Analysis (if provided)
        if contract_address:
            st.markdown("---")
            st.markdown("## 🔒 Contract Security Analysis")
            with st.spinner("Scanning contract..."):
                try:
                    contract_info = fetch_contract_source_code(contract_address)
                    if contract_info and contract_info.get('source_code'):
                        security_result = analyze_contract_security(contract_info['source_code'], contract_info)
                        contract_result = {
                            'info': contract_info,
                            'security': security_result
                        }
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown("### Contract Info")
                            st.write(f"**Name**: {contract_info.get('contract_name', 'Unknown')}")
                            st.write(f"**Address**: {contract_address[:10]}...{contract_address[-8:]}")
                        
                        with col2:
                            st.markdown("### Security Grade")
                            grade = security_result.get('grade', 'F')
                            st.metric("Grade", grade)
                            st.write(security_result.get('grade_explanation', 'N/A'))
                        
                        vulns = security_result.get('vulnerabilities', [])
                        counts = security_result.get('vulnerability_counts', {})
                        
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("🔴 Critical", counts.get('critical', 0))
                        with col2:
                            st.metric("🟠 High", counts.get('high', 0))
                        with col3:
                            st.metric("🟡 Medium", counts.get('medium', 0))
                        with col4:
                            st.metric("🟢 Low", counts.get('low', 0))
                        
                        if vulns:
                            # Group and display vulnerabilities
                            st.markdown("---")
                            st.markdown("### 🔍 Vulnerability Details by Category")
                            
                            vulns_by_category = {}
                            for vuln in vulns:
                                category = vuln.get('category', 'Other')
                                if category not in vulns_by_category:
                                    vulns_by_category[category] = []
                                vulns_by_category[category].append(vuln)
                            
                            category_icons = {
                                'Reentrancy Attacks': '🔄',
                                'Access Control': '🔐',
                                'Error Handling': '⚠️',
                                'Contract Destruction': '💥',
                                'Randomness & Time': '🎲',
                                'Arithmetic': '➕',
                                'Storage Issues': '💾',
                                'Code Quality': '✨',
                                'Input Validation': '✅',
                                'Deprecated': '⛔',
                                'Denial of Service': '🚫',
                                'Other': '📋'
                            }
                            
                            for category, category_vulns in sorted(vulns_by_category.items()):
                                category_icon = category_icons.get(category, '📋')
                                with st.expander(f"{category_icon} {category} ({len(category_vulns)} issue{'s' if len(category_vulns) > 1 else ''})", expanded=True):
                                    for vuln in category_vulns:
                                        severity_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(vuln.get('severity', 'UNKNOWN'), '⚪')
                                        st.markdown(f"{severity_icon} **{vuln.get('type')}** (Line {vuln.get('line', '?')})")
                                        st.caption(vuln.get('description', 'N/A'))
                    else:
                        st.warning("Could not fetch contract source")
                except Exception as e:
                    st.error(f"Contract analysis error: {str(e)}")
        
        # Final Recommendation - Enhanced
        st.markdown("---")
        st.markdown("## 💡 Final Recommendation")
        
        if proposal_result and contract_result:
            # Both analyses available
            risk_score = proposal_result['analysis'].get('risk_score', 0)
            grade = contract_result['security'].get('grade', 'F')
            vulns = contract_result['security'].get('vulnerabilities', [])
            critical_count = contract_result['security'].get('vulnerability_counts', {}).get('critical', 0)
            high_count = contract_result['security'].get('vulnerability_counts', {}).get('high', 0)
            
            # Generate comprehensive recommendation
            st.markdown("### 🎯 Overall Assessment")
            
            # Risk Level Determination
            overall_risk = "LOW"
            risk_color = "success-box"
            
            if critical_count > 0 or risk_score >= 8:
                overall_risk = "CRITICAL"
                risk_color = "danger-box"
            elif high_count > 0 or risk_score >= 7 or grade in ['D', 'F']:
                overall_risk = "HIGH"
                risk_color = "danger-box"
            elif risk_score >= 4 or grade == 'C' or high_count + len(vulns) > 2:
                overall_risk = "MEDIUM"
                risk_color = "warning-box"
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("📊 Proposal Risk", f"{risk_score}/10")
            with col2:
                st.metric("🔒 Security Grade", grade)
            with col3:
                st.metric("⚠️ Total Issues", len(vulns))
            
            # Detailed recommendation
            recommendation_text = f"## Overall Risk Level: {overall_risk}\n\n"
            
            if overall_risk == "CRITICAL":
                recommendation_text += "🔴 **CRITICAL CONCERNS IDENTIFIED**\n\n"
                recommendation_text += "This proposal presents significant risks and should NOT be approved without major revisions:\n\n"
                if critical_count > 0:
                    recommendation_text += f"- ❌ **{critical_count} CRITICAL security vulnerabilities** found in the contract\n"
                if high_count > 0:
                    recommendation_text += f"- ❌ **{high_count} HIGH severity issues** detected\n"
                if risk_score >= 8:
                    recommendation_text += f"- ❌ **Very high governance risk** (score: {risk_score}/10)\n"
                recommendation_text += "\n**Action Required:** Reject or request complete security audit and governance review before proceeding."
                
            elif overall_risk == "HIGH":
                recommendation_text += "🟠 **SIGNIFICANT RISKS DETECTED**\n\n"
                recommendation_text += "This proposal has notable security and governance concerns:\n\n"
                if high_count > 0:
                    recommendation_text += f"- ⚠️ **{high_count} HIGH severity vulnerabilities** in contract code\n"
                if grade in ['D', 'F']:
                    recommendation_text += f"- ⚠️ **Poor security grade ({grade})** - needs improvement\n"
                if risk_score >= 7:
                    recommendation_text += f"- ⚠️ **High governance risk** (score: {risk_score}/10)\n"
                recommendation_text += "\n**Recommendation:** Request security audit and address all high-severity issues before approval."
                
            elif overall_risk == "MEDIUM":
                recommendation_text += "🟡 **MODERATE CONCERNS**\n\n"
                recommendation_text += "This proposal shows some areas that need attention:\n\n"
                if len(vulns) > 0:
                    recommendation_text += f"- ⚠️ **{len(vulns)} security issues** identified (review each carefully)\n"
                if grade == 'C':
                    recommendation_text += f"- ⚠️ **Average security grade ({grade})** - room for improvement\n"
                if risk_score >= 4:
                    recommendation_text += f"- ⚠️ **Moderate governance risk** (score: {risk_score}/10)\n"
                recommendation_text += "\n**Recommendation:** Review all flagged issues. Consider security improvements before final approval."
                
            else:
                recommendation_text += "🟢 **LOW RISK - APPEARS SAFE**\n\n"
                recommendation_text += "This proposal meets security and governance standards:\n\n"
                recommendation_text += f"- ✅ Low governance risk (score: {risk_score}/10)\n"
                recommendation_text += f"- ✅ Good security grade ({grade})\n"
                if len(vulns) == 0:
                    recommendation_text += "- ✅ No major vulnerabilities detected\n"
                else:
                    recommendation_text += f"- ℹ️ Minor issues found ({len(vulns)}) - review for best practices\n"
                recommendation_text += "\n**Recommendation:** This proposal appears safe to approve. Standard due diligence recommended."
            
            st.markdown(f'<div class="{risk_color}" style="padding: 1.5rem;">{recommendation_text}</div>', unsafe_allow_html=True)
            
        elif proposal_result:
            # Only proposal analysis
            risk_score = proposal_result['analysis'].get('risk_score', 0)
            recommendation = proposal_result['analysis'].get('recommendation', '')
            
            if risk_score >= 7:
                st.markdown(f'<div class="danger-box">🔴 **High Risk Proposal** (Score: {risk_score}/10)\n\n{recommendation}\n\n**Note:** Add a contract address to perform security analysis.</div>', unsafe_allow_html=True)
            elif risk_score >= 4:
                st.markdown(f'<div class="warning-box">🟡 **Medium Risk Proposal** (Score: {risk_score}/10)\n\n{recommendation}\n\n**Note:** Add a contract address for complete security analysis.</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="success-box">🟢 **Low Risk Proposal** (Score: {risk_score}/10)\n\n{recommendation}\n\n**Note:** Add a contract address to verify smart contract security.</div>', unsafe_allow_html=True)
        else:
            st.info("ℹ️ Complete the analysis above to see final recommendations.")

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #666; padding: 2rem 0;">
    <p>🛡️ DAO Guardian | Built with uAgents, Groq, and Streamlit</p>
    <p>Protecting DAO governance through AI-powered analysis</p>
</div>
""", unsafe_allow_html=True)
