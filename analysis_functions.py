"""
DAO Guardian - Analysis Functions (Frontend Compatible)
========================================================
Standalone analysis functions without agent initialization
"""

import requests
import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

# Initialize API clients
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")

groq_client = None
if GROQ_API_KEY:
    groq_client = Groq(api_key=GROQ_API_KEY)

# ==================== PROPOSAL ANALYSIS ====================

def fetch_snapshot_proposal(proposal_id: str) -> dict:
    """Fetch proposal from Snapshot GraphQL API"""
    url = "https://hub.snapshot.org/graphql"
    
    query = """
    query Proposal($id: String!) {
      proposal(id: $id) {
        id
        title
        body
        choices
        start
        end
        snapshot
        state
        author
        space {
          id
          name
        }
      }
    }
    """
    
    try:
        response = requests.post(
            url,
            json={"query": query, "variables": {"id": proposal_id}},
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        
        if "data" in data and "proposal" in data["data"]:
            proposal = data["data"]["proposal"]
            if proposal is None:
                return {"error": "Proposal not found. This proposal ID may not exist on Snapshot or may have been deleted."}
            return proposal
        return {"error": "Invalid response from Snapshot API"}
    except requests.exceptions.Timeout:
        return {"error": "Request timed out. Snapshot API may be slow or down."}
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error: {str(e)}"}
    except Exception as e:
        print(f"Error fetching proposal: {e}")
        return {"error": f"Unexpected error: {str(e)}"}

def analyze_proposal_with_llm(proposal_data: dict) -> dict:
    """Analyze proposal using Groq LLM"""
    if not groq_client:
        return {
            "analysis": "Error: Groq API key not configured",
            "risk_score": 0,
            "recommendation": "Configure GROQ_API_KEY"
        }
    
    # Extract key information
    title = proposal_data.get("title", "No title")
    body = proposal_data.get("body", "No description")
    author = proposal_data.get("author", "Unknown")
    choices = proposal_data.get("choices", [])
    space = proposal_data.get("space", {})
    dao_name = space.get("name", "Unknown DAO")
    
    # Truncate body if too long
    if len(body) > 2000:
        body = body[:2000] + "..."
    
    # Create analysis prompt
    prompt = f"""You are a DAO governance security analyst. Analyze this proposal and provide:
1. A brief summary of what the proposal does
2. Key risks or concerns (if any)
3. A risk score from 1-10 (1=very safe, 10=very risky)
4. A one-sentence recommendation

Proposal Details:
- Title: {title}
- DAO: {dao_name}
- Author: {author}
- Choices: {', '.join(choices)}
- Description: {body}

Provide your analysis in this format:
## Summary
[Brief summary]

## Risks
[Key risks or "No significant risks identified"]

## Risk Score
[Number from 1-10]

## Recommendation
[One sentence recommendation]
"""
    
    try:
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=800,
            temperature=0.3
        )
        
        analysis_text = response.choices[0].message.content
        
        # Parse risk score
        risk_score = 5  # default
        for line in analysis_text.split('\n'):
            if 'risk score' in line.lower():
                # Extract number from line
                import re
                numbers = re.findall(r'\d+', line)
                if numbers:
                    risk_score = min(10, max(1, int(numbers[0])))
                    break
        
        # Extract recommendation
        recommendation = "Review carefully"
        lines = analysis_text.split('\n')
        for i, line in enumerate(lines):
            if 'recommendation' in line.lower() and i + 1 < len(lines):
                recommendation = lines[i + 1].strip()
                break
        
        return {
            "analysis": analysis_text,
            "risk_score": risk_score,
            "recommendation": recommendation
        }
    except Exception as e:
        return {
            "analysis": f"Error during analysis: {str(e)}",
            "risk_score": 0,
            "recommendation": "Analysis failed"
        }

# ==================== SECURITY ANALYSIS ====================

def fetch_contract_source_code(contract_address: str) -> dict:
    """Fetch contract source code from Etherscan V2 API"""
    if not ETHERSCAN_API_KEY:
        return {
            "error": "Etherscan API key not configured",
            "contract_address": contract_address,
            "contract_name": "Unknown (No API Key)",
            "source_code": "// API key required to fetch contract source",
        }
    
    # Use Etherscan V2 API endpoint
    url = "https://api.etherscan.io/v2/api"
    params = {
        "chainid": "1",  # Ethereum mainnet
        "module": "contract",
        "action": "getsourcecode",
        "address": contract_address,
        "apikey": ETHERSCAN_API_KEY
    }
    
    try:
        response = requests.get(url, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        # Check for API errors
        if data.get("status") == "0":
            error_msg = data.get("result", "Unknown error")
            print(f"Etherscan API Error: {error_msg}")
            # Return mock data for demo purposes
            return {
                "contract_address": contract_address,
                "contract_name": "Demo Contract (API Limited)",
                "source_code": generate_demo_contract(),
                "compiler_version": "v0.8.0",
                "optimization_used": "1",
                "runs": "200",
                "api_error": error_msg
            }
        
        if data["status"] == "1" and len(data["result"]) > 0:
            result = data["result"][0]
            source_code = result.get("SourceCode", "")
            
            # Handle empty source code
            if not source_code or source_code == "":
                return {
                    "contract_address": contract_address,
                    "contract_name": result.get("ContractName", "Unverified Contract"),
                    "source_code": "// Contract source code not verified on Etherscan",
                    "error": "Contract not verified"
                }
            
            return {
                "contract_address": contract_address,
                "contract_name": result.get("ContractName", "Unknown"),
                "source_code": source_code,
                "compiler_version": result.get("CompilerVersion", ""),
                "optimization_used": result.get("OptimizationUsed", ""),
                "runs": result.get("Runs", "")
            }
        return {}
    except Exception as e:
        print(f"Error fetching contract: {e}")
        # Return demo data on error
        return {
            "contract_address": contract_address,
            "contract_name": "Demo Contract (Network Error)",
            "source_code": generate_demo_contract(),
            "error": str(e)
        }

def generate_demo_contract() -> str:
    """Generate a demo contract for testing when API is unavailable"""
    return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DemoToken {
    string public name = "Demo Token";
    string public symbol = "DEMO";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    constructor(uint256 _initialSupply) {
        totalSupply = _initialSupply;
        balanceOf[msg.sender] = _initialSupply;
    }
    
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value, "Insufficient balance");
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    
    // Potential vulnerability: Using tx.origin for authentication
    function withdraw() public {
        require(tx.origin == msg.sender, "Not authorized");
        payable(msg.sender).transfer(address(this).balance);
    }
    
    // Potential vulnerability: Reentrancy risk
    function unsafeWithdraw(uint256 amount) public {
        require(balanceOf[msg.sender] >= amount);
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        balanceOf[msg.sender] -= amount;
    }
}"""

def analyze_contract_security(source_code: str, contract_info: dict) -> dict:
    """Analyze contract for security vulnerabilities"""
    vulnerabilities = []
    
    # Pattern-based vulnerability detection with detailed explanations
    patterns = {
        "Reentrancy": {
            "pattern": r"\.call\{value:",
            "severity": "HIGH",
            "category": "Reentrancy Attacks",
            "description": "Potential reentrancy vulnerability detected",
            "details": "External calls that transfer value before state updates can allow attackers to drain funds through recursive calls. Always update state before external calls (Checks-Effects-Interactions pattern).",
            "recommendation": "Update balances before making external calls, or use ReentrancyGuard from OpenZeppelin."
        },
        "Unchecked Call Return": {
            "pattern": r"\.call\((?!\s*\{)",
            "severity": "MEDIUM",
            "category": "Error Handling",
            "description": "Unchecked external call found",
            "details": "External calls can fail silently if the return value is not checked. This may lead to unexpected behavior or loss of funds.",
            "recommendation": "Always check return values: require(success, 'Call failed') or handle the failure appropriately."
        },
        "Delegatecall": {
            "pattern": r"delegatecall\(",
            "severity": "HIGH",
            "category": "Access Control",
            "description": "Delegatecall usage detected",
            "details": "Delegatecall executes code in the context of the calling contract. If the target is user-controlled or malicious, it can modify storage and take complete control of the contract.",
            "recommendation": "Only use delegatecall with trusted, immutable contracts. Implement strict access controls and validate target addresses."
        },
        "Selfdestruct": {
            "pattern": r"selfdestruct\(",
            "severity": "CRITICAL",
            "category": "Contract Destruction",
            "description": "Selfdestruct function found",
            "details": "The contract can be permanently destroyed, making all funds and functionality inaccessible. If access controls are weak, an attacker could destroy the contract.",
            "recommendation": "Ensure selfdestruct is protected by multi-sig or DAO governance. Consider if selfdestruct is truly necessary."
        },
        "tx.origin Authentication": {
            "pattern": r"tx\.origin\s*==",
            "severity": "MEDIUM",
            "category": "Access Control",
            "description": "Use of tx.origin for authentication",
            "details": "tx.origin returns the original sender of the transaction, not the immediate caller. This makes the contract vulnerable to phishing attacks where a malicious contract tricks a user into calling it.",
            "recommendation": "Replace tx.origin with msg.sender for authentication checks."
        },
        "Block Timestamp Dependency": {
            "pattern": r"block\.timestamp",
            "severity": "LOW",
            "category": "Randomness & Time",
            "description": "Reliance on block.timestamp",
            "details": "Miners can manipulate block.timestamp within a ~15 second window. If timestamp is used for critical logic (like lottery draws), it may be exploitable.",
            "recommendation": "Don't use block.timestamp for random number generation or critical time-sensitive operations. Use block.number for time windows instead."
        },
        "Unprotected Function": {
            "pattern": r"function\s+\w+\s*\([^)]*\)\s+public\s+(?!view|pure)",
            "severity": "MEDIUM",
            "category": "Access Control",
            "description": "Public function without access control",
            "details": "Public functions that modify state should have proper access control modifiers (onlyOwner, onlyAdmin, etc.) to prevent unauthorized access.",
            "recommendation": "Add appropriate access control modifiers like onlyOwner or implement role-based access control."
        },
        "Unsafe Transfer": {
            "pattern": r"\.transfer\(",
            "severity": "MEDIUM",
            "category": "Denial of Service",
            "description": "Use of transfer() for ETH transfers",
            "details": "transfer() and send() forward a fixed gas stipend (2300 gas) which may not be enough for complex fallback functions. This can cause transfers to fail unexpectedly.",
            "recommendation": "Use call{value: amount}('') instead of transfer() and check the return value."
        },
        "Integer Overflow (Pre-0.8.0)": {
            "pattern": r"pragma solidity\s+[\^<>=]*0\.[0-7]\.",
            "severity": "HIGH",
            "category": "Arithmetic",
            "description": "Potential integer overflow/underflow (Solidity < 0.8.0)",
            "details": "Versions before 0.8.0 don't have built-in overflow/underflow protection. Arithmetic operations can wrap around, leading to incorrect balances and potential exploits.",
            "recommendation": "Use SafeMath library for all arithmetic operations, or upgrade to Solidity 0.8.0+."
        },
        "Uninitialized Storage": {
            "pattern": r"(?:struct|mapping|array).*storage\s+\w+(?!\s*=)",
            "severity": "HIGH",
            "category": "Storage Issues",
            "description": "Uninitialized storage pointer",
            "details": "Uninitialized storage pointers can point to arbitrary storage slots, potentially overwriting critical state variables.",
            "recommendation": "Always initialize storage pointers explicitly or use memory for local variables."
        },
        "Floating Pragma": {
            "pattern": r"pragma solidity\s+\^",
            "severity": "LOW",
            "category": "Code Quality",
            "description": "Floating pragma version",
            "details": "Using floating pragmas (^0.8.0) can lead to contracts being compiled with different compiler versions, potentially introducing bugs or behavioral differences.",
            "recommendation": "Lock the pragma to a specific version: pragma solidity 0.8.20;"
        },
        "Missing Zero Address Check": {
            "pattern": r"=\s*0x0(?!\w)|address\(0\)",
            "severity": "LOW",
            "category": "Input Validation",
            "description": "Potential missing zero address validation",
            "details": "Functions that set addresses (like ownership transfer) should validate that the new address is not the zero address to prevent loss of access.",
            "recommendation": "Add require(newAddress != address(0), 'Zero address not allowed');"
        },
        "Unchecked Send": {
            "pattern": r"\.send\(",
            "severity": "HIGH",
            "category": "Error Handling",
            "description": "Unchecked send() call",
            "details": "send() returns false on failure but doesn't revert. If the return value is not checked, the contract may continue execution believing the transfer succeeded.",
            "recommendation": "Check the return value or use call{value: amount}('') with require()."
        },
        "Assert vs Require": {
            "pattern": r"assert\(",
            "severity": "LOW",
            "category": "Code Quality",
            "description": "Use of assert() instead of require()",
            "details": "assert() should only be used for invariants and consumes all remaining gas on failure. require() is better for input validation and external conditions.",
            "recommendation": "Use require() for validation and assert() only for checking invariants that should never fail."
        },
        "Deprecated Suicide": {
            "pattern": r"suicide\(",
            "severity": "HIGH",
            "category": "Deprecated",
            "description": "Use of deprecated suicide() function",
            "details": "suicide() is deprecated in favor of selfdestruct(). Using deprecated functions may cause compilation errors in newer compiler versions.",
            "recommendation": "Replace suicide() with selfdestruct()."
        },
        "Block Hash Dependency": {
            "pattern": r"block\.blockhash|blockhash\(",
            "severity": "MEDIUM",
            "category": "Randomness & Time",
            "description": "Use of blockhash for randomness",
            "details": "Miners have partial control over blockhash, making it unsuitable for generating random numbers. Can be manipulated for profit in gambling contracts.",
            "recommendation": "Use Chainlink VRF or similar oracle solutions for secure randomness."
        }
    }
    
    import re
    for vuln_type, info in patterns.items():
        matches = re.finditer(info["pattern"], source_code)
        for match in matches:
            # Find line number and surrounding context
            line_num = source_code[:match.start()].count('\n') + 1
            
            # Get the full line of code
            lines = source_code.split('\n')
            code_line = lines[line_num - 1].strip() if line_num <= len(lines) else match.group()
            
            # Get surrounding context (3 lines before and after)
            context_start = max(0, line_num - 4)
            context_end = min(len(lines), line_num + 3)
            context = '\n'.join(lines[context_start:context_end])
            
            vulnerabilities.append({
                "type": vuln_type,
                "severity": info["severity"],
                "category": info["category"],
                "description": info["description"],
                "details": info["details"],
                "recommendation": info["recommendation"],
                "line": line_num,
                "code": code_line,
                "context": context
            })
    
    # Calculate security grade
    critical_count = sum(1 for v in vulnerabilities if v["severity"] == "CRITICAL")
    high_count = sum(1 for v in vulnerabilities if v["severity"] == "HIGH")
    medium_count = sum(1 for v in vulnerabilities if v["severity"] == "MEDIUM")
    low_count = sum(1 for v in vulnerabilities if v["severity"] == "LOW")
    
    if critical_count > 0:
        grade = "F"
        grade_explanation = "Critical vulnerabilities found - immediate attention required"
    elif high_count > 2:
        grade = "D"
        grade_explanation = "Multiple high-severity issues - significant security risks"
    elif high_count > 0 or medium_count > 3:
        grade = "C"
        grade_explanation = "Several security concerns - review and remediation recommended"
    elif medium_count > 0 or low_count > 2:
        grade = "B"
        grade_explanation = "Minor security issues - generally safe but could be improved"
    else:
        grade = "A"
        grade_explanation = "Excellent security - no major issues detected"
    
    # Detailed summary
    if not vulnerabilities:
        summary = "✅ No major vulnerabilities detected. Contract appears to follow security best practices."
    else:
        issue_breakdown = []
        if critical_count > 0:
            issue_breakdown.append(f"{critical_count} CRITICAL")
        if high_count > 0:
            issue_breakdown.append(f"{high_count} HIGH")
        if medium_count > 0:
            issue_breakdown.append(f"{medium_count} MEDIUM")
        if low_count > 0:
            issue_breakdown.append(f"{low_count} LOW")
        
        summary = f"⚠️ Found {len(vulnerabilities)} potential issue{'s' if len(vulnerabilities) > 1 else ''}: {', '.join(issue_breakdown)} severity."
    
    return {
        "contract_address": contract_info.get("contract_address", ""),
        "contract_name": contract_info.get("contract_name", "Unknown"),
        "vulnerabilities": vulnerabilities,
        "grade": grade,
        "grade_explanation": grade_explanation,
        "summary": summary,
        "vulnerability_counts": {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count
        }
    }
