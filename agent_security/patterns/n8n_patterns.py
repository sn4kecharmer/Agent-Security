import re
from ..models import SecurityInfo, RiskLevel

N8N_PATTERNS = {
    # Code Node Env Access
    "n8n_code_node_env_access": SecurityInfo(
        name="Code Node Env Access",
        risk_level=RiskLevel.HIGH,
        description="Code node accessing environment variables via process.env.",
        impact="Workflow may exfiltrate sensitive environment variables, such as API keys or credentials, stored in the n8n server's environment.",
        remediation="Avoid accessing process.env directly in Code nodes. Use n8n's built-in credential management or node parameters for passing configuration and secrets securely. If environment variables must be used, ensure they do not contain highly sensitive information.",
        pattern=re.compile(r'process\.env')
        # Scanner applies this to JS code in 'n8n-nodes-base.code'
    ),

    # Expanded Code Node Eval/String-to-Code Usage
    "n8n_code_node_eval_usage": SecurityInfo(
        name="Code Node Risky String-to-Code Execution",
        risk_level=RiskLevel.CRITICAL,
        description="Code node uses potentially unsafe functions like eval(), new Function(), or setTimeout/setInterval with string arguments.",
        impact="Arbitrary code execution within the n8n workflow context is possible if the input to these functions is controlled by an attacker or unvalidated external data. This can lead to server compromise or data exfiltration.",
        remediation="Avoid eval(), new Function(), and passing strings to setTimeout()/setInterval(). Refactor code to use safer, parameterized methods. Sanitize any inputs if dynamic code execution is absolutely unavoidable and whitelisted.",
        # Pattern targets eval(', new Function(', setTimeout('...'), setInterval('...')
        pattern=re.compile(r'(?:eval|new\s+Function|setTimeout|setInterval)\s*\(\s*[\'"`]')
        # Scanner applies this to JS code in 'n8n-nodes-base.code'
    ),

    # Execute Command Node Usage (Original - flags any use)
    "n8n_execute_command_node_usage": SecurityInfo(
        name="Execute Command Node Usage",
        risk_level=RiskLevel.HIGH, # Risk is for the node itself, specific injection is CRITICAL
        description="Execute Command node is used in the workflow. This node allows execution of arbitrary shell commands on the n8n server.",
        impact="If not carefully managed, this node can introduce severe security risks, including command injection, leading to server compromise.",
        remediation="Whenever possible, use built-in n8n nodes for specific tasks instead of generic command execution. If Execute Command node is necessary, ensure commands are static or, if dynamic, that inputs are rigorously sanitized and validated. Limit the permissions of the n8n execution environment.",
        pattern=re.compile(r'n8n-nodes-base\.executeCommand'), # Matches the node type
        category="Command Execution",
        cwe=["CWE-78"], # Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
        owasp=["A03:2021-Injection"]
        # Scanner checks 'type' == 'n8n-nodes-base.executeCommand'
    ),

    # New: Command Injection in Execute Command via Expressions
    "n8n_command_injection_execute_command": SecurityInfo(
        name="Potential Command Injection in Execute Command Node via Expression",
        risk_level=RiskLevel.CRITICAL,
        description="The 'command' parameter of an Execute Command node uses an n8n expression (e.g., {{ $json.body.command }}).",
        impact="If the data within the expression is derived from external, unvalidated input, this can allow attackers to inject arbitrary commands and execute them on the n8n server, leading to full server compromise.",
        remediation="Do not use n8n expressions with untrusted or unvalidated external input directly in the 'command' parameter. If dynamic commands are required, ensure any data used in expressions is strictly validated and sanitized. Prefer passing specific, expected values rather than raw input.",
        pattern=re.compile(r'\{\{.*\}\}'), # Detects {{...}}
        category="Command Injection",
        cwe=["CWE-77", "CWE-78"], # CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')
        owasp=["A03:2021-Injection"]
        # Scanner applies this to 'parameters.command' of 'n8n-nodes-base.executeCommand'
    ),

    # Enhanced Hardcoded API Key (Generic)
    "n8n_hardcoded_api_key_generic": SecurityInfo(
        name="Potential Hardcoded Secret",
        risk_level=RiskLevel.HIGH,
        description="A potential hardcoded secret (e.g., API key, password, token) was found in a node's parameters.",
        impact="Exposure of sensitive secrets within the workflow JSON. If the workflow is shared or accessed by unauthorized individuals, these secrets can be compromised.",
        remediation="Store all secrets like API keys, passwords, and tokens in n8n's built-in credential manager. Reference credentials using expressions where necessary, e.g., {{ $credentials.myApiCredential.apiKey }}.",
        # Enhanced keyword list
        pattern=re.compile(r'(?i)(api_key|secret_key|token|password|secret|bearer|credential|access_token|client_secret|apikey|secretkey)[\s:=]+[\'"]([a-zA-Z0-9_/\-+]{16,})[\'"]'),
        category="Hardcoded Secrets",
        cwe=["CWE-798", "CWE-312"], # Use of Hard-coded Credentials, Cleartext Storage of Sensitive Information
        owasp=["A07:2021-Identification and Authentication Failures", "A05:2021-Security Misconfiguration"]
        # Scanner applies this to all string parameter values
    ),

    # SSRF in HTTP Request Node (Original)
    "n8n_ssrf_http_request_node": SecurityInfo(
        name="Potential SSRF via Internal IP in HTTP Request Node",
        risk_level=RiskLevel.HIGH,
        description="HTTP Request node is configured with a URL targeting a potential internal/private IP address (e.g., localhost, 10.x.x.x, 192.168.x.x).",
        impact="Allows the n8n server to make requests to internal network resources that may not be directly accessible externally. This can be abused for reconnaissance or attacking internal services (Server-Side Request Forgery - SSRF).",
        remediation="Validate and sanitize all URLs used in HTTP Request nodes. If internal requests are necessary, use a strict whitelist of allowed internal domains/IPs. Avoid using user-provided data directly in URLs without proper validation.",
        pattern=re.compile(r'(localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})'),
        category="Server-Side Request Forgery (SSRF)",
        cwe=["CWE-918"], # Server-Side Request Forgery (SSRF)
        owasp=["A10:2021-Server-Side Request Forgery (SSRF)"]
        # Scanner applies this to 'parameters.url' of 'n8n-nodes-base.httpRequest'
    ),

    # New: Sensitive Data in HTTP URL via Expressions
    "n8n_sensitive_data_in_http_url": SecurityInfo(
        name="Potential Sensitive Data Exposure in HTTP Request URL via Expression",
        risk_level=RiskLevel.HIGH, # Changed from MEDIUM to HIGH as per typical severity for this
        description="The URL parameter of an HTTP Request node uses an n8n expression (e.g., {{ $json.body.id }}), which might inadvertently expose secrets or sensitive internal data if the expression resolves to such information.",
        impact="Sensitive information (e.g., API keys, session tokens, personal data) could be logged by intermediate proxies, the target server, or exposed in browser history if the URL is ever processed or logged by other systems. This could lead to data breaches or privacy violations.",
        remediation="Carefully review all expressions used in HTTP Request URLs. Avoid passing sensitive data directly in URLs. Use n8n's credential system for API keys and tokens, and prefer passing other sensitive data in POST request bodies or secure HTTP headers. Ensure the target endpoint is trusted.",
        pattern=re.compile(r'\{\{.*\}\}'), # Detects {{...}}
        category="Information Exposure",
        cwe=["CWE-200", "CWE-598"], # Information Exposure, Use of GET Request Method With Sensitive Query Strings
        owasp=["A01:2021-Broken Access Control", "A04:2021-Insecure Design"] # Depending on impact
        # Scanner applies this to 'parameters.url' of 'n8n-nodes-base.httpRequest'
    ),
}
