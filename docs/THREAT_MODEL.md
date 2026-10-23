# v1.1 Security Model and Coverage

Agent Security is a local static-analysis helper for agent source code and configuration. Version 1.1 adds a small, inspectable set of checks for agent authorization, MCP configuration, unsafe execution, and credential exposure. Rule patterns and explanatory text are part of this open-source repository; there is no remote analysis service or hidden ruleset.

## Threats this version prioritizes

Modern agent deployments expand traditional application risk because a model can select tools, pass data between tools, and act through credentials held by the host process. OWASP describes excessive agency as the combination of excessive functionality, excessive permissions, or excessive autonomy, which can amplify manipulated or mistaken model outputs into damaging actions. Mitigations include minimizing tools and permissions, enforcing authorization in downstream systems, and requiring human approval for high-impact actions [1].

MCP adds risks around tool and server trust. OWASP's MCP Top 10 highlights token and secret exposure, scope creep, tool poisoning, supply-chain tampering, command execution, contextual prompt injection, authorization gaps, weak telemetry, shadow servers, and over-sharing [2]. The MCP project's security guidance further describes confused-deputy behavior, token passthrough, SSRF, session risks, local-server compromise, and scope minimization [3].

## What the scanner checks in v1.1

The scanner retains its existing Python and YAML heuristics and adds:

- Python AST checks for `eval`/`exec`, `subprocess` calls with `shell=True`, and `yaml.load` calls without an explicit safe loader.
- Agent/MCP JSON configuration scanning for shell-wrapped MCP server startup, cleartext HTTP endpoints, wildcard tool allow-lists, explicit approval bypasses, and token-passthrough settings.
- A generic heuristic for likely literal credentials assigned to secret-like names. The evidence text is redacted before it is placed in the finding or report.
- `--fail-on` risk thresholds for use as a simple CI gate and a 10 MiB per-file read limit.

These checks are deliberately conservative and may not match every framework's naming or configuration conventions. A finding is a review prompt, not a claim that a vulnerability is exploitable. The JSON scanner accepts likely agent/MCP files rather than treating every JSON document as agent configuration.

## Important boundaries

Static text analysis cannot reliably decide whether retrieved content is malicious, whether a model will follow an injected instruction, whether a tool result is properly isolated, or whether a user is authorized for a downstream action. It cannot establish that a server is trustworthy, that tool schemas remain unchanged, or that a code sandbox is effective. Absence of a finding is not evidence that an agent is safe.

Use downstream authorization and least-privileged identities for every tool call. Treat tool output and retrieved documents as untrusted data. Pin and review MCP servers and dependencies. Require approval for consequential actions and log enough context to investigate them. Run code-execution tools in a separate, resource-limited environment without ambient secrets. The scanner does not implement any of these runtime controls.

## Research references

[1]: https://genai.owasp.org/llmrisk/llm062025-excessive-agency/ "OWASP LLM06:2025 Excessive Agency"
[2]: https://owasp.org/projects/mcp-top-10 "OWASP MCP Top 10"
[3]: https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices "Model Context Protocol Security Best Practices"
[4]: https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html "OWASP MCP Security Cheat Sheet"
[5]: https://docs.github.com/en/actions/reference/security/secure-use "GitHub Actions Secure Use Reference"
