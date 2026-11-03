# Security policy

## Reporting a vulnerability

Please use **GitHub's private vulnerability-disclosure flow**:
<https://github.com/YanivSaar/ghost/security/advisories/new>

Do not file a public issue for a suspected vulnerability. We acknowledge within 72 hours.

## Supported versions

Only the **latest release** is supported with security patches. Older tags are not backported.

## Scope

Reports are welcome for memory-safety, authentication/authorization, privilege-escalation, injection, or data-exfiltration issues.

The following are explicitly **out of scope** (precedents from prior review passes — RFCs 0005 security review and the stability review PR):

- Denial-of-service / resource-exhaustion issues
- Outdated-dependency reports (handled by `cargo audit` in CI; see RFC 0008)
- Issues that require attacker control of environment variables or CLI arguments ghost is launched with
- Log-spoofing / unsanitised output to logs
- Theoretical races without a concrete exploit path
