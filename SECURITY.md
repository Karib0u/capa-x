# Security policy

capa-x parses potentially hostile executable files and rule content.
Memory-safety violations, panics on crafted input, uncontrolled resource use,
and unsafe external interactions are treated as security-relevant.

## Supported versions

Security fixes are made on the latest tagged release and on the `main` branch.
Older releases do not receive backported fixes. Upgrade to the newest release
before reporting an issue that may already be fixed.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability.

The preferred channel is GitHub's private vulnerability reporting:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Include the affected version or commit, platform, input type, impact, and
   the smallest reproducer you can safely provide.

If **Report a vulnerability** is not available, contact the repository owner
through their GitHub profile and request a private reporting channel. Do not
include vulnerability details or samples in a public message.

If a reproducer contains malware or sensitive material, provide hashes and
handling instructions before attaching the sample. Do not upload malware to a
public issue, pull request, or discussion.

We aim to acknowledge a report within seven days. Validation, remediation,
release timing, and disclosure coordination depend on severity and the
complexity of the fix.

## Security-relevant examples

- memory corruption or a violation of the project's unsafe-code boundary;
- a panic or process abort caused by a crafted sample, rule, or freeze file;
- attacker-controlled allocation or CPU use that creates a practical denial
  of service;
- path traversal or unintended file writes;
- command execution or unexpected network access;
- a malicious rules or archive path escaping its intended destination;
- a vulnerable dependency that is reachable through capa-x.

An ordinary disagreement with Python capa is usually an accuracy bug rather
than a vulnerability. Report it privately only when the difference creates a
security impact or the reproducer cannot safely be shared.

## Disclosure

Please allow time to validate and release a fix before public disclosure.
After remediation, the project may publish an advisory crediting the reporter,
unless anonymity is requested.
