from pathlib import Path

# Default SSHD config path (overridden in tests)
SSHD_CONFIG = Path("/etc/ssh/sshd_config")


def check_ssh_hardening():
    findings = []

    if not SSHD_CONFIG.exists():
        return findings

    content = SSHD_CONFIG.read_text().splitlines()

    permit_root_login = None
    password_auth = None

    for line in content:
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if line.lower().startswith("permitrootlogin"):
            permit_root_login = line.split()[1].lower()

        if line.lower().startswith("passwordauthentication"):
            password_auth = line.split()[1].lower()

    if permit_root_login == "yes":
        findings.append(
            {
                "control": "SSH Root Login",
                "severity": "HIGH",
                "reason": "Root login over SSH is enabled",
                "recommendation": "Set PermitRootLogin no",
            }
        )

    if password_auth == "yes":
        findings.append(
            {
                "control": "SSH Password Authentication",
                "severity": "MEDIUM",
                "reason": "Password-based SSH authentication is enabled",
                "recommendation": "Disable PasswordAuthentication and use SSH keys",
            }
        )

    return findings
