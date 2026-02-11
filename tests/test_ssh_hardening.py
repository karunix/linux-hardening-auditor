from auditor.checks.ssh_hardening import check_ssh_hardening
from pathlib import Path


def test_insecure_ssh_detected(monkeypatch, tmp_path):
    fake_config = tmp_path / "sshd_config"
    fake_config.write_text("""
PermitRootLogin yes
PasswordAuthentication yes
""")

    monkeypatch.setattr(
        "auditor.checks.ssh_hardening.SSHD_CONFIG",
        fake_config
    )

    findings = check_ssh_hardening()

    assert any("Root login" in f["reason"] for f in findings)
    assert any("Password-based" in f["reason"] for f in findings)
