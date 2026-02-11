from auditor.checks.ssh_hardening import check_ssh_hardening
import json


def main():
    results = check_ssh_hardening()
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
