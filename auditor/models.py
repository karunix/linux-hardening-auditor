from dataclasses import dataclass


@dataclass
class Finding:
    scope: str
    observation: str
    severity: str
    explanation: str
    recommendation: str
