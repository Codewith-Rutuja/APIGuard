from dataclasses import dataclass, asdict


@dataclass
class Finding:
    finding_id: str
    title: str
    description: str
    severity: str
    owasp_category: str
    endpoint: str
    method: str
    evidence: str
    impact: str
    remediation: str

    def to_dict(self):
        return asdict(self)
