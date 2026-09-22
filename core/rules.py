"""Rule system for the decision engine."""
from dataclasses import dataclass
from typing import Callable, List
from core.models import ScanResult, Recommendation


@dataclass
class Rule:
    name: str
    condition: Callable[[ScanResult], bool]
    recommendations: List[Recommendation]

    def evaluate(self, scan: ScanResult):
        if self.condition(scan):
            return self.recommendations
        return []


def default_rules() -> List[Rule]:
    rules: List[Rule] = []

    # If HTTP ports found -> run gobuster, nuclei, whatweb
    def http_condition(scan: ScanResult) -> bool:
        for p in scan.ports:
            if p.port in (80, 443, 8080, 8443):
                return True
        return False

    rules.append(
        Rule(
            name="http-enum",
            condition=http_condition,
            recommendations=[
                Recommendation(tool="gobuster", reason="HTTP service discovered", confidence=0.9),
                Recommendation(tool="nuclei", reason="HTTP service discovered", confidence=0.85),
                Recommendation(tool="whatweb", reason="HTTP service discovered", confidence=0.6),
            ],
        )
    )

    # If port 445 found -> enum4linux, crackmapexec
    def smb_condition(scan: ScanResult) -> bool:
        return any(p.port == 445 for p in scan.ports)

    rules.append(
        Rule(
            name="smb-enum",
            condition=smb_condition,
            recommendations=[
                Recommendation(tool="enum4linux", reason="SMB port open", confidence=0.9),
                Recommendation(tool="crackmapexec", reason="SMB port open", confidence=0.75),
            ],
        )
    )

    # LDAP -> BloodHound collector
    def ldap_condition(scan: ScanResult) -> bool:
        return any(p.port in (389, 636) for p in scan.ports)

    rules.append(
        Rule(
            name="ldap-enum",
            condition=ldap_condition,
            recommendations=[Recommendation(tool="bloodhound-collector", reason="LDAP service found", confidence=0.9)],
        )
    )

    return rules
