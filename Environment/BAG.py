
from typing import  List
from dataclasses import dataclass


@dataclass
class Vulnerability:
    """Represents a vulnerability with CVSS score"""
    vuln_id: str
    cvss_score: float   # 0-10 scale
    description: str = ""

    def get_exploit_probability(self) -> float:
        """Convert CVSS score to exploit probability (Equation 3)"""
        return self.cvss_score / 10.0


@dataclass
class DefenseAction:
    """Represents a defense action (MTD, patching, etc.)"""
    action_id: str
    effectiveness: float  # 0-1 scale (0 = no mitigation, 1 = complete mitigation)
    decay_constant: float = 0.1  # λ value for time decay


class BAGRiskCalculator:
    """Bayesian Attack Graph Risk Calculator"""

    def __init__(self):
        self.default_vulnerabilities = {
            'web_service': [
                Vulnerability('CVE-2023-001', 7.5, 'SQL Injection'),
                Vulnerability('CVE-2023-002', 6.2, 'XSS'),
                Vulnerability('CVE-2023-003', 8.1, 'Authentication Bypass')
            ],
            'gateway': [
                Vulnerability('CVE-2023-004', 9.0, 'Remote Code Execution'),
                Vulnerability('CVE-2023-005', 5.3, 'Information Disclosure'),
                Vulnerability('CVE-2023-006', 7.8, 'Privilege Escalation')
            ]
        }

    @staticmethod
    def calculate_node_risk_without_dependencies(vulnerabilities: List[Vulnerability]) -> float:
        if not vulnerabilities:
            return 0.0

        risk_product = 1.0

        for vuln in vulnerabilities:
            base_prob = vuln.get_exploit_probability()


            # Calculate complement probability for OR logic
            risk_product *= (1 - base_prob)


        # Final risk probability (1 minus product of complements)
        return 1 - risk_product

    def calculate_node_risk_with_dependencies(self, local_vulnerabilities: List[Vulnerability],
                                              parent_risks: List[float]) -> float:
        # Calculate local risk
        local_risk = self.calculate_node_risk_without_dependencies(local_vulnerabilities)

        # Calculate parent risk propagation (OR scheme)
        parent_risk_product = 1.0
        for parent_risk in parent_risks:
            parent_risk_product *= (1 - parent_risk)

        parent_propagated_risk = 1 - parent_risk_product

        # Combine local and propagated risk
        total_risk = 1 - ( 1- local_risk) * (1- parent_propagated_risk)

        return total_risk
