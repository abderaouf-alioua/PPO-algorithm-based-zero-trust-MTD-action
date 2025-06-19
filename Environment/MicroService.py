import random
from typing import Dict
from Environment.User import User
from Environment.BAG import Vulnerability
from Environment.BAG import BAGRiskCalculator

import numpy as np


class MicroService:
    def __init__(self, service_id, name ,gateway_id):
        self.service_id = service_id
        self.name = name
        self.gateway_id = gateway_id
        self.ip_address = f"192.168.{gateway_id}.{service_id}"
        self.port = 8080
        self.is_isolated = False
        self.is_active = True
        self.Risk_assessment = 0
        self.users: Dict[str, User] = {}
        # Initialize with default values when no users
        self.cpu_usage = 0.0
        self.memory_usage = 0.0
        self.bandwidth_usage = 0.0
        self.latency = 0
        self.overhead = (self.cpu_usage, self.bandwidth_usage, self.memory_usage, self.latency)

        # history of performance
        self.cpu_usageH = []
        self.memory_usageH = []
        self.bandwidth_usageH = []
        self.latencyH = []

        self.performance_thresholds = {
            'cpu_warning': 0.7,
            'cpu_critical': 0.9,
            'memory_warning': 0.7,
            'memory_critical': 0.9,
            'latency_warning': 100,
            'latency_critical': 200
        }
        self.risk_calculator = BAGRiskCalculator()
        self.parent_gateway = None
        self.vulnerabilities = [
                Vulnerability('CVE-2023-001', 8.5, 'SQL Injection'),
                Vulnerability('CVE-2024-001', 9, 'gg Injection'),
            ]

    def compliance_score(self):
        """Calculate compliance score"""
        if not self.users:
            return random.uniform(0.6 , 0.7)

        return np.mean(us.DLPCS for us in self.users.values() if us.is_active)


    def shuffle_ip(self):
        """Change IP address for shuffling"""
        new_ip = f"192.168.1.{random.randint(101, 254)}"
        self.ip_address = new_ip
        return new_ip

    def update_risk_assessment(self):
        """Update risk assessment using BAG model"""
        parent_risks = []
        if self.parent_gateway:
            parent_risks = [self.parent_gateway.gateway_risk_assessment]

        self.Risk_assessment = self.risk_calculator.calculate_node_risk_with_dependencies(
            self.vulnerabilities,
            parent_risks,
        )
    def isolate(self):
        """Isolate the microservice"""
        self.is_isolated = True
        self.is_active = False
        for user in self.users.values():
            user.CLPCS = 0.0
    def reduce_compliance(self ):
        for ms in self.users.values():
            if ms.is_active:
                ms.DLPCS += 0.032



    def restore_connection(self):
        """Restore connection after isolation"""
        self.is_isolated = False
        self.is_active = True

    def add_vulnerability(self, vuln: Vulnerability):
        """Add a new vulnerability to the microservice"""
        self.vulnerabilities.append(vuln)
        self.update_risk_assessment()

    def update_metrics(self):
        """Update performance metrics with some randomness"""
        self.cpu_usage = max(0.0, min(1.0, self.cpu_usage + random.uniform(+0.05, 0.25)))
        self.memory_usage = max(0.0, min(1.0, self.memory_usage + random.uniform(+0.05, 0.32)))
        self.bandwidth_usage = max(0.0, min(1.0, self.bandwidth_usage + random.uniform(+0.05, 0.5)))
        self.latency = max(1.0, self.latency + random.uniform(+5, 20))
        self.overhead = (self.cpu_usage, self.bandwidth_usage, self.memory_usage, self.latency)

    def state_history(self, cpu_usage, memory_usage, bandwidth_usage, latency):
        self.cpu_usageH.append(cpu_usage)
        self.memory_usageH.append(memory_usage)
        self.bandwidth_usageH.append(bandwidth_usage)
        self.latencyH.append(latency)

    def reset(self):
        self.is_isolated = False
        self.ip_address = f"192.168.{self.gateway_id}.{self.service_id}"
        self.cpu_usageH = []
        self.memory_usageH = []
        self.bandwidth_usageH = []
        self.latencyH = []
        self.is_active = True
        self.Risk_assessment = 0
        self.vulnerabilities = [
            Vulnerability('CVE-2023-001',8, 'SQL Injection'),
            Vulnerability('CVE-2024-001', 9, 'gg Injection'),

        ]
    def update_alpha (self , a , b):
        for us in self.users.values():
            us.update_risk_score(a,b)

    def ms_status(self):
        return {
            'microservice_id': self.service_id,
            'name': self.name,
            'ip_address': self.ip_address,
            'port': self.port,
            'is_isolated': self.is_isolated,
            'is_active': self.is_active,
            'Risk_assessment': self.Risk_assessment,
            'overhead': self.overhead,
            'active_users': len([u for u in self.users.values() if u.is_active]),
            'total_users': len(self.users),
            'global_risk_score': np.mean([u.DLPCS for u in self.users.values()]),

        }

    def get_performance_analytics(self) -> Dict:
        """Get detailed performance analytics"""
        if not self.cpu_usageH:
            return {"error": "No performance data available"}

        return {
            'cpu_stats': {
                'current': self.cpu_usage,
                'average': sum(self.cpu_usageH) / len(self.cpu_usageH),
                'peak': max(self.cpu_usageH),
                'min': min(self.cpu_usageH)
            },
            'memory_stats': {
                'current': self.memory_usage,
                'average': sum(self.memory_usageH) / len(self.memory_usageH),
                'peak': max(self.memory_usageH),
                'min': min(self.memory_usageH)
            },
            'latency_stats': {
                'current': self.latency,
                'average': sum(self.latencyH) / len(self.latencyH),
                'peak': max(self.latencyH),
                'min': min(self.latencyH)
            },
            'bandwidth_stats': {
                'current': self.bandwidth_usage,
                'average': sum(self.bandwidth_usageH) / len(self.bandwidth_usageH),
                'peak': max(self.bandwidth_usageH),
                'min': min(self.bandwidth_usageH)
            }
        }


    def calculate_performance_after_add_user(self):
        self.cpu_usage = np.mean([cpu.cpu_usage for cpu in self.users.values()])
        self.memory_usage = np.mean([mem.memory_usage for mem in self.users.values()])
        self.bandwidth_usage = np.mean([ban.bandwidth_usage for ban in self.users.values()])
        self.latency = np.mean([lat.latency for lat in self.users.values()])

        self.overhead = (self.cpu_usage, self.bandwidth_usage, self.memory_usage, self.latency)




