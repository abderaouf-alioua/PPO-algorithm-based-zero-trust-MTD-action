from Environment.MicroService import MicroService
from Environment.User import User
from Environment.BAG import BAGRiskCalculator
from Environment.BAG import Vulnerability
import random
from typing import  Dict

class SDPGateway:
    def __init__(self, gateway_id, name , micro_segment_id):
        self.gateway_id = gateway_id
        self.micro_segment_id = micro_segment_id
        self.name = name
        self.ip_address = f"192.168.{gateway_id}.1"
        self.risk_calculator = BAGRiskCalculator()
        self.vulnerabilities = [Vulnerability('CVE-2023-004', 1, 'Remote Code Execution'),
                Vulnerability('CVE-2023-005', 1, 'Information Disclosure')]
        self.gateway_risk_assessment = self.risk_calculator.calculate_node_risk_without_dependencies(self.vulnerabilities)

        self.microservices: Dict[str, MicroService] = {}

    def add_user(self, user_id, user_name, service_id):
        """Add user to gateway"""
        if service_id not in self.microservices:
            print(f"Error: Microservice {service_id} not found")
            return False

        user = User(user_id, user_name, service_id, gateway_id=self.gateway_id)
        self.microservices[service_id].users[user_id] = user
        print(f"User {user_id} added to micro-service {service_id} with score {self.microservices[service_id].users[user_id].DLPCS}")
        return True

    def revoke_user(self, user_id):
        """Revoke user from gateway"""
        for service in self.microservices.values():
            if user_id in service.users:
                service.users[user_id].revoke_privilege()
                # print(f"User {user_id} revoked from micro-service {service.service_id}")
                break


    def add_microservice(self, service_id, service_name):
        """Add microservice to gateway"""
        microservice = MicroService(service_id, service_name, gateway_id=self.gateway_id)
        microservice.parent_gateway = self
        self.microservices[service_id] = microservice
        self.update_risk_assessment()
        print(f"Microservice {service_name} (ID: {service_id}) added to gateway")

    def update_risk_assessment(self):
        """Update gateway risk assessment (no dependencies - entry point)"""
        self.gateway_risk_assessment = self.risk_calculator.calculate_node_risk_without_dependencies(
            self.vulnerabilities,

        )

        # Update all dependent microservices
        for microservice in self.microservices.values():
            microservice.update_risk_assessment()

    def isolate_microservice(self, service_id):
        """Isolate microservice"""
        if service_id in self.microservices:
            self.microservices[service_id].isolate()




    def restore_microservice(self, service_id):
        """Restore connection after isolation"""
        if service_id in self.microservices:
            self.microservices[service_id].restore_connection()
            print(f"Microservice {service_id} connection restored")
        else:
            print(f"Microservice {service_id} not found")

    def shuffle_ip(self):
        """Change IP address for shuffling"""
        old_ip = self.ip_address
        new_ip = f"192.168.{random.randint(101, 254)}.1"
        self.ip_address = new_ip

        return new_ip

    def shuffle_ip_microservice(self, service_id):
        if service_id in self.microservices:
            new_ip = self.microservices[service_id].shuffle_ip()

            return new_ip
        else:

            return None

    def get_gateway_status(self):
        """Get gateway status"""
        active_ms = sum(1 for ms in self.microservices.values() if ms.is_active)
        total_users = sum(len(ms.users) for ms in self.microservices.values())
        active_users = sum(len([u for u in ms.users.values() if u.is_active])
                           for ms in self.microservices.values())

        return {
            'gateway_id': self.gateway_id,
            'name': self.name,
            'ip_address': self.ip_address,
            'total_microservices': len(self.microservices),
            'active_microservices': active_ms,
            'total_users': total_users,
            'active_users': active_users,
        }

    # def _update_user_metrics(self):
    #     """Update random user metrics"""
    #     import random
    #     updated_users = []
    #     for ms in self.microservices.values():
    #         if ms.users and random.random() > 0.5:
    #             user = random.choice(list(ms.users.values()))
    #             user.update_metrics()
    #             user.update_risk_score()
    #             updated_users.append(user.user_name)
    #             ms.calculate_performance_after_add_user()


# gateway = SDPGateway(1, "Gateway 1", 1)
# gateway.add_microservice(1, "Microservice 1")
# gateway.add_microservice(2, "Microservice 2")
# gateway.add_microservice(3, "Microservice 3")
#
#
# gateway.add_user(1 , f"User {1}", 1)
# gateway.add_user(2 , f"User {2}", 1)
# gateway.add_user(3 , f"User {3}", 1)
# gateway.add_user(4 , f"User {4}", 2)
# gateway.add_user(5 , f"User {5}", 2)
# gateway.add_user(6 , f"User {6}", 2)
# gateway.add_user(7 , f"User {7}", 3)
# for i in gateway.microservices.values():
#     i.calculate_performance_after_add_user()
#
#
# print(gateway.microservices[1].ms_status())
# print(gateway.microservices[2].ms_status())
# print(gateway.microservices[3].ms_status())
# gateway.microservices[1].users[1].update_metrics()
# for i in gateway.microservices.values():
#     i.calculate_performance_after_add_user()
# for j in gateway.microservices[1].users.values():
#     j.update_risk_score()
# print(gateway.microservices[1].ms_status())







