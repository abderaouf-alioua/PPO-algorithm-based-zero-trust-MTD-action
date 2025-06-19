import random
import json
import numpy as np

import math

class User:
    def __init__(self, user_id: int, user_name: str, microservice_id: int, gateway_id: int) -> None:
        # identity of user
        self.user_id = user_id
        self.user_name = user_name
        self.microservice_id = microservice_id
        self.gateway_id = gateway_id
        self.ip_address = f"192.168.{gateway_id}.{user_id}"

        # user status
        self.is_active = True

        # user consumption metrics - Initialize with realistic values
        self.cpu_usage = 0.3
        self.memory_usage = 0.35
        self.bandwidth_usage = 0.29
        self.latency = 30
        self.overhead = (self.cpu_usage, self.bandwidth_usage, self.memory_usage, self.latency)
        # baslin performance
        self.cpu_baseline = 0.7  # 20% CPU as baseline
        self.memory_baseline = 0.7  # 15% memory as baseline
        self.bandwidth_baseline = 0.6  # 10% bandwidth as baseline
        self.latency_baseline = 65


        # history of user consumption metrics
        self.history_cpu = []
        self.history_memory = []
        self.history_bandwidth = []
        self.history_latency = []

        # Device Attributes of leaste privilege compliance score
        self.Device_attributes_Weight = {
            "connection_security": 0.13,
            "software_patch_level": 0.11,
            "system_patch_level": 0.10,
            "device_type": 0.09,
            "device_fingerprint": 0.08,
            "location_context": 0.07,
            "device_health": 0.06,
            "managed_device_status": 0.12,
            "service_usage_pattern": 0.08,
            "user_usage_pattern": 0.07
        }
    #     Network Attributes of leaste privilege compliance score
        self.Network_attributes_Weight = {
           'authentication_security': 0.4,
           'confidentiality_security': 0.35,
           'integrity_security': 0.25
        }
        self.User_attributes_Weight = {
            "authentication_factors": 0.17,
            "authentication_patterns": 0.14,
            "enterprise_presence": 0.13,
            "trust_history": 0.12,
            "input_behavior": 0.11,
            "service_usage": 0.09,
            "device_usage": 0.11,
            "access_time": 0.13
        }

        self.device_score = self.calculate_device_score()
        self.network_score = self.calculate_network_score()
        self.user_score = self.calculate_user_score()
        self.ILPCS = 0.3 * self.device_score + 0.3 * self.network_score + 0.4 * self.user_score
        k = 5  # sensitivity parameter
        individual_scores = [
           float(1 - math.exp(-k * abs((self.cpu_usage - self.cpu_baseline) / self.cpu_baseline))) ,
            float(1 - math.exp(-k * abs((self.memory_usage - self.memory_baseline) / self.memory_baseline))),
            float(1 - math.exp(-k * abs((self.bandwidth_usage - self.bandwidth_baseline) / self.bandwidth_baseline))),
            float(1 - math.exp(-k * abs((self.latency - self.latency_baseline) / self.latency_baseline)))
        ]
        self.CLPCS = float(1.0 - np.mean(individual_scores))
        # user privilege compliance score

        self.DLPCS = 0.8 * self.ILPCS + 0.2 * self.CLPCS
        self.olde_score = self.DLPCS


    def update_risk_score(self , alpha , delta):
        self.device_score = self.calculate_device_score()
        self.network_score = self.calculate_network_score()
        self.user_score = self.calculate_user_score()
        self.ILPCS = 0.3 * self.device_score + 0.3 * self.network_score + 0.4 * self.user_score
        k = 5  # sensitivity parameter
        individual_scores = [
            float(1 - math.exp(-k * abs((self.cpu_usage - self.cpu_baseline) / self.cpu_baseline))),
            float(1 - math.exp(-k * abs((self.memory_usage - self.memory_baseline) / self.memory_baseline))),
            float(1 - math.exp(-k * abs((self.bandwidth_usage - self.bandwidth_baseline) / self.bandwidth_baseline))),
            float(1 - math.exp(-k * abs((self.latency - self.latency_baseline) / self.latency_baseline)))
        ]
        self.CLPCS = float(1.0 - np.mean(individual_scores))

        # user privilege compliance score
        self.DLPCS = alpha * self.ILPCS + delta * self.CLPCS



    def update_metrics(self):
        """Update performance metrics with some randomness"""
        self.cpu_usage = max(0.0, min(1.0, self.cpu_usage + random.uniform(0.1, 0.2)))
        self.memory_usage = max(0.0, min(1.0, self.memory_usage + random.uniform(0.1, 0.2)))
        self.bandwidth_usage = max(0.0, min(1.0, self.bandwidth_usage + random.uniform(0.1, 0.2)))
        self.latency = max(1.0, self.latency + random.uniform(10,30 ))
        self.overhead = (self.cpu_usage, self.bandwidth_usage, self.memory_usage, self.latency)

    @staticmethod
    def load_network_data (json_file_path):
        try:
            with open(json_file_path, 'r') as file:
                data = json.load(file)
                return data['framework']['attributes']
        except FileNotFoundError:
            print(f"JSON file {json_file_path} not found")
            return None
        except json.JSONDecodeError:
            print(f"Error parsing JSON file {json_file_path}")
            return None

    def calculate_network_score(self):
        """Calculate network security score: network_score = w1*AUTH + w2*CONF + w3*INT"""
        # Load data from JSON file
        network_data = self.load_network_data('C:/Users/FANOOS INFO/Desktop/python_django/DRL_ZT_micro-segmentation/Zero-Trus_Policy(PIP)/Network_Attributs_Scors.json')
        if not network_data:
            print("Could not load network data from JSON file")
            return 0.0

        # Extract trust scores from JSON
        auth_scenarios = network_data['authentication_security']['authentication_scenarios']
        conf_scenarios = network_data['confidentiality_security']['confidentiality_scenarios']
        int_scenarios = network_data['integrity_security']['integrity_scenarios']

        # Randomly select scenarios
        auth_scenario = random.choice(auth_scenarios)
        conf_scenario = random.choice(conf_scenarios)
        int_scenario = random.choice(int_scenarios)

        # Get trust scores
        auth_score = auth_scenario['trust_score']
        conf_score = conf_scenario['trust_score']
        int_score = int_scenario['trust_score']

        # Calculate network score: w1*AUTH + w2*CONF + w3*INT
        w1 = self.Network_attributes_Weight['authentication_security']  # 0.4
        w2 = self.Network_attributes_Weight['confidentiality_security']  # 0.35
        w3 = self.Network_attributes_Weight['integrity_security']  # 0.25

        network_score = w1 * auth_score + w2 * conf_score + w3 * int_score

        return network_score

    def calculate_device_score (self):
        network_data = self.load_network_data('C:/Users/FANOOS INFO/Desktop/python_django/DRL_ZT_micro-segmentation/Zero-Trus_Policy(PIP)/Device_Attribute_Scors.json')
        if not network_data:
            print("Could not load network data from JSON file")
            return 0.0
        # Extract trust scores from JSON
        cs_scenarios = network_data['connection_security']['scenarios']
        psl_scenarios = network_data['software_patch_level']['scenarios']
        spl_scenarios = network_data['system_patch_level']['scenarios']
        dt_scenarios = network_data['device_type']['scenarios']
        df_scenarios = network_data['device_fingerprint']['scenarios']
        lc_scenarios = network_data['location_context']['scenarios']
        dh_scenarios = network_data['device_health']['scenarios']
        mds_scenarios = network_data['managed_device_status']['scenarios']
        sup_scenarios = network_data['service_usage_pattern']['scenarios']
        uup_scenarios = network_data['user_usage_pattern']['scenarios']

        # random choice

        cs_scenario = random.choice(cs_scenarios)
        psl_scenario = random.choice(psl_scenarios)
        spl_scenario = random.choice(spl_scenarios)
        dt_scenario = random.choice(dt_scenarios)
        df_scenario = random.choice(df_scenarios)
        lc_scenario = random.choice(lc_scenarios)
        dh_scenario = random.choice(dh_scenarios)
        mds_scenario = random.choice(mds_scenarios)
        sup_scenario = random.choice(sup_scenarios)
        upp_scenario = random.choice(uup_scenarios)

        # get trust score

        cs_score = cs_scenario['trust_score']
        psl_score = psl_scenario['trust_score']
        spl_score = spl_scenario['trust_score']
        dt_score = dt_scenario['trust_score']
        df_score = df_scenario['trust_score']
        lc_score = lc_scenario['trust_score']
        dh_score = dh_scenario['trust_score']
        mds_score = mds_scenario['trust_score']

        sup_score = sup_scenario['trust_score']
        upp_score = upp_scenario['trust_score']

        # get weight
        w1 = self.Device_attributes_Weight['connection_security']
        w2 = self.Device_attributes_Weight['software_patch_level']
        w3 = self.Device_attributes_Weight['system_patch_level']
        w4 = self.Device_attributes_Weight['device_type']
        w5 = self.Device_attributes_Weight['device_fingerprint']
        w6 = self.Device_attributes_Weight['location_context']
        w7 = self.Device_attributes_Weight['device_health']
        w8 = self.Device_attributes_Weight['managed_device_status']

        w10 = self.Device_attributes_Weight['service_usage_pattern']
        w11 = self.Device_attributes_Weight['user_usage_pattern']

        ns = w1 * cs_score + w2 * psl_score + w3 * spl_score + w4 * dt_score + w5 * df_score + w6 * lc_score + w7 * dh_score + w8 * mds_score + w10 * sup_score + w11 * upp_score

        return ns

    def calculate_user_score (self):
        network_data = self.load_network_data(
            'C:/Users/FANOOS INFO/Desktop/python_django/DRL_ZT_micro-segmentation/Zero-Trus_Policy(PIP)/User_Attribute_Scors.json')
        if not network_data:
            print("Could not load network data from JSON file")
            return 0.0

        # Extract trust scores from JSON
        af_scenarios = network_data['authentication_factors']['scenarios']
        ap_scenarios = network_data['authentication_patterns']['scenarios']
        ep_scenarios = network_data['enterprise_presence']['scenarios']
        th_scenarios = network_data['trust_history']['scenarios']
        ib_scenarios = network_data['input_behavior']['scenarios']
        su_scenarios = network_data['service_usage']['scenarios']
        du_scenarios = network_data['device_usage']['scenarios']
        at_scenarios = network_data['access_time']['scenarios']

        # random choice

        af_scenario = random.choice(af_scenarios)
        ap_scenario = random.choice(ap_scenarios)
        ep_scenario = random.choice(ep_scenarios)
        th_scenario = random.choice(th_scenarios)
        ib_scenario = random.choice(ib_scenarios)
        su_scenario = random.choice(su_scenarios)
        du_scenario = random.choice(du_scenarios)
        at_scenario = random.choice(at_scenarios)

        # get trust score
        af_score = af_scenario['trust_score']
        ap_score = ap_scenario['trust_score']
        ep_score = ep_scenario['trust_score']
        th_score = th_scenario['trust_score']
        ib_score = ib_scenario['trust_score']
        su_score = su_scenario['trust_score']
        du_score = du_scenario['trust_score']
        at_score = at_scenario['trust_score']

        # get weight
        w1 = self.User_attributes_Weight['authentication_factors']
        w2 = self.User_attributes_Weight['authentication_patterns']
        w3 = self.User_attributes_Weight['enterprise_presence']
        w4 = self.User_attributes_Weight['trust_history']
        w5 = self.User_attributes_Weight['input_behavior']
        w6 = self.User_attributes_Weight['service_usage']
        w7 = self.User_attributes_Weight['device_usage']
        w8 = self.User_attributes_Weight['access_time']
        ns = w1 * af_score + w2 * ap_score + w3 * ep_score + w4 * th_score + w5 * ib_score + w6 * su_score + w7 * du_score + w8 * at_score

        return ns



    def revoke_privilege(self):
        self.is_active = False
        self.cpu_usage = 0.0
        self.memory_usage = 0.0
        self.bandwidth_usage = 0.0
        self.latency = 0.0




    def get_user_status(self):
        """Get user status"""
        return {
            'user_id': self.user_id,
            'user_name': self.user_name,
            'privilege_compliance_score': self.DLPCS,
            'is_active': self.is_active,
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage,
            'bandwidth_usage': self.bandwidth_usage,
            'latency': self.latency
        }

    def reset(self):
        self.is_active = True
        self.cpu_usage = 0.18
        self.memory_usage = 0.14
        self.bandwidth_usage = 0.10
        self.latency = 30
        self.DLPCS = self.olde_score


