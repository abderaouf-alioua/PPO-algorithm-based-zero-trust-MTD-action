import gymnasium as gym
import numpy as np
from gymnasium import spaces
from Environment.SDPGateway import SDPGateway
from typing import Optional
import matplotlib.pyplot as plt
import random
from Environment.BAG import Vulnerability
from collections import defaultdict, deque
import pandas as pd


class MicroSegmentsEnv(gym.Env):
    """Enhanced Custom Environment for MicroSegmentation with comprehensive training visualization"""

    metadata = {"render_modes": ["human"], "render_fps": 30}

    def __init__(self):
        super(MicroSegmentsEnv, self).__init__()

        # Define observation space for 4 microservices and 12 users (3 per microservice)
        self.observation_space = spaces.Dict({
            'System_performance': spaces.Box(low=0.0, high=1.0, shape=(4, 4), dtype=np.float32),
            'Dynamic_least_privilege_scores': spaces.Box(low=0.0, high=1.0, shape=(4, 3), dtype=np.float32),
            'risk_assessment': spaces.Box(low=0.0, high=1.0, shape=(5,), dtype=np.float32),
        })

        # Define action space: Enhanced for 4 microservices and 12 users
        self.action_space = spaces.Discrete(18)

        # Initialize components
        self.gateway = SDPGateway(1, "Gateway-1", 1)

        # Add 4 microservices
        self.gateway.add_microservice(0, "auth-service")
        self.gateway.add_microservice(1, "user-service")
        self.gateway.add_microservice(2, "product-service")
        self.gateway.add_microservice(3, "payment-service")

        # Add 3 users per microservice (12 total users)
        user_id = 0
        for service_id in range(4):
            for user_num in range(3):
                self.gateway.add_user(user_id, f"user_{user_id}", service_id)
                user_id += 1

        # Environment parameters
        self.timestep = 0
        self.episode_length = 300
        self.shuffle_period = 100
        self.episode_count = 0
        self.add_vul = 20
        self.decrease_vul = 10
        self.security_incidents = 0

        # Enhanced tracking for comprehensive analysis
        # Training Performance Metrics
        self.episode_rewards = []
        self.episode_cumulative_rewards = []
        self.episode_lengths = []
        self.moving_avg_rewards = deque(maxlen=50)

        # Action Analysis
        self.action_history = []
        self.action_counts_per_episode = []
        self.action_effectiveness = defaultdict(list)  # Track reward per action type
        self.action_frequency = defaultdict(int)

        # State Metrics
        self.risk_history = []
        self.compliance_history = []
        self.overhead_history = []
        self.security_incidents_history = []

        # Detailed per-episode tracking
        self.detailed_episode_data = []

        # Current episode tracking
        self.current_episode_rewards = []
        self.current_episode_actions = []
        self.current_episode_risks = []
        self.current_episode_compliance = []
        self.current_episode_overhead = []
        self.current_episode_action_rewards = []

        # Learning indicators
        self.learning_milestones = []
        self.convergence_window = deque(maxlen=20)
        self.best_episode_reward = float('-inf')
        self.episodes_since_improvement = 0

        # Performance benchmarks
        self.risk_threshold_violations = []
        self.compliance_improvements = []
        self.efficiency_scores = []

        # Initialize state
        self.state = self.reset()[0]

    def global_compliance_score(self):
        """Calculate a weighted global compliance score for all active users."""
        active_users = []
        for ms in self.gateway.microservices.values():
            active_users.extend([user for user in ms.users.values() if user.is_active])

        if not active_users:
            return 0.54

        scores = np.array([user.DLPCS for user in active_users])
        # Use harmonic mean to penalize low scores
        harmonic_mean = len(scores) / np.sum(1.0 / (scores + 1e-5))
        return np.clip(harmonic_mean, 0.1, 0.98)

    def _simulate_user_decrease(self):
        """Simulate a decrease in user's DLPCS."""
        active_users = []
        for ms_id, microservice in self.gateway.microservices.items():
            for user_id, user in microservice.users.items():
                if user.is_active and user.DLPCS > 0.1:
                    active_users.append((ms_id, user_id, user))

        if not active_users:
            return

        ms_id, user_id, user = random.choice(active_users)
        current_score = user.DLPCS
        decrease_percentage = random.uniform(0.1, 0.3)
        decrease_amount = max(0.05, current_score * decrease_percentage)
        user.DLPCS = max(0.0, current_score - decrease_amount)

    def step(self, action):
        done = False
        info = {}

        # Store state before action for reward calculation
        prev_avg_risk = np.mean([m.Risk_assessment for m in self.gateway.microservices.values()])
        prev_avg_compliance = self.global_compliance_score()
        prev_avg_overhead = self._calculate_average_overhead()

        # Apply selected action
        action_info = self._execute_action(action)
        info.update(action_info)

        # Calculate state-based rewards
        reward = self._calculate_simple_state_reward(prev_avg_risk, prev_avg_compliance, prev_avg_overhead)

        # Track action effectiveness
        self.action_effectiveness[action].append(reward)
        self.action_frequency[action] += 1

        # Apply reconnaissance-based risk increase
        self._apply_reconnaissance_risk_increase()

        # Periodic IP shuffling
        if self.timestep % self.shuffle_period == 0:
            shuffle_reward = self._perform_periodic_shuffling()
            reward += shuffle_reward

        if self.timestep % self.decrease_vul == 0:
            self._simulate_user_decrease()
        if self.timestep % self.add_vul == 0:
            self._simulate_new_vulnerability()

        # Enhanced performance metrics tracking
        self._track_comprehensive_metrics(reward, action, prev_avg_risk, prev_avg_compliance, prev_avg_overhead)

        # Update state and check termination
        self.timestep += 1
        self.state = self._get_obs()

        if self.timestep >= self.episode_length:
            done = True
            self._finalize_comprehensive_episode_tracking()

        # Current state metrics for info
        current_risk = np.mean([m.Risk_assessment for m in self.gateway.microservices.values()])
        current_compliance = self.global_compliance_score()
        current_overhead = self._calculate_average_overhead()

        info.update({
            'avg_risk': current_risk,
            'avg_compliance': current_compliance,
            'avg_overhead': current_overhead,
            'security_incidents': self.security_incidents,
            'shuffle_period': self.shuffle_period,
            'timestep': self.timestep,
            'risk_improvement': prev_avg_risk - current_risk,
            'compliance_improvement': current_compliance - prev_avg_compliance
        })

        return self.state, reward, done, False, info

    def _track_comprehensive_metrics(self, reward, action, prev_risk, prev_compliance, prev_overhead):
        """Track comprehensive metrics for detailed analysis."""
        current_risk = np.mean([m.Risk_assessment for m in self.gateway.microservices.values()])
        current_compliance = self.global_compliance_score()
        current_overhead = self._calculate_average_overhead()

        # Update current episode tracking
        self.current_episode_rewards.append(reward)
        self.current_episode_actions.append(action)
        self.current_episode_risks.append(current_risk)
        self.current_episode_compliance.append(current_compliance)
        self.current_episode_overhead.append(current_overhead)
        self.current_episode_action_rewards.append((action, reward))

        # Track specific improvements
        if current_risk < prev_risk:
            self.risk_threshold_violations.append(False)
        else:
            self.risk_threshold_violations.append(current_risk > 0.7)

        if current_compliance > prev_compliance:
            self.compliance_improvements.append(current_compliance - prev_compliance)

        # Calculate efficiency score (reward per overhead)
        if current_overhead > 0:
            efficiency = reward / current_overhead
            self.efficiency_scores.append(efficiency)

    def _finalize_comprehensive_episode_tracking(self):
        """Comprehensive episode finalization with detailed analysis."""
        total_reward = np.sum(self.current_episode_rewards)

        # Basic episode metrics
        self.episode_rewards.append(total_reward)
        self.episode_lengths.append(len(self.current_episode_rewards))
        self.moving_avg_rewards.append(total_reward)

        # Action analysis
        action_counts = np.bincount(self.current_episode_actions, minlength=18)
        self.action_counts_per_episode.append(action_counts)
        self.action_history.append(self.current_episode_actions.copy())

        # State evolution
        self.risk_history.append(self.current_episode_risks.copy())
        self.compliance_history.append(self.current_episode_compliance.copy())
        self.overhead_history.append(self.current_episode_overhead.copy())
        self.security_incidents_history.append(self.security_incidents)

        # Detailed episode data
        episode_data = {
            'episode': self.episode_count,
            'total_reward': total_reward,
            'avg_reward': np.mean(self.current_episode_rewards),
            'avg_risk': np.mean(self.current_episode_risks),
            'avg_compliance': np.mean(self.current_episode_compliance),
            'avg_overhead': np.mean(self.current_episode_overhead),
            'final_risk': self.current_episode_risks[-1] if self.current_episode_risks else 0,
            'final_compliance': self.current_episode_compliance[-1] if self.current_episode_compliance else 0,
            'security_incidents': self.security_incidents,
            'unique_actions': len(set(self.current_episode_actions)),
            'most_used_action': max(set(self.current_episode_actions), key=self.current_episode_actions.count),
            'risk_variance': np.var(self.current_episode_risks),
            'compliance_variance': np.var(self.current_episode_compliance)
        }
        self.detailed_episode_data.append(episode_data)

        # Learning progress tracking
        if total_reward > self.best_episode_reward:
            self.best_episode_reward = total_reward
            self.episodes_since_improvement = 0
            self.learning_milestones.append((self.episode_count, total_reward))
        else:
            self.episodes_since_improvement += 1

        # Convergence analysis
        self.convergence_window.append(total_reward)

        # Calculate cumulative rewards
        if len(self.episode_cumulative_rewards) == 0:
            self.episode_cumulative_rewards.append(total_reward)
        else:
            self.episode_cumulative_rewards.append(self.episode_cumulative_rewards[-1] + total_reward)

    def _simulate_new_vulnerability(self):
        """Add a new vulnerability to a random microservice."""
        ms_id = random.randint(0, 3)
        ms = self.gateway.microservices[ms_id]
        vuln = Vulnerability(
            f"CVE-{random.randint(2023, 2030)}-{random.randint(1000, 9999)}",
            random.randint(1, 5),
            "Simulated Attack Vulnerability"
        )
        ms.add_vulnerability(vuln)

    def _apply_reconnaissance_risk_increase(self):
        """Increase risk from attacker reconnaissance."""
        for ms in self.gateway.microservices.values():
            if ms.is_active and not ms.is_isolated:
                ms.Risk_assessment = min(1.0, ms.Risk_assessment + 0.012)
            elif ms.is_isolated:
                ms.Risk_assessment = min(1.0, ms.Risk_assessment + 0.019)

    def _perform_periodic_shuffling(self):
        """Periodic shuffling with risk reduction."""
        shuffle_reward = 0
        for ms in self.gateway.microservices.values():
            if ms.is_active:
                old_risk = ms.Risk_assessment
                ms.shuffle_ip()
                risk_reduction = min(0.4, old_risk * 0.5)
                ms.Risk_assessment = max(0.1, ms.Risk_assessment - risk_reduction)
                ms.update_metrics()
                shuffle_reward += risk_reduction * 30
        return shuffle_reward

    def _execute_action(self, action):
        """Execute action with enhanced rewards."""
        info = {'action_type': 'unknown'}

        avg_risk = np.mean([m.Risk_assessment for m in self.gateway.microservices.values()])
        avg_compliance = self.global_compliance_score()

        if action == 0:  # No action
            info['action_type'] = 'no_action'

        elif action == 1:  # Adjust shuffling period
            if avg_risk > 0.65 or avg_compliance < 0.35:
                self.shuffle_period = max(5, self.shuffle_period - 40)
            elif avg_risk < 0.3 and avg_compliance > 0.7:
                self.shuffle_period = min(100, self.shuffle_period + 5)
            info['action_type'] = 'shuffle_adjustment'

        elif action in [2, 3, 4, 5]:  # Isolate microservices (0-3)
            service_id = action - 2
            ms = self.gateway.microservices[service_id]

            if ms.Risk_assessment > 0.7:
                if not ms.is_isolated:
                    self.gateway.isolate_microservice(service_id)
                    ms.Risk_assessment = max(0.1, ms.Risk_assessment - 0.25)
                    self._reduce_risk_for_non_isolated_microservices(0.09)
                    ms.update_metrics()
            info['action_type'] = f'isolate_service_{service_id}'

        elif action in range(6, 18):  # Revoke user privileges (users 0-11)
            user_id = action - 6
            target_user = None
            target_service_id = None

            for service_id, ms in self.gateway.microservices.items():
                if user_id in ms.users:
                    target_user = ms.users[user_id]
                    target_service_id = service_id
                    break

            if target_user:
                if target_user.DLPCS < 0.4:
                    if target_user.is_active:
                        self.gateway.revoke_user(user_id)
                        for u in self.gateway.microservices[target_service_id].users.values():
                            if u.is_active and u.user_id != user_id:
                                u.DLPCS = min(1.0, u.DLPCS + 0.15)
                        self.reduce_score()
            info['action_type'] = f'revoke_user_{user_id}'

        return info

    def reduce_score(self):
        """Reduce compliance scores for all microservices."""
        for ms in self.gateway.microservices.values():
            ms.reduce_compliance()

    def _calculate_simple_state_reward(self, prev_risk, prev_compliance, prev_overhead):
        """State-based reward using utility function."""
        current_risk = np.mean([m.Risk_assessment for m in self.gateway.microservices.values()])
        current_compliance = self.global_compliance_score()
        current_overhead = self._calculate_average_overhead()

        # Calculate utility-based reward
        reward = (0.8 * ((1 - current_risk) * current_compliance) - 0.2 * (1 - current_overhead)) * 100

        # Additional penalty for high-risk scenarios
        if current_risk > 0.8 or current_compliance < 0.2:
            self.security_incidents += 1
            reward -= 30

        return reward

    def _calculate_average_overhead(self):
        """Calculate average system overhead."""
        overhead_values = []
        for ms in self.gateway.microservices.values():
            if ms.is_active:
                overhead_values.extend([ms.cpu_usage, ms.memory_usage, ms.bandwidth_usage])
        return np.mean(overhead_values) if overhead_values else 0.5

    def _get_obs(self):
        """Get observation with updated structure for 4 microservices and 12 users."""
        # System performance: 4 microservices x 4 metrics
        system_performance = np.zeros((4, 4), dtype=np.float32)
        for i, ms in enumerate(self.gateway.microservices.values()):
            system_performance[i] = [ms.cpu_usage, ms.memory_usage, ms.bandwidth_usage,
                                     ms.latency / 200.0]

        # Dynamic least privilege scores: 4 microservices x 3 users each
        privilege_scores = np.zeros((4, 3), dtype=np.float32)
        for service_id, ms in self.gateway.microservices.items():
            user_scores = [user.DLPCS for user in ms.users.values()]
            for j in range(min(3, len(user_scores))):
                privilege_scores[service_id, j] = user_scores[j]

        # Risk assessment: 4 microservices + 1 gateway = 5 total
        risk_scores = np.zeros(5, dtype=np.float32)
        for i, ms in enumerate(self.gateway.microservices.values()):
            risk_scores[i] = ms.Risk_assessment
        risk_scores[4] = self.gateway.gateway_risk_assessment

        return {
            'System_performance': system_performance,
            'Dynamic_least_privilege_scores': privilege_scores,
            'risk_assessment': risk_scores,
        }

    def reset(self, seed: Optional[int] = None, options: Optional[dict] = None):
        """Enhanced reset with better state initialization for 4 microservices."""
        # Finalize previous episode if needed
        if hasattr(self, 'current_episode_rewards') and len(self.current_episode_rewards) > 0:
            self._finalize_comprehensive_episode_tracking()

        # Reset episode-specific variables
        self.timestep = 0
        self.security_incidents = 0
        self.episode_count += 1
        self.current_episode_rewards = []
        self.current_episode_actions = []
        self.current_episode_risks = []
        self.current_episode_compliance = []
        self.current_episode_overhead = []
        self.current_episode_action_rewards = []
        self.shuffle_period = 100

        # Reset gateway components
        for ms in self.gateway.microservices.values():
            ms.cpu_usage = np.random.uniform(0.2, 0.6)
            ms.memory_usage = np.random.uniform(0.2, 0.6)
            ms.bandwidth_usage = np.random.uniform(0.1, 0.5)
            ms.latency = np.random.uniform(8, 15)

        self.gateway.gateway_risk_assessment = self.gateway.risk_calculator.calculate_node_risk_without_dependencies(
            self.gateway.vulnerabilities
        )

        # Reset all microservices
        for ms in self.gateway.microservices.values():
            ms.reset()
            ms.Risk_assessment = ms.risk_calculator.calculate_node_risk_with_dependencies(
                ms.vulnerabilities,
                [self.gateway.gateway_risk_assessment]
            )

            # Reset all users in this microservice
            for user in ms.users.values():
                user.reset()

            # Recalculate microservice performance
            ms.calculate_performance_after_add_user()

        self.state = self._get_obs()

        info = {
            'episode_count': self.episode_count,
            'reset_reason': 'manual_reset',
            'active_microservices': sum(1 for ms in self.gateway.microservices.values() if ms.is_active),
            'total_users': sum(len(ms.users) for ms in self.gateway.microservices.values()),
            'active_users': sum(len([u for u in ms.users.values() if u.is_active])
                                for ms in self.gateway.microservices.values())
        }

        return self.state, info

    def render(self, mode='human'):
        """Enhanced rendering with comprehensive training proof plots."""
        if mode == 'human':
            self.render_comprehensive_training_analysis()

    def render_comprehensive_training_analysis(self):
        """Render only two plots: Isolation impact on risk and Revoke impact on compliance"""
        # Create figure
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        fig.suptitle('Security Action Impact Analysis', fontsize=16, fontweight='bold')

        # 1. Isolation Action Impact on Risk (last episode)
        if self.risk_history and len(self.risk_history) > 0:
            last_episode_risks = self.risk_history[-1]
            timesteps = range(len(last_episode_risks))
            ax1.plot(timesteps, last_episode_risks, 'r-', linewidth=2, alpha=0.8, label='Risk Level')

            # Mark isolation actions (actions 2-5)
            if self.action_history and len(self.action_history) > 0:
                last_episode_actions = self.action_history[-1]
                isolation_timesteps = [i for i, action in enumerate(last_episode_actions) if action in [2, 3, 4, 5]]
                isolation_risks = [last_episode_risks[i] for i in isolation_timesteps]

                # Add markers for isolation actions
                ax1.scatter(isolation_timesteps, isolation_risks, c='blue', s=80, marker='o',
                            edgecolors='white', zorder=5, label='Isolation Action')

                # Annotate action type
                for i, t in enumerate(isolation_timesteps):
                    service_id = last_episode_actions[t] - 2
                    ax1.annotate(f'Isolate MS-{service_id}', (t, isolation_risks[i]),
                                 xytext=(t + 2, isolation_risks[i] + 0.05),
                                 arrowprops=dict(arrowstyle='->', color='blue', alpha=0.7))

            ax1.set_title('Isolation Actions: Impact on Risk Assessment', fontsize=12, fontweight='bold')
            ax1.set_xlabel('Timestep')
            ax1.set_ylabel('Risk Level')
            ax1.grid(True, alpha=0.3)
            ax1.legend()
        else:
            ax1.set_title('Risk Data Not Available', fontsize=12)
            ax1.set_axis_off()

        # 2. Revoke Action Impact on Compliance
        if self.compliance_history and len(self.compliance_history) > 0:
            last_episode_compliance = self.compliance_history[-1]
            timesteps = range(len(last_episode_compliance))
            ax2.plot(timesteps, last_episode_compliance, 'g-', linewidth=2, alpha=0.8, label='Compliance Score')

            # Mark revoke actions (actions 6-17)
            if self.action_history and len(self.action_history) > 0:
                last_episode_actions = self.action_history[-1]
                revoke_timesteps = [i for i, action in enumerate(last_episode_actions) if 6 <= action <= 17]
                revoke_compliance = [last_episode_compliance[i] for i in revoke_timesteps]

                # Add markers for revoke actions
                ax2.scatter(revoke_timesteps, revoke_compliance, c='red', s=80, marker='s',
                            edgecolors='white', zorder=5, label='Revoke Action')

                # Annotate action type
                for i, t in enumerate(revoke_timesteps):
                    user_id = last_episode_actions[t] - 6
                    ax2.annotate(f'Revoke U-{user_id}', (t, revoke_compliance[i]),
                                 xytext=(t + 2, revoke_compliance[i] - 0.05),
                                 arrowprops=dict(arrowstyle='->', color='red', alpha=0.7))

            ax2.set_title('Revoke Actions: Impact on Compliance Score', fontsize=12, fontweight='bold')
            ax2.set_xlabel('Timestep')
            ax2.set_ylabel('Compliance Score')
            ax2.grid(True, alpha=0.3)
            ax2.legend()
        else:
            ax2.set_title('Compliance Data Not Available', fontsize=12)
            ax2.set_axis_off()

        plt.tight_layout(rect=[0, 0, 1, 0.95])  # Adjust for suptitle
        plt.show()
    def _reduce_risk_for_non_isolated_microservices(self, reduction_value):
        """Reduce risk for non-isolated microservices."""
        for microservice in self.gateway.microservices.values():
            if not microservice.is_isolated:
                microservice.Risk_assessment = max(0.0, microservice.Risk_assessment - reduction_value)

    def close(self):
        """Clean up the environment."""
        pass