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
        """Render comprehensive training analysis with multiple detailed plots."""
        if len(self.episode_rewards) < 2:
            print("Not enough episodes to render comprehensive analysis")
            return

        # Set style for better plots
        plt.style.use('seaborn-v0_8')

        # Create main figure with subplots
        fig = plt.figure(figsize=(24, 18))
        fig.suptitle('Comprehensive MicroSegments Environment Training Analysis & Proof',
                     fontsize=20, fontweight='bold', y=0.98)

        # 1. Learning Curve - Rewards and Moving Average
        ax1 = plt.subplot(3, 4, 1)
        episodes = range(1, len(self.episode_rewards) + 1)
        window_size = min(10, len(self.episode_rewards) // 4)
        moving_avg = np.convolve(self.episode_rewards, np.ones(window_size) / window_size, mode='valid')
        ax1.plot(range(window_size, len(self.episode_rewards) + 1), moving_avg, 'purple', linewidth=2)
        ax1.set_title(f'Learning Curve (Moving Avg, window={window_size})')
        ax1.set_xlabel('Episode')
        ax1.set_ylabel('Average Reward')
        ax1.grid(True, alpha=0.3)

        # 2. Cumulative Rewards
        ax2 = plt.subplot(3, 4, 2)
        if self.episode_cumulative_rewards:
            ax2.plot(episodes, self.episode_cumulative_rewards, 'g-', linewidth=2)
            ax2.set_title('Cumulative Rewards', fontsize=12, fontweight='bold')
            ax2.set_xlabel('Episode')
            ax2.set_ylabel('Cumulative Reward')
            ax2.grid(True, alpha=0.3)

        # 3. Performance Metrics Evolution
        ax3 = plt.subplot(3, 4, 3)
        if self.detailed_episode_data:
            df = pd.DataFrame(self.detailed_episode_data)
            ax3.plot(df['episode'], df['avg_risk'], 'r-', label='Avg Risk', alpha=0.8)
            ax3.plot(df['episode'], df['avg_compliance'], 'g-', label='Avg Compliance', alpha=0.8)
            ax3.plot(df['episode'], df['avg_overhead'], 'b-', label='Avg Overhead', alpha=0.8)
            ax3.axhline(y=0.7, color='red', linestyle='--', alpha=0.5, label='Risk Threshold')
            ax3.set_title('System Metrics Evolution', fontsize=12, fontweight='bold')
            ax3.set_xlabel('Episode')
            ax3.set_ylabel('Score')
            ax3.legend()
            ax3.grid(True, alpha=0.3)

        # 4. Security Incidents Trend
        ax4 = plt.subplot(3, 4, 4)
        if self.security_incidents_history:
            ax4.plot(episodes[:len(self.security_incidents_history)],
                     self.security_incidents_history, 'ro-', markersize=4)
            ax4.set_title('Security Incidents per Episode', fontsize=12, fontweight='bold')
            ax4.set_xlabel('Episode')
            ax4.set_ylabel('Incidents Count')
            ax4.grid(True, alpha=0.3)

        # 5. Action Distribution Analysis
        ax5 = plt.subplot(3, 4, 5)
        if self.action_counts_per_episode:
            action_totals = np.sum(self.action_counts_per_episode, axis=0)
            action_names = ['No Action', 'Shuffle'] + [f'Isolate-{i}' for i in range(4)] + [f'Revoke-{i}' for i in
                                                                                            range(12)]
            colors = plt.cm.tab20(np.linspace(0, 1, 18))
            bars = ax5.bar(range(18), action_totals, color=colors, alpha=0.8)
            ax5.set_title('Total Action Distribution', fontsize=12, fontweight='bold')
            ax5.set_xlabel('Action Type')
            ax5.set_ylabel('Total Count')
            ax5.set_xticks(range(0, 18, 3))
            ax5.set_xticklabels([action_names[i] for i in range(0, 18, 3)], rotation=45)
            ax5.grid(True, alpha=0.3)

        # 6. Action Effectiveness
        ax6 = plt.subplot(3, 4, 6)
        if self.action_effectiveness:
            action_means = []
            action_labels = []
            for action, rewards in self.action_effectiveness.items():
                if len(rewards) > 0:
                    action_means.append(np.mean(rewards))
                    action_labels.append(f'Action {action}')

            if action_means:
                colors = plt.cm.viridis(np.linspace(0, 1, len(action_means)))
                bars = ax6.bar(range(len(action_means)), action_means, color=colors, alpha=0.8)
                ax6.set_title('Action Effectiveness (Avg Reward)', fontsize=12, fontweight='bold')
                ax6.set_xlabel('Action')
                ax6.set_ylabel('Average Reward')
                ax6.set_xticks(range(len(action_labels)))
                ax6.set_xticklabels(action_labels, rotation=45)
                ax6.grid(True, alpha=0.3)

        # 7. Risk Evolution (Last Episode)
        ax7 = plt.subplot(3, 4, 7)
        if self.risk_history and len(self.risk_history) > 0:
            last_episode_risks = self.risk_history[-1]
            timesteps = range(len(last_episode_risks))
            ax7.plot(timesteps, last_episode_risks, 'r-', linewidth=2, alpha=0.8)
            ax7.axhline(y=0.4, color='orange', linestyle='--', alpha=0.7, label='Low Risk')
            ax7.axhline(y=0.7, color='red', linestyle='--', alpha=0.7, label='High Risk')
            ax7.set_title('Risk Evolution (Last Episode)', fontsize=12, fontweight='bold')
            ax7.set_xlabel('Timestep')
            ax7.set_ylabel('Risk Level')
            ax7.legend()
            ax7.grid(True, alpha=0.3)

        # 8. Compliance Evolution (Last Episode)
        ax8 = plt.subplot(3, 4, 8)
        if self.compliance_history and len(self.compliance_history) > 0:
            last_episode_compliance = self.compliance_history[-1]
            timesteps = range(len(last_episode_compliance))
            ax8.plot(timesteps, last_episode_compliance, 'g-', linewidth=2, alpha=0.8)
            ax8.axhline(y=0.4, color='red', linestyle='--', alpha=0.7, label='Low Compliance')
            ax8.axhline(y=0.7, color='green', linestyle='--', alpha=0.7, label='Good Compliance')
            ax8.set_title('Compliance Evolution (Last Episode)', fontsize=12, fontweight='bold')
            ax8.set_xlabel('Timestep')
            ax8.set_ylabel('Compliance Score')
            ax8.legend()
            ax8.grid(True, alpha=0.3)

        # 9. Learning Milestones
        ax9 = plt.subplot(3, 4, 9)
        if self.learning_milestones:
            milestone_episodes, milestone_rewards = zip(*self.learning_milestones)
            ax9.scatter(milestone_episodes, milestone_rewards, c='gold', s=100,
                        marker='*', edgecolors='red', linewidth=2, alpha=0.8)
            ax9.plot(episodes, self.episode_rewards, 'b-', alpha=0.3)
            ax9.set_title('Learning Milestones (Best Rewards)', fontsize=12, fontweight='bold')
            ax9.set_xlabel('Episode')
            ax9.set_ylabel('Reward')
            ax9.grid(True, alpha=0.3)

        # 10. Convergence Analysis
        ax10 = plt.subplot(3, 4, 10)
        if len(self.convergence_window) > 5:
            convergence_std = np.std(list(self.convergence_window))
            convergence_episodes = range(max(1, len(episodes) - len(self.convergence_window) + 1), len(episodes) + 1)
            ax10.plot(convergence_episodes, list(self.convergence_window), 'purple', linewidth=2)
            ax10.axhline(y=np.mean(self.convergence_window), color='red', linestyle='--',
                         label=f'Mean: {np.mean(self.convergence_window):.2f}')
            ax10.set_title(f'Convergence Analysis (Std: {convergence_std:.2f})', fontsize=12, fontweight='bold')
            ax10.set_xlabel('Recent Episodes')
            ax10.set_ylabel('Reward')
            ax10.legend()
            ax10.grid(True, alpha=0.3)

        # 11. System Performance Heatmap
        ax11 = plt.subplot(3, 4, 11)
        if self.detailed_episode_data and len(self.detailed_episode_data) > 5:
            df = pd.DataFrame(self.detailed_episode_data)
            # Create performance matrix
            performance_metrics = df[['avg_risk', 'avg_compliance', 'avg_overhead', 'total_reward']].tail(10)
            performance_metrics_normalized = (performance_metrics - performance_metrics.min()) / (
                        performance_metrics.max() - performance_metrics.min())

            im = ax11.imshow(performance_metrics_normalized.T, cmap='RdYlGn', aspect='auto')
            ax11.set_title('Performance Heatmap (Last 10 Episodes)', fontsize=12, fontweight='bold')
            ax11.set_xlabel('Episode (Recent)')
            ax11.set_yticks(range(len(performance_metrics.columns)))
            ax11.set_yticklabels(['Risk', 'Compliance', 'Overhead', 'Reward'])
            plt.colorbar(im, ax=ax11, shrink=0.8)

        # 12. Training Statistics Summary
        ax12 = plt.subplot(3, 4, 12)
        ax12.axis('off')
        if self.detailed_episode_data:
            df = pd.DataFrame(self.detailed_episode_data)

            stats_text = f"""
            TRAINING SUMMARY STATISTICS
            ═══════════════════════════

            Episodes Completed: {len(self.episode_rewards)}

            REWARD ANALYSIS:
            • Best Episode Reward: {self.best_episode_reward:.2f}
            • Average Reward: {np.mean(self.episode_rewards):.2f}
            • Reward Std Dev: {np.std(self.episode_rewards):.2f}
            • Episodes Since Best: {self.episodes_since_improvement}

            PERFORMANCE METRICS:
            • Avg Risk Level: {df['avg_risk'].mean():.3f}
            • Avg Compliance: {df['avg_compliance'].mean():.3f}
            • Avg Overhead: {df['avg_overhead'].mean():.3f}

            LEARNING INDICATORS:
            • Learning Milestones: {len(self.learning_milestones)}
            • Convergence Std: {np.std(list(self.convergence_window)):.3f}
            • Total Security Incidents: {sum(self.security_incidents_history)}

            ACTION ANALYSIS:
            • Most Used Action: {max(self.action_frequency, key=self.action_frequency.get) if self.action_frequency else 'N/A'}
            • Action Diversity: {len(self.action_frequency)} unique actions
            • Total Actions Taken: {sum(self.action_frequency.values())}
            """

            ax12.text(0.05, 0.95, stats_text, transform=ax12.transAxes, fontsize=10,
                      verticalalignment='top', fontfamily='monospace',
                      bbox=dict(boxstyle="round,pad=0.5", facecolor="lightblue", alpha=0.8))

        plt.tight_layout()
        plt.subplots_adjust(top=0.94)
        plt.show()

    def render_advanced_analysis(self):
        """Render advanced analysis plots for deeper training insights."""
        if len(self.episode_rewards) < 5:
            print("Not enough episodes for advanced analysis")
            return

        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        fig.suptitle('Advanced Training Analysis - Deep Learning Insights', fontsize=16, fontweight='bold')

        # 1. Reward Distribution Analysis
        ax1 = axes[0, 0]
        ax1.hist(self.episode_rewards, bins=min(20, len(self.episode_rewards) // 2),
                 alpha=0.7, color='skyblue', edgecolor='black')
        ax1.axvline(np.mean(self.episode_rewards), color='red', linestyle='--',
                    label=f'Mean: {np.mean(self.episode_rewards):.2f}')
        ax1.axvline(np.median(self.episode_rewards), color='green', linestyle='--',
                    label=f'Median: {np.median(self.episode_rewards):.2f}')
        ax1.set_title('Reward Distribution')
        ax1.set_xlabel('Reward')
        ax1.set_ylabel('Frequency')
        ax1.legend()
        ax1.grid(True, alpha=0.3)

        # 2. Learning Velocity (Reward Improvement Rate)
        ax2 = axes[0, 1]
        if len(self.episode_rewards) > 1:
            reward_diff = np.diff(self.episode_rewards)
            episodes = range(2, len(self.episode_rewards) + 1)
            ax2.plot(episodes, reward_diff, 'b-', alpha=0.6, label='Episode-to-Episode Change')

            # Smooth the learning velocity
            if len(reward_diff) > 5:
                window = min(5, len(reward_diff) // 3)
                smooth_diff = np.convolve(reward_diff, np.ones(window) / window, mode='valid')
                smooth_episodes = range(2 + window // 2, len(self.episode_rewards) + 1 - window // 2)
                ax2.plot(smooth_episodes, smooth_diff, 'r-', linewidth=2, label='Smoothed Trend')

            ax2.axhline(y=0, color='gray', linestyle='--', alpha=0.5)
            ax2.set_title('Learning Velocity (Reward Changes)')
            ax2.set_xlabel('Episode')
            ax2.set_ylabel('Reward Change')
            ax2.legend()
            ax2.grid(True, alpha=0.3)

        # 3. Action Strategy Evolution
        ax3 = axes[0, 2]
        if self.action_counts_per_episode and len(self.action_counts_per_episode) > 3:
            # Show action preference changes over time
            action_probs = []
            for episode_actions in self.action_counts_per_episode:
                total_actions = np.sum(episode_actions)
                if total_actions > 0:
                    action_probs.append(episode_actions / total_actions)
                else:
                    action_probs.append(np.zeros(18))

            action_probs = np.array(action_probs)

            # Show evolution of top 5 actions
            top_actions = np.argsort(np.sum(action_probs, axis=0))[-5:]
            episodes = range(1, len(action_probs) + 1)

            colors = plt.cm.tab10(np.linspace(0, 1, 5))
            for i, action in enumerate(top_actions):
                ax3.plot(episodes, action_probs[:, action],
                         color=colors[i], label=f'Action {action}', linewidth=2)

            ax3.set_title('Action Strategy Evolution (Top 5 Actions)')
            ax3.set_xlabel('Episode')
            ax3.set_ylabel('Action Probability')
            ax3.legend()
            ax3.grid(True, alpha=0.3)

        # 4. Performance Stability Analysis
        ax4 = axes[1, 0]
        if self.detailed_episode_data:
            df = pd.DataFrame(self.detailed_episode_data)

            # Rolling standard deviation of rewards
            window_size = min(10, len(df) // 3)
            if len(df) > window_size:
                rolling_std = df['total_reward'].rolling(window=window_size).std()
                ax4.plot(df['episode'], rolling_std, 'purple', linewidth=2)
                ax4.set_title(f'Performance Stability (Rolling Std, window={window_size})')
                ax4.set_xlabel('Episode')
                ax4.set_ylabel('Reward Standard Deviation')
                ax4.grid(True, alpha=0.3)

        # 5. Risk-Reward Correlation
        ax5 = axes[1, 1]
        if self.detailed_episode_data:
            df = pd.DataFrame(self.detailed_episode_data)
            scatter = ax5.scatter(df['avg_risk'], df['total_reward'],
                                  c=df['episode'], cmap='viridis', alpha=0.7)
            ax5.set_title('Risk vs Reward Correlation')
            ax5.set_xlabel('Average Risk')
            ax5.set_ylabel('Total Reward')
            plt.colorbar(scatter, ax=ax5, label='Episode')
            ax5.grid(True, alpha=0.3)

        # 6. Compliance-Performance Relationship
        ax6 = axes[1, 2]
        if self.detailed_episode_data:
            df = pd.DataFrame(self.detailed_episode_data)
            scatter = ax6.scatter(df['avg_compliance'], df['total_reward'],
                                  c=df['security_incidents'], cmap='Reds', alpha=0.7)
            ax6.set_title('Compliance vs Performance')
            ax6.set_xlabel('Average Compliance')
            ax6.set_ylabel('Total Reward')
            plt.colorbar(scatter, ax=ax6, label='Security Incidents')
            ax6.grid(True, alpha=0.3)

        plt.tight_layout()
        plt.show()

    def generate_training_report(self):
        """Generate a comprehensive training report."""
        if len(self.episode_rewards) < 1:
            print("No training data available for report generation.")
            return

        print("=" * 80)
        print("COMPREHENSIVE TRAINING REPORT - MICROSEGMENTS ENVIRONMENT")
        print("=" * 80)

        # Basic Statistics
        print(f"\n📊 BASIC TRAINING STATISTICS:")
        print(f"   • Total Episodes: {len(self.episode_rewards)}")
        print(f"   • Episode Length: {self.episode_length} timesteps")
        print(f"   • Total Timesteps: {len(self.episode_rewards) * self.episode_length}")

        # Reward Analysis
        print(f"\n🎯 REWARD ANALYSIS:")
        print(f"   • Best Episode Reward: {self.best_episode_reward:.2f}")
        print(f"   • Average Reward: {np.mean(self.episode_rewards):.2f} ± {np.std(self.episode_rewards):.2f}")
        print(f"   • Median Reward: {np.median(self.episode_rewards):.2f}")
        print(f"   • Total Cumulative Reward: {sum(self.episode_rewards):.2f}")
        print(f"   • Episodes Since Best: {self.episodes_since_improvement}")

        # Performance Metrics
        if self.detailed_episode_data:
            df = pd.DataFrame(self.detailed_episode_data)
            print(f"\n📈 PERFORMANCE METRICS:")
            print(f"   • Average Risk Level: {df['avg_risk'].mean():.3f} ± {df['avg_risk'].std():.3f}")
            print(f"   • Average Compliance: {df['avg_compliance'].mean():.3f} ± {df['avg_compliance'].std():.3f}")
            print(f"   • Average Overhead: {df['avg_overhead'].mean():.3f} ± {df['avg_overhead'].std():.3f}")
            print(f"   • Risk Improvement: {(df['avg_risk'].iloc[0] - df['avg_risk'].iloc[-1]):.3f}")
            print(f"   • Compliance Improvement: {(df['avg_compliance'].iloc[-1] - df['avg_compliance'].iloc[0]):.3f}")

        # Security Analysis
        print(f"\n🔒 SECURITY ANALYSIS:")
        print(f"   • Total Security Incidents: {sum(self.security_incidents_history)}")
        print(f"   • Average Incidents per Episode: {np.mean(self.security_incidents_history):.2f}")
        print(f"   • Episodes with Zero Incidents: {self.security_incidents_history.count(0)}")

        # Action Analysis
        print(f"\n🎮 ACTION ANALYSIS:")
        if self.action_frequency:
            most_used_action = max(self.action_frequency, key=self.action_frequency.get)
            print(f"   • Most Used Action: {most_used_action} ({self.action_frequency[most_used_action]} times)")
            print(f"   • Unique Actions Used: {len(self.action_frequency)}/18")
            print(f"   • Total Actions Taken: {sum(self.action_frequency.values())}")

            # Action effectiveness
            if self.action_effectiveness:
                best_action = max(self.action_effectiveness,
                                  key=lambda x: np.mean(self.action_effectiveness[x]))
                print(
                    f"   • Most Effective Action: {best_action} (avg reward: {np.mean(self.action_effectiveness[best_action]):.2f})")

        # Learning Progress
        print(f"\n🧠 LEARNING PROGRESS:")
        print(f"   • Learning Milestones Achieved: {len(self.learning_milestones)}")
        if len(self.convergence_window) > 1:
            convergence_std = np.std(list(self.convergence_window))
            print(f"   • Recent Performance Stability (Std): {convergence_std:.3f}")
            print(f"   • Convergence Status: {'Converging' if convergence_std < 50 else 'Still Learning'}")

        # Improvement Trends
        if len(self.episode_rewards) > 10:
            early_avg = np.mean(self.episode_rewards[:len(self.episode_rewards) // 3])
            late_avg = np.mean(self.episode_rewards[-len(self.episode_rewards) // 3:])
            improvement = ((late_avg - early_avg) / abs(early_avg)) * 100 if early_avg != 0 else 0

            print(f"\n📊 LEARNING TRENDS:")
            print(f"   • Early Training Avg: {early_avg:.2f}")
            print(f"   • Recent Training Avg: {late_avg:.2f}")
            print(f"   • Overall Improvement: {improvement:.1f}%")

        print(f"\n" + "=" * 80)
        print("TRAINING PROOF SUMMARY:")
        print("✅ Reward progression tracked and visualized")
        print("✅ Performance metrics monitored across episodes")
        print("✅ Action strategy evolution documented")
        print("✅ Learning milestones and convergence analyzed")
        print("✅ Security and compliance improvements measured")
        print("=" * 80)

    def save_training_data(self, filename="training_data.npz"):
        """Save training data for later analysis."""
        np.savez(filename,
                 episode_rewards=self.episode_rewards,
                 action_history=self.action_history,
                 risk_history=self.risk_history,
                 compliance_history=self.compliance_history,
                 security_incidents=self.security_incidents_history,
                 detailed_data=self.detailed_episode_data)
        print(f"Training data saved to {filename}")

    def _reduce_risk_for_non_isolated_microservices(self, reduction_value):
        """Reduce risk for non-isolated microservices."""
        for microservice in self.gateway.microservices.values():
            if not microservice.is_isolated:
                microservice.Risk_assessment = max(0.0, microservice.Risk_assessment - reduction_value)

    def close(self):
        """Clean up the environment."""
        pass