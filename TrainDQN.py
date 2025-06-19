from gymnasium import make
import warnings
warnings.simplefilter('ignore')
import os

from stable_baselines3 import DQN
from stable_baselines3 import PPO
from stable_baselines3.common.monitor import Monitor


from Environment.Register_Env import register


register('v1')
env = make('zero-trust-v1')
log_path = os.path.join('training', 'logs-micro-segments-v1')
os.makedirs(log_path, exist_ok=True)
env = Monitor(env, log_path)

# Reset environment
obs = env.reset()
done = False

# Create DQN model with optimized hyperparameters
# model = DQN(
#      'MultiInputPolicy', #for dict spaces
#     env,
#     learning_rate= 0.9,
#     buffer_size = 10000,
#     batch_size=64,
#     exploration_initial_eps=1,
#     exploration_fraction=0.5,
#
#     exploration_final_eps=0.02,
#     learning_starts= 2000,
#     train_freq=4,
#     gamma=0.9,
#     target_update_interval=1000,
#     verbose=1,
#     gradient_steps=1,
#     tensorboard_log=log_path,
# )
model = PPO(
     'MultiInputPolicy',  # Use MlpPolicy for Box spaces
    env,
    verbose=1,
    learning_rate=3e-4,
    n_steps=2048,
    batch_size=64,
    n_epochs=10,
    gamma=0.99,
    gae_lambda=0.95,
    clip_range=0.2,
    tensorboard_log="./ppo_microsegments_tensorboard/",
)

env.reset()
if hasattr(env, 'reset_count'):
    env.reset_count()

model.learn(total_timesteps=1000)

env.render()




