import gymnasium as gym
from gymnasium.envs.registration import register as gym_register

def register(version='v0'):

    env_id = f'zero-trust-{version}'

    try:
        # Try to register the environment
        gym_register(
            id=env_id,
            entry_point='state3:MicroSegmentsEnv',
            max_episode_steps=200,
            reward_threshold=500.0,
        )
        print(f"environment {env_id} successfully registered")

    except gym.error.Error as e:
        # Environment already registered
        print(f"environment {env_id} already registered, skipping...")

    return env_id
