import numpy as np
import pandas as pd
from geopy.distance import geodesic
import os
import json
from scipy.stats import beta

class MarkovDeviceModel:
    def __init__(self, base_device):
        self.devices = [base_device]
        self.transitions = {base_device: {base_device: 0.95, "new_device": 0.05}}
        
    def next_device(self):
        current = self.devices[-1]
        next_dev = np.random.choice(
            list(self.transitions[current].keys()),
            p=list(self.transitions[current].values())
        )
        if next_dev == "new_device":
            new_dev = f"device_{len(self.devices)}"
            self.transitions[new_dev] = {new_dev: 0.9, "new_device": 0.1}
            self.transitions[current][new_dev] = self.transitions[current].pop("new_device")
            next_dev = new_dev
        self.devices.append(next_dev)
        return next_dev

def generate_behavior_data(users=20000, sessions_per_user=50, output_dir="../data"):
    os.makedirs(output_dir, exist_ok=True)
    all_sessions = []
    
    for user_id in range(users):
        # Determine user archetype
        arch_type = np.random.choice(['staff', 'admin', 'contractor'], 
                                    p=[0.7, 0.2, 0.1])
        
        # Archetype parameters
        params = {
            'staff': {'loc_variance': 5, 'device_change_prob': 0.05},
            'admin': {'loc_variance': 2, 'device_change_prob': 0.01},
            'contractor': {'loc_variance': 100, 'device_change_prob': 0.3}
        }[arch_type]
        
        # Base location and device
        base_location = (np.random.uniform(-90, 90), np.random.uniform(-180, 180))
        base_device = f"device_{user_id}_0"
        device_model = MarkovDeviceModel(base_device)
        
        # Generate sessions
        for session_idx in range(sessions_per_user):
            # Device simulation
            current_device = device_model.next_device()
            device_anomaly = int(current_device != base_device)
            
            # Location simulation
            offset = np.random.normal(0, params['loc_variance']/111, 2)
            lat = min(90, max(-90, base_location[0] + offset[0]))
            lon = min(180, max(-180, base_location[1] + offset[1]))
            location = (lat, lon)
            dist_km = geodesic(base_location, location).km
            location_anomaly = min(1, dist_km / 500)
            
            # Behavioral features
            time_anomaly = abs(np.random.normal(0, 40))
            action_entropy = beta.rvs(0.8, 0.8)
            ip_risk = beta.rvs(0.5, 5) if np.random.rand() < 0.1 else beta.rvs(5, 0.5)
            
            # Session entry
            all_sessions.append({
                'user_id': user_id,
                'user_type': arch_type,
                'time_anomaly': time_anomaly,
                'device_anomaly': device_anomaly,
                'location_anomaly': location_anomaly,
                'action_entropy': action_entropy,
                'ip_risk': ip_risk,
                'session_duration': max(60, np.random.normal(300, 120)),
                'is_anomaly': int(np.random.rand() < params['device_change_prob'])
            })
    
    # Create DataFrame and save
    df = pd.DataFrame(all_sessions)
    df['behavior_anomaly_score'] = (
        0.3 * (df['time_anomaly'] / 1440) +
        0.2 * df['device_anomaly'] +
        0.2 * df['location_anomaly'] +
        0.15 * df['action_entropy'] +
        0.15 * df['ip_risk']
    ).clip(0, 1)
    
    output_path = os.path.join(output_dir, "synthetic_behavior_data.parquet")
    df.to_parquet(output_path)
    print(f"Generated behavior data with {len(df)} sessions at {output_path}")
    
    # Optionally: load and merge keystroke features for each user/session
    keystroke_path = os.path.join(output_dir, '../keystroke_features.csv')
    if os.path.exists(keystroke_path):
        keystroke_df = pd.read_csv(keystroke_path)
        # Example: merge on user/session or aggregate as needed
        for session in all_sessions:
            kf = keystroke_df[keystroke_df['user'] == session['user_id']]
            if not kf.empty:
                session['avg_hold_time'] = kf['avg_hold_time'].mean()
                session['avg_flight_time'] = kf['avg_flight_time'].mean()
            else:
                session['avg_hold_time'] = 0
                session['avg_flight_time'] = 0

        # Convert back to DataFrame with merged features and recompute score
        df = pd.DataFrame(all_sessions)
        df['behavior_anomaly_score'] = (
            0.3 * (df['time_anomaly'] / 1440)
            + 0.2 * df['device_anomaly']
            + 0.2 * df['location_anomaly']
            + 0.15 * df['action_entropy']
            + 0.15 * df['ip_risk']
        ).clip(0, 1)
        df.to_parquet(output_path)
        print(f"Merged keystroke features into behavior data at {output_path}")

if __name__ == "__main__":
    generate_behavior_data()
