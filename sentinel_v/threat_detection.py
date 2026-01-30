import numpy as np
from sklearn.ensemble import IsolationForest

class ThreatDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
    
    def train(self, data):
        # Data: numpy array of features (e.g., packet sizes, timestamps)
        self.model.fit(data)
    
    def detect(self, new_data):
        # Returns -1 for anomalies, 1 for normal
        predictions = self.model.predict(new_data)
        return predictions

# Example usage
if __name__ == "__main__":
    # Simulated normal/anomalous network data
    normal_data = np.random.normal(100, 20, (100, 1))
    anomalous_data = np.random.normal(500, 100, (10, 1))
    train_data = np.vstack([normal_data, anomalous_data])
    detector = ThreatDetector()
    detector.train(train_data)
    test_data = np.array([[150], [600]])
    print(detector.detect(test_data))  # e.g., [1, -1]
