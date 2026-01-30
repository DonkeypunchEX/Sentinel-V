import flwr as fl
from tensorflow import keras
import numpy as np

class AutonomousResponder:
    def __init__(self):
        self.model = keras.Sequential([
            keras.layers.Flatten(input_shape=(28, 28)),
            keras.layers.Dense(128, activation='relu'),
            keras.layers.Dense(10, activation='softmax')
        ])
        self.model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
    
    def train_federated(self):
        # Simulated client data
        (x_train, y_train), _ = keras.datasets.mnist.load_data()
        x_train, y_train = x_train[:5000] / 255.0, y_train[:5000]
        
        class Client(fl.client.NumPyClient):
            def get_parameters(self, config):
                return self.model.get_weights()
            
            def fit(self, parameters, config):
                self.model.set_weights(parameters)
                self.model.fit(x_train, y_train, epochs=1, batch_size=32)
                return self.model.get_weights(), len(x_train), {}
        
        fl.client.start_numpy_client(server_address="localhost:8080", client=Client())

# Run server separately: fl.server.start_server(...)
