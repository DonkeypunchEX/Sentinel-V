"""Federated-learning response model (optional ``ml`` extra).

Requires tensorflow and flwr. Loaded lazily via
``sentinel_v.AutonomousResponder``; the dependency-light response engine
used by the core system lives in ``sentinel_v.response``.
"""

from typing import Any, Dict, List, Tuple

import flwr as fl
from tensorflow import keras


class AutonomousResponder:
    """Trains a shared response model across federated defense nodes."""

    def __init__(self) -> None:
        self.model = keras.Sequential(
            [
                keras.layers.Flatten(input_shape=(28, 28)),
                keras.layers.Dense(128, activation="relu"),
                keras.layers.Dense(10, activation="softmax"),
            ]
        )
        self.model.compile(
            optimizer="adam",
            loss="sparse_categorical_crossentropy",
            metrics=["accuracy"],
        )

    def train_federated(self, server_address: str = "localhost:8080") -> None:
        """Join a Flower federation round as a client."""
        (x_train, y_train), _ = keras.datasets.mnist.load_data()
        x_train, y_train = x_train[:5000] / 255.0, y_train[:5000]
        model = self.model

        class Client(fl.client.NumPyClient):
            """Flower client bound to this responder's model."""

            def get_parameters(self, config: Dict[str, Any]) -> List[Any]:
                weights: List[Any] = model.get_weights()
                return weights

            def fit(
                self, parameters: List[Any], config: Dict[str, Any]
            ) -> Tuple[List[Any], int, Dict[str, Any]]:
                model.set_weights(parameters)
                model.fit(x_train, y_train, epochs=1, batch_size=32)
                weights: List[Any] = model.get_weights()
                return weights, len(x_train), {}

        fl.client.start_numpy_client(server_address=server_address, client=Client())


# Run server separately: fl.server.start_server(...)
