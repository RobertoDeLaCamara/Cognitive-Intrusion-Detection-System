"""LSTM Autoencoder architecture for temporal anomaly detection.

Shared between training (scripts/generate_demo_models.py) and inference
(src/engines/lstm_autoencoder.py) so that torch.load can resolve the class.
"""

import torch.nn as nn


class LSTMAutoencoder(nn.Module):
    def __init__(self, n_features=18, hidden_dim=64, latent_dim=32,
                 num_layers=2, dropout=0.2):
        super().__init__()
        self.seq_len = 20
        self.n_features = n_features
        self.encoder = nn.LSTM(
            input_size=n_features, hidden_size=hidden_dim,
            num_layers=num_layers,
            dropout=dropout if num_layers > 1 else 0,
            batch_first=True,
        )
        self.latent = nn.Linear(hidden_dim, latent_dim)
        self.decoder = nn.LSTM(
            input_size=latent_dim, hidden_size=hidden_dim,
            num_layers=num_layers,
            dropout=dropout if num_layers > 1 else 0,
            batch_first=True,
        )
        self.output_layer = nn.Linear(hidden_dim, n_features)

    def forward(self, x):
        enc_out, _ = self.encoder(x)
        latent = self.latent(enc_out)
        dec_out, _ = self.decoder(latent)
        return self.output_layer(dec_out)
