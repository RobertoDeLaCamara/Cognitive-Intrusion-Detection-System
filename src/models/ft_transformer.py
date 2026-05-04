"""FT-Transformer (Gorishniy et al., 2021) — minimal implementation matching
the unified ML-IDS supervised checkpoint at models/unified/unified_ft_transformer.pt.

Loading state_dict requires the class definition to be importable at the same
attribute path used during save, so this module exists as a stable home.
"""

from typing import Any, Dict

import torch
import torch.nn as nn


class FTTransformer(nn.Module):
    """Tabular feature tokenizer + Transformer encoder + classification head.

    Mirrors the architecture used in the unified-model Optuna sweep
    (notebooks/ft_transformer_optuna_sweep.py). Do not change without
    retraining — state_dict shapes are coupled.
    """

    def __init__(
        self,
        n_features: int,
        n_classes: int,
        d_token: int,
        n_blocks: int,
        n_heads: int,
        ff_factor: float,
        dropout: float,
    ) -> None:
        super().__init__()
        # Construct under no_grad: nn.TransformerEncoderLayer (and our own
        # tokenizer init) call nn.init.kaiming_uniform_, which requires
        # autograd to be off when the target tensors are leaf parameters.
        # We then re-enable grad on the parameters so training/finetuning still
        # works for any future consumer.
        with torch.no_grad():
            self.tokenizer_w = nn.Parameter(
                nn.init.kaiming_uniform_(torch.empty(n_features, d_token), a=5 ** 0.5)
            )
            self.tokenizer_b = nn.Parameter(torch.zeros(n_features, d_token))
            self.cls = nn.Parameter(
                nn.init.normal_(torch.empty(1, 1, d_token), std=0.02)
            )
            enc_layer = nn.TransformerEncoderLayer(
                d_model=d_token,
                nhead=n_heads,
                dim_feedforward=int(d_token * ff_factor),
                dropout=dropout,
                activation="gelu",
                batch_first=True,
                norm_first=True,
            )
            self.encoder = nn.TransformerEncoder(enc_layer, num_layers=n_blocks)
            self.norm = nn.LayerNorm(d_token)
            self.head = nn.Linear(d_token, n_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        tokens = x.unsqueeze(-1) * self.tokenizer_w + self.tokenizer_b
        cls = self.cls.expand(x.size(0), -1, -1)
        z = torch.cat([cls, tokens], dim=1)
        z = self.encoder(z)
        return self.head(self.norm(z[:, 0]))


# UNSW-NB15 label space used by the unified model.
# Order matches the numeric class index (0..9) produced by the model head.
UNIFIED_CLASS_LABELS = (
    "Benign",
    "Analysis",
    "Backdoor",
    "DoS",
    "Exploits",
    "Fuzzers",
    "Generic",
    "Reconnaissance",
    "Shellcode",
    "Worms",
)


def load_checkpoint(path: str, map_location: str = "cpu") -> Dict[str, Any]:
    """Load a unified-model checkpoint, returning the bundle dict.

    Expected keys: state_dict, config, n_features, n_classes, feature_names.
    """
    bundle = torch.load(path, map_location=map_location, weights_only=False)
    if "state_dict" not in bundle or "config" not in bundle:
        raise ValueError(
            f"{path}: not a unified FT-Transformer checkpoint "
            f"(missing state_dict / config). Keys: {list(bundle.keys())}"
        )
    return bundle


def build_from_checkpoint(bundle: Dict[str, Any]) -> FTTransformer:
    """Instantiate FTTransformer from a checkpoint bundle and load weights.

    Tolerates extra hyperparams in `config` (e.g. lr, weight_decay) that the
    architecture itself does not consume.
    """
    cfg = bundle["config"]
    model = FTTransformer(
        n_features=int(bundle["n_features"]),
        n_classes=int(bundle["n_classes"]),
        d_token=int(cfg["d_token"]),
        n_blocks=int(cfg["n_blocks"]),
        n_heads=int(cfg["n_heads"]),
        ff_factor=float(cfg["ff_factor"]),
        dropout=float(cfg["dropout"]),
    )
    model.load_state_dict(bundle["state_dict"], strict=True)
    model.eval()
    return model
