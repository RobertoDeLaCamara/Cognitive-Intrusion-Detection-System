"""Custom sklearn-compatible transformers for the CNDS RF Pipeline.

These must live in an importable module (not in scripts/) so that joblib
can deserialise the Pipeline on any machine that has the package installed.
"""

import numpy as np
import pandas as pd

SKEW_THRESHOLD = 5.0


class ClipNegativeTransformer:
    """Clip negative values to 0 before log1p transform."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return np.clip(X, 0, None)

    def fit_transform(self, X, y=None):
        return self.fit(X, y).transform(X)

    def get_params(self, deep=True):
        return {}

    def set_params(self, **params):
        return self


class SelectiveLog1pTransformer:
    """Apply log1p only to columns identified as highly skewed during fit."""

    def __init__(self, threshold: float = SKEW_THRESHOLD):
        self.threshold = threshold
        self.skewed_cols_ = None

    def fit(self, X, y=None):
        df = pd.DataFrame(X)
        skewness = df.skew().abs()
        self.skewed_cols_ = skewness[skewness > self.threshold].index.tolist()
        return self

    def transform(self, X):
        X = np.array(X, dtype=np.float64)
        if self.skewed_cols_:
            X[:, self.skewed_cols_] = np.log1p(X[:, self.skewed_cols_])
        return X

    def fit_transform(self, X, y=None):
        return self.fit(X, y).transform(X)

    def get_params(self, deep=True):
        return {"threshold": self.threshold}

    def set_params(self, **params):
        for k, v in params.items():
            setattr(self, k, v)
        return self
