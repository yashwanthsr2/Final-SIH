"""
CODEZILLA DDoS detector.

Wraps the packaged temporal HGB model and exposes
a simple detector interface for the team.
"""

from pathlib import Path
import sys

# Allow importing the shared predictor module
ROOT_DIR = Path(__file__).resolve().parents[2]

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.ml_predictor import predict


THREAT_CLASS = "DDoS"


def detect(
    feature_dataframe,
    top_k: int = 5
) -> list[dict]:
    """
    Run the DDoS detector.

    Parameters
    ----------
    feature_dataframe:
        DataFrame containing exactly the 62 temporal
        model features expected by the packaged model.

    top_k:
        Number of SHAP evidence features to return.

    Returns
    -------
    list[dict]
        Structured DDoS predictions.
    """

    results = predict(
        feature_dataframe,
        include_evidence=True,
        top_k=top_k
    )

    for result in results:
        result["threat_class"] = THREAT_CLASS

    return results