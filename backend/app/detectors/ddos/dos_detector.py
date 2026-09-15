"""
CODEZILLA DDoS detector.

Wraps the packaged temporal HGB model and exposes
a simple detector interface for the team.
"""

from backend.app.ml.inference import run_inference


def predict(df, top_k: int = 5, **kwargs):
    return run_inference("dos_hgb.joblib", df, threshold=0.5, top_k=top_k)


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