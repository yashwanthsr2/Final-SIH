from dataclasses import dataclass, field
from typing import Any


@dataclass
class EvidenceFeature:
    feature: str
    value: float
    contribution: float


@dataclass
class MLAlert:
    timestamp: str
    flow_id: str
    threat_class: str
    prediction: str
    model_score: float
    severity: str
    evidence: list[EvidenceFeature] = field(
        default_factory=list
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "flow_id": self.flow_id,
            "threat_class": self.threat_class,
            "prediction": self.prediction,
            "model_score": self.model_score,
            "severity": self.severity,
            "evidence": [
                {
                    "feature": item.feature,
                    "value": item.value,
                    "contribution": item.contribution
                }
                for item in self.evidence
            ]
        }