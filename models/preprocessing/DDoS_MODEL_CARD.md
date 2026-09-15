# CODEZILLA DDoS Temporal Detector

## Model

HistGradientBoostingClassifier

## Detection design

Temporal next-window DDoS detection.

Traffic is aggregated into 2-second windows.

The model uses current and past traffic behaviour to predict
whether the next 2-second window will contain attack traffic.

## Features

62 temporal/behavioural features.

Feature schema is stored in:

dos_feature_schema.json

## Decision threshold

0.80

The threshold was selected using validation data only.

## Validation performance

Precision: 0.9686
Recall:    0.9112
F1:        0.9390
FPR:       0.0407

## Final holdout test performance

Accuracy:  0.9075
Precision: 0.9625
Recall:    0.8800
F1:        0.9194
FPR:       0.0513

## Explainability

SHAP is used to identify features supporting or opposing
each prediction.

## Important limitation

This model specifically represents the DDoS temporal detection
component. It does not by itself detect all threat classes
described in the SIH problem statement.