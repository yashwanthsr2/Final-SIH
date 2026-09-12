# CODEZILLA modern-data plan

## Selected modern source
**UWF-ZeekDataSum2025-1** is the primary modern benchmark because it contains benign traffic plus multiple MITRE ATT&CK tactics. **UWF-ZeekDataSum2025-2** can be used as an additional holdout after the first run.

## What is trained here
A separate, compact `HistGradientBoostingClassifier` uses portable Zeek behavioural metadata. IP addresses and timestamps are deliberately excluded from the model to avoid identity/time leakage and to keep the detector portable.

## What is NOT changed
The current production models for DDoS, C2, DNS and encrypted traffic remain untouched. The 2025 model is an auxiliary modern benchmark until its metrics are inspected.

## Required final evidence
Do not report literature numbers as CODEZILLA numbers. After downloading the data and running the validator, report:
- accuracy
- precision
- recall
- F1
- ROC-AUC
- confusion matrix
- number of rows used
- exact feature list

A model is promoted into production only when its test behaviour is demonstrably useful and its feature contract can be mapped to the live pipeline without leakage.
