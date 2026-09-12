# CODEZILLA — Modern 2025 Dataset Validation Report

## Purpose
This report documents the independent modern-data validation layer for CODEZILLA. The 2025 benchmark is **not** being substituted for the existing production training datasets.

## Dataset
**UWF-ZeekDataSum25-1 (University of West Florida)**

## Evaluation design
- Attack traffic is held out by tactic/source group.
- Benign traffic is partitioned into matching folds.
- Held-out attack and benign groups are excluded from training for each fold.
- IP addresses and timestamps are excluded from model features.
- The earlier random row-split result of 1.0000 is **not** used as headline evidence.

## CODEZILLA result
| Metric | Result |
|---|---:|
| Accuracy | **77.00%** |
| Precision | **99.99%** |
| Recall | **54.17%** |
| F1 | **70.27%** |
| ROC-AUC | **57.41%** |
| Evaluation rows | **58,131** |

### Confusion matrix
```text
[[28962, 2],
 [13368, 15799]]
```

## Interpretation
The auxiliary model shows very high precision with moderate recall on grouped 2025 traffic. The ROC-AUC of 0.5741 indicates that this model should **not** be presented as a superior replacement for the existing production detectors.

## Production status
**AUXILIARY VALIDATION ONLY**

Current production detectors remain unchanged: DDoS, C2, DNS, and Encrypted traffic.

## Judge-safe wording
> CODEZILLA uses established benchmark datasets for core detector training and independently validates generalization on modern 2025 UWF Zeek traffic. Under grouped out-of-group evaluation, the auxiliary 2025 benchmark achieved 70.27% F1 with 99.99% precision.

Do not claim that this result is 99.99% accuracy, or that the 2025 auxiliary model is better than every existing detector.
