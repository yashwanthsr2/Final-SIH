# CODEZILLA — Modern 2025 Dataset Validation Report

## Dataset
**UWF-ZeekDataSum2025-1**

## Evaluation method
**grouped_out_of_group_cross_validation**

Rows used: **58,131**

The strict evaluation holds out traffic by source/tactic group and excludes IP addresses and timestamps from model features.

## Results
| Metric | Result |
|---|---:|
| Accuracy | **77.00%** |
| Precision | **99.99%** |
| Recall | **54.17%** |
| F1 | **70.27%** |
| ROC-AUC | **57.41%** |

### Confusion matrix
```text
[[28962, 2], [13368, 15799]]
```

## Production status
**AUXILIARY VALIDATION ONLY**

Do not use the earlier random-split 1.0000 result as headline evidence.
