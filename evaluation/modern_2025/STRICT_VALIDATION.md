# Strict 2025 validation

The first validator used a random stratified row split. The resulting 1.0000 scores are not suitable as headline evidence because rows from the same traffic grouping can land in both train and test.

The current validator defaults to a leakage-resistant grouped evaluation:

- attack traffic is held out by tactic folder/group;
- benign traffic is divided into matching folds;
- the held-out attack group and held-out benign fold are never used for training that fold;
- all held-out predictions are aggregated into one out-of-group test result.

Use:

```powershell
python scripts\validate_2025_uwf.py --data data\modern_2025\UWF-ZeekDataSum25-1
```

The `--mode random` option exists only to reproduce the old comparison split:

```powershell
python scripts\validate_2025_uwf.py --data data\modern_2025\UWF-ZeekDataSum25-1 --mode random
```

For SIH evidence, use the **strict** results, not the random-split 1.0000 result.
