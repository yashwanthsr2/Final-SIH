from __future__ import annotations
import json
from pathlib import Path

def pct(x):
    return f"{100*float(x):.2f}%"

def main():
    root = Path(__file__).resolve().parents[1]
    metrics_path = root / "evaluation" / "modern_2025" / "output" / "uwf_2025_metrics.json"
    if not metrics_path.exists():
        raise SystemExit(f"Metrics file not found: {metrics_path}")
    data = json.loads(metrics_path.read_text(encoding="utf-8"))
    m = data.get("metrics", {})
    ev = data.get("evaluation", {})
    cm = m.get("confusion_matrix", [])
    rows = data.get("rows_used", 0)
    report = (
        "# CODEZILLA — Modern 2025 Dataset Validation Report\n\n"
        f"## Dataset\n**{data.get('dataset','UWF-ZeekDataSum2025-1')}**\n\n"
        f"## Evaluation method\n**{ev.get('evaluation_method','grouped_out_of_group_cross_validation')}**\n\n"
        f"Rows used: **{rows:,}**\n\n"
        "The strict evaluation holds out traffic by source/tactic group and excludes IP addresses and timestamps from model features.\n\n"
        "## Results\n| Metric | Result |\n|---|---:|\n"
        f"| Accuracy | **{pct(m.get('accuracy',0))}** |\n"
        f"| Precision | **{pct(m.get('precision',0))}** |\n"
        f"| Recall | **{pct(m.get('recall',0))}** |\n"
        f"| F1 | **{pct(m.get('f1',0))}** |\n"
        f"| ROC-AUC | **{pct(m.get('roc_auc',0))}** |\n\n"
        "### Confusion matrix\n```text\n" + str(cm) + "\n```\n\n"
        "## Production status\n**AUXILIARY VALIDATION ONLY**\n\n"
        "Do not use the earlier random-split 1.0000 result as headline evidence.\n"
    )
    out = root / "evaluation" / "modern_2025" / "output" / "FINAL_2025_VALIDATION_REPORT.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding='utf-8')
    print(f"Saved: {out}")

if __name__ == '__main__':
    main()
