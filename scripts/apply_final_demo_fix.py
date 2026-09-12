from __future__ import annotations

from pathlib import Path
import re
import shutil
from datetime import datetime


ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "app" / "main.py"
BACKUP_DIR = ROOT / "backup_final_fix"
CSV_PATH = ROOT / "evaluation" / "packaging" / "verified_attack_input.csv"
SCHEMA_PATH = ROOT / "models" / "dos_feature_schema.json"

START_MARKER = "# DDOS VERIFIED DEMO"
END_MARKER = "# RUN ALL DEMO SCENARIOS"

NEW_BLOCK = r'''# ============================================================
# DDOS VERIFIED DEMO
#
# Final judge-safe implementation:
# - Uses the packaged, verified 62-feature CSV input.
# - Does NOT require pandas parquet/pyarrow for the dashboard demo.
# - Sends the sample through the same production DDoS ML pipeline.
# - Preserves all other routes, including live monitoring.
# ============================================================

@app.post(
    "/demo/ddos"
)
def run_ddos_demo():

    csv_path = (
        PROJECT_ROOT
        / "evaluation"
        / "packaging"
        / "verified_attack_input.csv"
    )

    schema_path = (
        PROJECT_ROOT
        / "models"
        / "dos_feature_schema.json"
    )

    if not csv_path.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                "Verified DDoS demo input not found: "
                + str(csv_path)
            ),
        )

    if not schema_path.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                "DDoS feature schema not found: "
                + str(schema_path)
            ),
        )

    try:
        ddos_data = pd.read_csv(csv_path)

        with open(
            schema_path,
            "r",
            encoding="utf-8",
        ) as f:
            dos_schema = json.load(f)

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to load verified DDoS demo input: "
                + str(exc)
            ),
        ) from exc

    if ddos_data.empty:
        raise HTTPException(
            status_code=500,
            detail="Verified DDoS demo input is empty.",
        )

    required_features = dos_schema.get("features", [])

    if len(required_features) != 62:
        raise HTTPException(
            status_code=500,
            detail=(
                "Expected exactly 62 DDoS features, found "
                f"{len(required_features)}."
            ),
        )

    missing_features = [
        feature
        for feature in required_features
        if feature not in ddos_data.columns
    ]

    if missing_features:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "DDoS feature mismatch",
                "missing_features": missing_features,
            },
        )

    selected = ddos_data.iloc[0]
    ddos_payload: Dict[str, float] = {}

    for feature in required_features:
        value = selected[feature]

        try:
            ddos_payload[feature] = float(value)
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=500,
                detail=(
                    f"Invalid DDoS value for '{feature}': {value}"
                ),
            )

    try:
        request = DetectionRequest(
            source="VERIFIED-DDOS-SAMPLE",
            time_window="VERIFIED-BENCHMARK-WINDOW",
            ddos_features=ddos_payload,
        )

        result = analyze_request(request)

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "DDoS detection failed: "
                + str(exc)
            ),
        ) from exc

    store_alert(result)

    result["demo_source"] = "verified_ddos_csv"
    result["demo_input"] = str(csv_path.relative_to(PROJECT_ROOT))

    if "score" in result:
        try:
            result["verified_model_score"] = float(result["score"])
        except (TypeError, ValueError):
            pass

    return result


# ============================================================
# RUN ALL DEMO SCENARIOS
#
# IMPORTANT:
# This route MUST appear before /demo/{scenario}.
# ============================================================
'''


def main() -> int:
    if not MAIN.exists():
        print(f"ERROR: Could not find {MAIN}")
        return 1

    if not CSV_PATH.exists():
        print(f"ERROR: Missing verified DDoS CSV: {CSV_PATH}")
        return 1

    if not SCHEMA_PATH.exists():
        print(f"ERROR: Missing DDoS schema: {SCHEMA_PATH}")
        return 1

    text = MAIN.read_text(encoding="utf-8")
    if START_MARKER not in text or END_MARKER not in text:
        print("ERROR: Could not find the DDoS demo section markers in app/main.py")
        print("No file was changed.")
        return 1

    start = text.index(START_MARKER)
    end = text.index(END_MARKER, start)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backup = BACKUP_DIR / f"main.py.before_final_ddos_fix_{timestamp}.bak"
    shutil.copy2(MAIN, backup)

    new_text = text[:start] + NEW_BLOCK + text[end + len(END_MARKER):]
    MAIN.write_text(new_text, encoding="utf-8")

    print("CODEZILLA final DDoS demo fix applied.")
    print(f"Updated: {MAIN}")
    print(f"Backup : {backup}")
    print("The fix removes the runtime parquet/pyarrow dependency from /demo/ddos.")
    print("Live-monitoring and all other routes are preserved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
