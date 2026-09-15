import pandas as pd
from pathlib import Path
def validate_dataset(df: pd.DataFrame, target_col: str) -> bool:
    return target_col in df.columns and not df.empty
