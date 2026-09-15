from backend.app.schemas.flow import NormalizedFlow
def parse_conn_log(row: dict) -> NormalizedFlow:
    return NormalizedFlow.from_zeek_conn(row)
