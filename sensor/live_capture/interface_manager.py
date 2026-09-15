import psutil
from typing import List

def list_network_interfaces() -> List[str]:
    return list(psutil.net_if_addrs().keys())
