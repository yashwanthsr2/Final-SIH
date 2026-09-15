const API_BASE = "";

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}

export async function fetchMetrics() {
  const res = await fetch(`${API_BASE}/api/metrics`);
  return res.json();
}

export async function fetchAlerts(limit = 100) {
  const res = await fetch(`${API_BASE}/api/alerts?limit=${limit}`);
  return res.json();
}

export async function fetchFlows(limit = 100) {
  const res = await fetch(`${API_BASE}/api/flows?limit=${limit}`);
  return res.json();
}

export async function fetchNetworkGraph() {
  const res = await fetch(`${API_BASE}/api/network`);
  return res.json();
}

export async function fetchTrajectories() {
  const res = await fetch(`${API_BASE}/api/trajectory`);
  return res.json();
}

export async function fetchModels() {
  const res = await fetch(`${API_BASE}/api/models`);
  return res.json();
}

export async function triggerDemoScenario(scenario: string) {
  const res = await fetch(`${API_BASE}/demo/${scenario}`, { method: "POST" });
  return res.json();
}
