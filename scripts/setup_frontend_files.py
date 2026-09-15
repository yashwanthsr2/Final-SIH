import os

# package.json
with open('frontend/package.json', 'w') as f:
    f.write('''{
  "name": "cybersentinel-frontend",
  "version": "1.2.0",
  "private": true,
  "description": "CyberSentinel UI - SIH26-26145",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "chart.js": "^4.4.4",
    "d3": "^7.9.0",
    "lucide-react": "^0.441.0"
  },
  "devDependencies": {
    "@types/react": "^18.3.5",
    "@types/react-dom": "^18.3.0",
    "@types/d3": "^7.4.3",
    "typescript": "^5.5.4",
    "vite": "^5.4.3"
  }
}
''')

# tsconfig.json
with open('frontend/tsconfig.json', 'w') as f:
    f.write('''{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["src"]
}
''')

# Dockerfile
with open('frontend/Dockerfile', 'w') as f:
    f.write('''FROM nginx:alpine
COPY public /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
''')

# Types
with open('frontend/src/types/index.ts', 'w') as f:
    f.write('''export interface Alert {
  alert_id: string;
  prediction: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  score: number;
  confidence: number;
  risk_score: number;
  primary_threat?: string;
  threat_class?: string;
  source?: string;
  destination?: string;
  protocol?: string;
  timestamp?: number;
  current_state?: string;
  predicted_next_state?: string;
  prediction_confidence?: number;
  prediction_reasoning?: string;
  evidence: Array<{ feature: string; value: any; contribution: number }>;
}

export interface Flow {
  id: string;
  timestamp: number;
  source: string;
  destination: string;
  protocol: string;
  bytes_out: number;
  bytes_in: number;
  threat_flag: number;
  threat_class?: string;
}

export interface NetworkNode {
  id: string;
  type: string;
  threat_score: number;
  threat_classes: string[];
  flow_count: number;
  bytes: number;
}

export interface NetworkEdge {
  src: string;
  dst: string;
  flow_count: number;
  bytes: number;
  threat_score: number;
  threat_class?: string;
}
''')

# Services: api.ts
with open('frontend/src/services/api.ts', 'w') as f:
    f.write('''const API_BASE = "";

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
''')

# Services: websocket.ts
with open('frontend/src/services/websocket.ts', 'w') as f:
    f.write('''export function connectWebSocket(onMessage: (data: any) => void) {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const host = window.location.host;
  const ws = new WebSocket(`${protocol}//${host}/ws/alerts`);

  ws.onmessage = (event) => {
    try {
      const parsed = JSON.parse(event.data);
      onMessage(parsed);
    } catch (e) {
      console.error("WS Parse Error", e);
    }
  };

  ws.onclose = () => {
    setTimeout(() => connectWebSocket(onMessage), 3000);
  };

  return ws;
}
''')

# Utils
with open('frontend/src/utils/formatters.ts', 'w') as f:
    f.write('''export function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}
''')

# Components
with open('frontend/src/components/Navbar.tsx', 'w') as f:
    f.write('''import React from "react";

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab }) => {
  const tabs = [
    { id: "dashboard", label: "Executive Dashboard" },
    { id: "live", label: "Live Traffic" },
    { id: "alerts", label: "Threat Center" },
    { id: "threats", label: "Threat Details" },
    { id: "network", label: "Network Graph" },
    { id: "trajectory", label: "Attack Trajectory" },
    { id: "models", label: "Model Center" },
    { id: "health", label: "System Health" },
  ];

  return (
    <nav className="flex space-x-4 border-b border-gray-800 px-6 py-3 bg-gray-950">
      {tabs.map((t) => (
        <button
          key={t.id}
          onClick={() => setActiveTab(t.id)}
          className={`px-3 py-1.5 rounded-md font-medium text-sm transition-colors ${
            activeTab === t.id
              ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30"
              : "text-gray-400 hover:text-gray-200"
          }`}
        >
          {t.label}
        </button>
      ))}
    </nav>
  );
};
''')

# Pages
pages = [
  ("Dashboard", "DashboardPage"),
  ("LiveTraffic", "LiveTrafficPage"),
  ("ThreatCenter", "ThreatCenterPage"),
  ("ThreatDetails", "ThreatDetailsPage"),
  ("NetworkGraph", "NetworkGraphPage"),
  ("AttackTrajectory", "AttackTrajectoryPage"),
  ("ModelCenter", "ModelCenterPage"),
  ("SystemHealth", "SystemHealthPage"),
]

for folder, comp in pages:
    with open(f'frontend/src/pages/{folder}/{comp}.tsx', 'w') as f:
        f.write(f'''import React from "react";

export const {comp}: React.FC = () => {{
  return (
    <div className="p-6">
      <h2 className="text-xl font-bold text-cyan-400 mb-4">{folder} View</h2>
      <p className="text-gray-400">CyberSentinel {folder} Intelligence Telemetry.</p>
    </div>
  );
}};
''')

# Root App.tsx
with open('frontend/src/App.tsx', 'w') as f:
    f.write('''import React, { useState, useEffect } from "react";
import { Navbar } from "./components/Navbar";
import { fetchHealth, fetchMetrics } from "./services/api";

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [health, setHealth] = useState<any>(null);

  useEffect(() => {
    fetchHealth().then(setHealth).catch(console.error);
  }, []);

  return (
    <div className="min-h-screen bg-black text-white flex flex-col font-sans">
      <header className="px-6 py-4 border-b border-gray-800 flex justify-between items-center bg-gray-950">
        <h1 className="text-xl font-black text-cyan-400 tracking-wider">
          CYBERSENTINEL <span className="text-xs text-gray-500">SIH26-26145</span>
        </h1>
        <span className="text-xs text-emerald-400 font-mono">
          STATUS: {health ? health.status.toUpperCase() : "CONNECTING..."}
        </span>
      </header>
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} />
      <main className="flex-1 overflow-auto">
        <div className="p-6">
          <p className="text-sm text-gray-400">Active Tab: {activeTab}</p>
        </div>
      </main>
    </div>
  );
};
export default App;
''')

print('Frontend modular architecture established.')
