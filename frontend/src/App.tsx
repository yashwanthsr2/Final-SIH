import React, { useState, useEffect } from "react";
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
