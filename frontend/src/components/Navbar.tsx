import React from "react";

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
