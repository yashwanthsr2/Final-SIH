export interface Alert {
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
