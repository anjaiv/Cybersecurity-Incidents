import { MITRE_TACTICS, type MitreTactic } from "./mitre";

export type Severity = "high" | "medium" | "low";

export type Indicator = {
  label: string;
  detail: string;
  severity: Severity;
};

export type AnalysisResult = {
  verdict: "phishing" | "safe";
  confidence: number;
  risk_score: number;
  threat_level: "HIGH" | "MEDIUM" | "LOW";
  indicators: Indicator[];
  mitre: MitreTactic;
  explanation: string;
  email_text: string;
  ml_result: string;
  llm_result: string;
  timestamp: number;
};

export type DatasetStats = {
  total_emails: number;
  phishing_emails: number;
  safe_emails: number;
  phishing_percentage: number;
  safe_percentage: number;
  model_metrics?: {
    accuracy: number;
    precision: number;
    recall: number;
    f1: number;
  };
};

export type BackendSample = {
  type: "Phishing" | "Safe";
  text: string;
};

type BackendAnalysisResponse = {
  input_email: string;
  ml_result: string;
  confidence: number;
  risk_score: number;
  threat_level: "HIGH" | "MEDIUM" | "LOW";
  llm_result: string;
  mitre_mapping: string;
  indicators?: Indicator[];
  timestamp: string;
};

const API_BASE: string =
  (import.meta as any).env?.VITE_API_BASE_URL ?? "http://localhost:8000";

const ANALYZE_URL: string =
  (import.meta as any).env?.VITE_ANALYZE_URL ?? `${API_BASE}/analyze`;

const URGENCY_WORDS = [
  "urgent", "immediately", "asap", "within 24 hours", "within 12 hours",
  "expires", "suspended", "act now", "final notice", "last warning",
];

const CREDENTIAL_WORDS = [
  "password", "verify your account", "confirm your credentials",
  "re-validate", "validate your account", "ssn", "social security",
  "seed phrase", "wallet", "online banking",
];

const MONEY_WORDS = [
  "wire transfer", "bitcoin", "btc", "eth", "airdrop", "customs fee",
  "invoice", "payment required", "gift card",
];

const SUSPICIOUS_TLDS = [".ru", ".tk", ".xyz", ".info", ".top", ".click", ".co"];

const URL_REGEX = /https?:\/\/[^\s)>"]+/gi;
const IP_URL_REGEX = /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/i;

function countMatches(text: string, terms: string[]): { count: number; matches: string[] } {
  const lower = text.toLowerCase();
  const matches = terms.filter((t) => lower.includes(t));
  return { count: matches.length, matches };
}

function parseMitre(mapping: string): MitreTactic {
  if (/TA0001|Initial Access/i.test(mapping)) return MITRE_TACTICS.TA0001;
  if (/TA0006|Credential Access/i.test(mapping)) return MITRE_TACTICS.TA0006;
  if (/TA0002|Execution/i.test(mapping)) return MITRE_TACTICS.TA0002;
  if (/TA0009|Collection/i.test(mapping)) return MITRE_TACTICS.TA0009;
  return MITRE_TACTICS.NONE;
}

function normalizeConfidence(value: number): number {
  return Math.round(value <= 1 ? value * 100 : value);
}

function threatFromScore(score: number, isPhishing: boolean): "HIGH" | "MEDIUM" | "LOW" {
  if (!isPhishing) return "LOW";
  if (score > 90) return "HIGH";
  if (score > 70) return "MEDIUM";
  return "LOW";
}

export async function fetchDatasetStats(): Promise<DatasetStats | null> {
  try {
    const resp = await fetch(`${API_BASE}/dataset-stats`);
    if (!resp.ok) throw new Error(`Backend ${resp.status}`);
    return (await resp.json()) as DatasetStats;
  } catch (err) {
    console.warn("Dataset stats unavailable:", err);
    return null;
  }
}

export async function fetchBackendSamples(): Promise<BackendSample[]> {
  try {
    const resp = await fetch(`${API_BASE}/samples`);
    if (!resp.ok) throw new Error(`Backend ${resp.status}`);
    const data = (await resp.json()) as { samples: BackendSample[] };
    return data.samples ?? [];
  } catch (err) {
    console.warn("Backend samples unavailable:", err);
    return [];
  }
}

export function analyzeLocally(emailText: string): AnalysisResult {
  const text = emailText.trim();
  const indicators: Indicator[] = [];
  let score = 0;

  const urgency = countMatches(text, URGENCY_WORDS);
  if (urgency.count > 0) {
    score += 25;
    indicators.push({
      label: "Urgency / pressure language",
      detail: `Detected: ${urgency.matches.slice(0, 3).join(", ")}`,
      severity: "high",
    });
  }

  const creds = countMatches(text, CREDENTIAL_WORDS);
  if (creds.count > 0) {
    score += 30;
    indicators.push({
      label: "Credential / sensitive data request",
      detail: `Email asks for: ${creds.matches.slice(0, 3).join(", ")}`,
      severity: "high",
    });
  }

  const money = countMatches(text, MONEY_WORDS);
  if (money.count > 0) {
    score += 20;
    indicators.push({
      label: "Financial / payment lure",
      detail: `Mentions: ${money.matches.slice(0, 3).join(", ")}`,
      severity: "medium",
    });
  }

  const urls = text.match(URL_REGEX) ?? [];
  if (urls.length > 0) {
    if (IP_URL_REGEX.test(text)) {
      score += 25;
      indicators.push({
        label: "Raw IP address in link",
        detail: "Links pointing to bare IP addresses are a strong phishing signal.",
        severity: "high",
      });
    }

    const suspiciousUrl = urls.find((url) =>
      SUSPICIOUS_TLDS.some((tld) => url.toLowerCase().includes(`${tld}/`) || url.toLowerCase().endsWith(tld)),
    );
    if (suspiciousUrl) {
      score += 18;
      indicators.push({
        label: "Suspicious link / lookalike domain",
        detail: `Unusual TLD or spoofed brand: ${suspiciousUrl.slice(0, 60)}...`,
        severity: "high",
      });
    }
  }

  const fromMatch = text.match(/from:\s*([^<\n]+)<?([^>\n]*)>?/i);
  if (fromMatch) {
    const display = fromMatch[1].toLowerCase();
    const addr = (fromMatch[2] || "").toLowerCase();
    if (
      /(ceo|admin|support|security|helpdesk|microsoft|chase|paypal|dhl)/.test(display) &&
      /(gmail|yahoo|outlook|hotmail|protonmail|\.tk|\.ru|\.xyz|\.info)/.test(addr)
    ) {
      score += 22;
      indicators.push({
        label: "Spoofed / mismatched sender",
        detail: `Display name claims authority but address is ${addr}`,
        severity: "high",
      });
    }
  }

  if (/dear (user|customer|client|sir|madam)/i.test(text)) {
    score += 8;
    indicators.push({
      label: "Generic greeting",
      detail: "Lacks personalization typical of legitimate correspondence.",
      severity: "low",
    });
  }

  if (/seed phrase|private key/i.test(text)) {
    score += 15;
    indicators.push({
      label: "Crypto credential harvesting",
      detail: "Requests wallet seed phrase, an unrecoverable private secret.",
      severity: "high",
    });
  }

  let mitre: MitreTactic;
  if (creds.count > 0 || /seed phrase|private key/i.test(text)) {
    mitre = MITRE_TACTICS.TA0006;
  } else if (urls.length > 0 && score >= 40) {
    mitre = MITRE_TACTICS.TA0001;
  } else if (money.count > 0) {
    mitre = MITRE_TACTICS.TA0009;
  } else {
    mitre = MITRE_TACTICS.NONE;
  }

  const isPhishing = score >= 40;
  const confidence = isPhishing
    ? Math.min(98, 55 + score * 0.4)
    : Math.max(72, 96 - score * 0.6);
  const confidenceRounded = Math.round(confidence);

  if (!isPhishing && indicators.length === 0) {
    indicators.push({
      label: "No adversarial patterns found",
      detail: "Tone, links, and sender all appear consistent with legitimate correspondence.",
      severity: "low",
    });
  }

  const verdict: "phishing" | "safe" = isPhishing ? "phishing" : "safe";
  const ml_result = isPhishing ? "Phishing Email" : "Safe Email";

  const llm_result = isPhishing
    ? `This message exhibits ${indicators.length} suspicious indicator(s) commonly observed in phishing campaigns. ` +
      `Primary signals include ${indicators.slice(0, 2).map((i) => i.label.toLowerCase()).join(" and ")}. ` +
      `MITRE ATT&CK mapping: ${mitre.name} (${mitre.id}). Recommended action: do not interact with links or attachments; report to the SOC.`
    : `No adversarial indicators detected. The message structure, sender domain, and language are consistent with a legitimate communication. ` +
      `MITRE ATT&CK mapping: ${mitre.name}.`;

  return {
    verdict,
    confidence: confidenceRounded,
    risk_score: confidenceRounded,
    threat_level: threatFromScore(confidenceRounded, isPhishing),
    indicators,
    mitre,
    explanation: llm_result,
    email_text: text,
    ml_result,
    llm_result,
    timestamp: Date.now(),
  };
}

export async function analyzeEmail(emailText: string): Promise<AnalysisResult> {
  const minLatency = new Promise((resolve) => setTimeout(resolve, 750));

  try {
    const [resp] = await Promise.all([
      fetch(ANALYZE_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email_text: emailText }),
      }),
      minLatency,
    ]);
    if (!resp.ok) throw new Error(`Backend ${resp.status}`);
    const data = (await resp.json()) as BackendAnalysisResponse;
    const local = analyzeLocally(emailText);
    const isPhishing = /phish/i.test(data.ml_result);
    const confidence = normalizeConfidence(data.confidence);

    return {
      ...local,
      verdict: isPhishing ? "phishing" : "safe",
      confidence,
      risk_score: data.risk_score ?? confidence,
      threat_level: data.threat_level,
      indicators: data.indicators?.length ? data.indicators : local.indicators,
      mitre: parseMitre(data.mitre_mapping),
      explanation: data.llm_result,
      email_text: data.input_email || emailText,
      ml_result: data.ml_result,
      llm_result: data.llm_result,
      timestamp: data.timestamp ? Date.parse(data.timestamp) || Date.now() : Date.now(),
    };
  } catch (err) {
    console.warn("Backend unavailable, falling back to demo analyzer:", err);
  }

  await minLatency;
  return analyzeLocally(emailText);
}
