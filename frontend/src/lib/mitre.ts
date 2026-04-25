export type MitreTactic = {
  id: string;
  name: string;
  description: string;
  url: string;
};

export const MITRE_TACTICS: Record<string, MitreTactic> = {
  TA0001: {
    id: "TA0001",
    name: "Initial Access",
    description:
      "Adversary attempts to gain an initial foothold via spearphishing links or attachments.",
    url: "https://attack.mitre.org/tactics/TA0001/",
  },
  TA0006: {
    id: "TA0006",
    name: "Credential Access",
    description:
      "Stealing credentials through phishing pages that mimic legitimate login portals.",
    url: "https://attack.mitre.org/tactics/TA0006/",
  },
  TA0002: {
    id: "TA0002",
    name: "Execution",
    description:
      "Tricking the user into running malicious code via a weaponized attachment.",
    url: "https://attack.mitre.org/tactics/TA0002/",
  },
  TA0009: {
    id: "TA0009",
    name: "Collection",
    description:
      "Harvesting personal or financial information submitted through fraudulent forms.",
    url: "https://attack.mitre.org/tactics/TA0009/",
  },
  NONE: {
    id: "N/A",
    name: "No Adversary Tactic Detected",
    description: "Content appears benign and does not map to a known ATT&CK tactic.",
    url: "https://attack.mitre.org/",
  },
};
