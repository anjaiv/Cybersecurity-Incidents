import { Mail, ShieldAlert, ShieldCheck, Percent, Database } from "lucide-react";
import type { LucideIcon } from "lucide-react";

type Props = {
  total: number;
  phishing: number;
  safe: number;
  ratio: number;
  datasetTotal?: number;
  modelAccuracy?: number;
};

const Stat = ({
  icon: Icon,
  label,
  value,
  accent,
}: {
  icon: LucideIcon;
  label: string;
  value: string | number;
  accent: "neon" | "danger" | "safe" | "muted";
}) => {
  const accentClass =
    accent === "danger"
      ? "text-danger border-destructive/40"
      : accent === "safe"
      ? "text-safe border-safe/40"
      : accent === "muted"
      ? "text-foreground border-border"
      : "text-neon border-primary/40";
  return (
    <div className={`panel relative overflow-hidden px-5 py-4 border ${accentClass}`}>
      <div className="flex items-center justify-between gap-3">
        <span className="font-mono-cyber text-[11px] uppercase tracking-wider text-muted-foreground">
          {label}
        </span>
        <Icon className="h-4 w-4 opacity-70 shrink-0" />
      </div>
      <div className={`font-display text-2xl md:text-3xl font-bold mt-2 ${accentClass.split(" ")[0]}`}>
        {value}
      </div>
    </div>
  );
};

export const StatsPanel = ({
  total,
  phishing,
  safe,
  ratio,
  datasetTotal,
  modelAccuracy,
}: Props) => {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-6 gap-4">
      <Stat icon={Mail} label="Session Total" value={total} accent="neon" />
      <Stat icon={ShieldAlert} label="Phishing" value={phishing} accent="danger" />
      <Stat icon={ShieldCheck} label="Safe" value={safe} accent="safe" />
      <Stat icon={Percent} label="Detection Ratio" value={`${ratio}%`} accent="muted" />
      <Stat icon={Database} label="Dataset Emails" value={datasetTotal ?? "-"} accent="neon" />
      <Stat
        icon={Percent}
        label="Model Accuracy"
        value={modelAccuracy ? `${Math.round(modelAccuracy * 100)}%` : "-"}
        accent="safe"
      />
    </div>
  );
};
