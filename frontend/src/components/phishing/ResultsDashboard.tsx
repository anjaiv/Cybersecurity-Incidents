import type { AnalysisResult } from "@/lib/analyzer";
import { ShieldAlert, ShieldCheck, AlertTriangle, Crosshair, ExternalLink, Brain } from "lucide-react";

type Props = { result: AnalysisResult | null };

const sevStyle = (s: "high" | "medium" | "low") =>
  s === "high"
    ? "border-destructive/50 text-danger bg-destructive/5"
    : s === "medium"
    ? "border-[hsl(var(--warning)/0.5)] text-warn bg-[hsl(var(--warning)/0.05)]"
    : "border-border text-muted-foreground bg-muted/20";

export const ResultsDashboard = ({ result }: Props) => {
  if (!result) {
    return (
      <section className="panel p-10 text-center relative overflow-hidden">
        <div className="font-mono-cyber text-sm text-muted-foreground">
          <p className="mb-2">&gt; awaiting input...</p>
          <p className="cursor-blink">&gt; run analysis to populate results dashboard</p>
        </div>
      </section>
    );
  }

  const isPhish = result.verdict === "phishing";

  return (
    <section className="grid grid-cols-1 lg:grid-cols-3 gap-5">
      <div
        className={`panel p-6 relative overflow-hidden ${
          isPhish ? "glow-border-red" : "glow-border-safe"
        }`}
      >
        <div className="flex items-center gap-2 mb-4">
          <Brain className="h-4 w-4 text-primary" />
          <h3 className="font-mono-cyber text-[11px] uppercase tracking-[0.25em] text-primary">
            Machine Learning Prediction
          </h3>
        </div>

        <div
          className={`inline-flex items-center gap-2 rounded-md px-4 py-3 border-2 font-display font-bold text-lg ${
            isPhish
              ? "border-destructive text-danger bg-destructive/10 animate-pulse-danger"
              : "border-safe text-safe bg-[hsl(var(--safe)/0.1)]"
          }`}
        >
          {isPhish ? <ShieldAlert className="h-5 w-5" /> : <ShieldCheck className="h-5 w-5" />}
          {isPhish ? "PHISHING EMAIL" : "SAFE EMAIL"}
        </div>

        <div className="mt-5 space-y-2 font-mono-cyber text-xs">
          <div className="flex justify-between">
            <span className="text-muted-foreground">confidence</span>
            <span className={isPhish ? "text-danger" : "text-safe"}>
              {result.confidence}%
            </span>
          </div>
          <div className="h-2 rounded bg-muted/40 overflow-hidden">
            <div
              className={`h-full ${
                isPhish ? "bg-destructive shadow-[0_0_12px_hsl(var(--destructive))]" : "bg-[hsl(var(--safe))] shadow-[0_0_12px_hsl(var(--safe))]"
              }`}
              style={{ width: `${result.confidence}%` }}
            />
          </div>
          <div className="flex justify-between text-muted-foreground">
            <span>model</span>
            <span>tfidf + logreg</span>
          </div>
          <div className="flex justify-between text-muted-foreground">
            <span>risk score</span>
            <span>{result.risk_score}/100</span>
          </div>
          <div className="flex justify-between text-muted-foreground">
            <span>threat level</span>
            <span
              className={
                result.threat_level === "HIGH"
                  ? "text-danger"
                  : result.threat_level === "MEDIUM"
                  ? "text-warn"
                  : "text-safe"
              }
            >
              {result.threat_level}
            </span>
          </div>
        </div>
      </div>

      <div className="panel p-6 relative overflow-hidden">
        <div className="flex items-center gap-2 mb-4">
          <AlertTriangle className="h-4 w-4 text-primary" />
          <h3 className="font-mono-cyber text-[11px] uppercase tracking-[0.25em] text-primary">
            Suspicious Indicators
          </h3>
        </div>

        <ul className="space-y-2.5">
          {result.indicators.map((ind, i) => (
            <li
              key={i}
              className={`rounded-md border px-3 py-2 ${sevStyle(ind.severity)} ${
                ind.severity === "high" ? "animate-flicker" : ""
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono-cyber text-xs font-semibold">
                  {ind.label}
                </span>
                <span className="font-mono-cyber text-[10px] uppercase opacity-70">
                  {ind.severity}
                </span>
              </div>
              <p className="font-mono-cyber text-[11px] mt-1 opacity-80 leading-relaxed">
                {ind.detail}
              </p>
            </li>
          ))}
        </ul>
      </div>

      <div className="panel p-6 relative overflow-hidden">
        <div className="flex items-center gap-2 mb-4">
          <Crosshair className="h-4 w-4 text-primary" />
          <h3 className="font-mono-cyber text-[11px] uppercase tracking-[0.25em] text-primary">
            MITRE ATT&amp;CK Mapping
          </h3>
        </div>

        <div className="rounded-md border border-primary/30 bg-primary/5 p-4">
          <div className="font-mono-cyber text-[10px] uppercase tracking-wider text-muted-foreground">
            Tactic
          </div>
          <div className="font-display text-xl font-bold text-neon mt-1">
            {result.mitre.name}
          </div>
          <div className="font-mono-cyber text-xs text-primary/80 mt-1">
            {result.mitre.id}
          </div>
        </div>

        <p className="mt-4 font-mono-cyber text-xs text-muted-foreground leading-relaxed">
          {result.mitre.description}
        </p>

        <a
          href={result.mitre.url}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-4 inline-flex items-center gap-1.5 font-mono-cyber text-xs text-primary hover:text-primary/80 transition-colors"
        >
          attack.mitre.org <ExternalLink className="h-3 w-3" />
        </a>

        <div className="mt-5 pt-4 border-t border-border">
          <div className="font-mono-cyber text-[10px] uppercase tracking-wider text-muted-foreground mb-2">
            Analyst Summary
          </div>
          <p className="font-mono-cyber text-[11px] text-foreground/80 leading-relaxed whitespace-pre-line">
            {result.explanation}
          </p>
        </div>
      </div>
    </section>
  );
};
