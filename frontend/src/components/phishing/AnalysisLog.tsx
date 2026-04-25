import type { HistoryEntry } from "@/hooks/useAnalysisHistory";
import { Trash2 } from "lucide-react";

type Props = {
  history: HistoryEntry[];
  onClear: () => void;
};

const fmtTime = (ts: number) => {
  const d = new Date(ts);
  return d.toTimeString().slice(0, 8);
};

const summarize = (text: string) => {
  const subj = text.match(/subject:\s*(.+)/i);
  const raw = (subj?.[1] ?? text.split("\n").find((line) => line.trim()) ?? "").trim();
  return raw.length > 48 ? raw.slice(0, 48) + "..." : raw || "(no subject)";
};

export const AnalysisLog = ({ history, onClear }: Props) => {
  return (
    <section className="panel p-5 h-full flex flex-col min-h-[420px]">
      <div className="flex items-center justify-between mb-3">
        <h3 className="font-mono-cyber text-[11px] uppercase tracking-[0.25em] text-primary">
          Recent Analysis Log
        </h3>
        {history.length > 0 && (
          <button
            onClick={onClear}
            className="font-mono-cyber text-[10px] text-muted-foreground hover:text-destructive transition-colors flex items-center gap-1"
            aria-label="Clear log"
          >
            <Trash2 className="h-3 w-3" /> clear
          </button>
        )}
      </div>

      <div className="flex-1 overflow-y-auto rounded-md bg-background/60 border border-border p-3 font-mono-cyber text-[11px] leading-relaxed">
        <p className="text-muted-foreground/70 mb-2">
          $ tail -f /var/log/phish-analyzer.log
        </p>
        {history.length === 0 ? (
          <p className="text-muted-foreground/60 cursor-blink">waiting for events</p>
        ) : (
          <ul className="space-y-1.5">
            {history.slice(0, 10).map((h) => (
              <li key={h.id} className="flex flex-wrap gap-x-2">
                <span className="text-muted-foreground/70">[{fmtTime(h.timestamp)}]</span>
                <span className="text-primary">&gt;</span>
                <span
                  className={
                    h.verdict === "phishing"
                      ? "text-danger font-semibold"
                      : "text-safe font-semibold"
                  }
                >
                  {h.verdict === "phishing" ? "PHISH" : "SAFE "}
                </span>
                <span className="text-muted-foreground">|</span>
                <span className="text-foreground/80">{summarize(h.email_text)}</span>
                <span className="text-muted-foreground/60">- {h.mitre.id}</span>
              </li>
            ))}
            <li className="cursor-blink text-primary/80">&nbsp;</li>
          </ul>
        )}
      </div>
    </section>
  );
};
