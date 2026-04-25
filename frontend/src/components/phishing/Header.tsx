import { ShieldCheck, Activity } from "lucide-react";

export const Header = () => {
  return (
    <header className="relative overflow-hidden panel panel-glow px-6 py-8 md:px-10 md:py-10">
      <div className="absolute inset-0 pointer-events-none opacity-30 [background:radial-gradient(circle_at_20%_20%,hsl(120_100%_54%/0.15),transparent_50%)]" />
      <div className="relative flex flex-col md:flex-row md:items-center md:justify-between gap-6">
        <div className="flex items-start gap-4">
          <div className="rounded-lg border border-primary/40 p-3 glow-border-neon shrink-0">
            <ShieldCheck className="h-8 w-8 text-primary" />
          </div>
          <div>
            <h1 className="font-display text-3xl md:text-4xl font-bold text-neon leading-tight">
              Phishing Email Analysis System
            </h1>
            <p className="font-mono-cyber text-sm md:text-base text-muted-foreground mt-2">
              &gt; Graduation Thesis Project - Cybersecurity &amp; AI
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 self-start md:self-center">
          <div className="flex items-center gap-2 rounded-md border border-primary/30 bg-card/60 px-3 py-2 font-mono-cyber text-xs">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-75" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-primary" />
            </span>
            <span className="text-primary">SYSTEM ONLINE</span>
          </div>
          <div className="hidden md:flex items-center gap-2 rounded-md border border-border bg-card/60 px-3 py-2 font-mono-cyber text-xs text-muted-foreground">
            <Activity className="h-3.5 w-3.5 text-primary" />
            <span>v1.0.0 / API READY</span>
          </div>
        </div>
      </div>
    </header>
  );
};
