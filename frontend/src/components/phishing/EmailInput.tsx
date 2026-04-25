import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { SAMPLE_EMAILS, type SampleEmail } from "@/lib/sampleEmails";
import { Terminal, Zap, Loader2 } from "lucide-react";

type Props = {
  onAnalyze: (emailText: string) => void;
  isAnalyzing: boolean;
  samples?: SampleEmail[];
};

export const EmailInput = ({ onAnalyze, isAnalyzing, samples = SAMPLE_EMAILS }: Props) => {
  const [text, setText] = useState("");

  const handleSampleSelect = (id: string) => {
    const sample = samples.find((s) => s.id === id);
    if (sample) setText(sample.body);
  };

  const handleSubmit = () => {
    if (!text.trim() || isAnalyzing) return;
    onAnalyze(text.trim());
  };

  return (
    <section className="panel panel-glow p-6 relative">
      <div className="flex items-center gap-2 mb-4">
        <Terminal className="h-4 w-4 text-primary" />
        <h2 className="font-mono-cyber text-xs uppercase tracking-[0.25em] text-primary">
          Enter Email Text
        </h2>
      </div>

      <div className="flex flex-col md:flex-row gap-3 mb-4">
        <Select onValueChange={handleSampleSelect}>
          <SelectTrigger className="font-mono-cyber bg-card/80 border-border md:w-80">
            <SelectValue placeholder="Choose Sample Email" />
          </SelectTrigger>
          <SelectContent className="font-mono-cyber bg-popover border-border">
            {samples.map((s) => (
              <SelectItem key={s.id} value={s.id} className="text-xs">
                {s.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <button
          type="button"
          onClick={() => setText("")}
          className="font-mono-cyber text-xs text-muted-foreground hover:text-primary transition-colors px-3"
        >
          [ clear ]
        </button>
      </div>

      <div className="relative">
        <Textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Paste suspicious email content here..."
          className="font-mono-cyber min-h-[260px] bg-background/70 border-border focus-visible:ring-primary/40 focus-visible:border-primary/60 text-sm leading-relaxed resize-y"
        />
        <div className="absolute bottom-2 right-3 font-mono-cyber text-[10px] text-muted-foreground/70">
          {text.length} chars
        </div>
      </div>

      <div className="mt-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <p className="font-mono-cyber text-[11px] text-muted-foreground">
          &gt; Analysis pipeline: ML classifier - indicator extraction - MITRE ATT&amp;CK mapping
        </p>
        <Button
          onClick={handleSubmit}
          disabled={!text.trim() || isAnalyzing}
          className="font-display tracking-wider bg-primary text-primary-foreground hover:bg-primary/90 glow-border-neon h-12 px-8 text-sm font-bold"
        >
          {isAnalyzing ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              ANALYZING...
            </>
          ) : (
            <>
              <Zap className="h-4 w-4" />
              ANALYZE EMAIL
            </>
          )}
        </Button>
      </div>
    </section>
  );
};
