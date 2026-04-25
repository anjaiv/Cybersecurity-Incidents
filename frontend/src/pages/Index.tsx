import { useEffect, useMemo, useState } from "react";
import { toast } from "@/hooks/use-toast";
import { Header } from "@/components/phishing/Header";
import { StatsPanel } from "@/components/phishing/StatsPanel";
import { EmailInput } from "@/components/phishing/EmailInput";
import { ResultsDashboard } from "@/components/phishing/ResultsDashboard";
import { AnalysisLog } from "@/components/phishing/AnalysisLog";
import { Footer } from "@/components/phishing/Footer";
import {
  analyzeEmail,
  fetchBackendSamples,
  fetchDatasetStats,
  type AnalysisResult,
  type DatasetStats,
} from "@/lib/analyzer";
import { useAnalysisHistory } from "@/hooks/useAnalysisHistory";
import { SAMPLE_EMAILS, type SampleEmail } from "@/lib/sampleEmails";

const Index = () => {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [datasetStats, setDatasetStats] = useState<DatasetStats | null>(null);
  const [backendSamples, setBackendSamples] = useState<SampleEmail[]>([]);
  const { history, add, clear, stats } = useAnalysisHistory();

  useEffect(() => {
    fetchDatasetStats().then(setDatasetStats);
    fetchBackendSamples().then((samples) => {
      setBackendSamples(
        samples.map((sample, index) => ({
          id: `api-${index}`,
          label: `[${sample.type.toUpperCase()}] Backend sample ${index + 1}`,
          category: sample.type === "Phishing" ? "phishing" : "safe",
          body: sample.text,
        })),
      );
    });
  }, []);

  const samples = useMemo(
    () => (backendSamples.length ? [...backendSamples, ...SAMPLE_EMAILS] : SAMPLE_EMAILS),
    [backendSamples],
  );

  const handleAnalyze = async (emailText: string) => {
    setIsAnalyzing(true);
    try {
      const res = await analyzeEmail(emailText);
      setResult(res);
      add(res);
      toast({
        title: res.verdict === "phishing" ? "Phishing detected" : "Email appears safe",
        description:
          res.verdict === "phishing"
            ? `Mapped to ${res.mitre.name} (${res.mitre.id})`
            : "No adversarial indicators found.",
      });
    } catch (err) {
      console.error(err);
      toast({
        title: "Analysis failed",
        description: "Something went wrong while analyzing the email.",
        variant: "destructive",
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="min-h-screen">
      <main className="mx-auto max-w-7xl px-4 md:px-8 py-6 md:py-10 space-y-6">
        <Header />

        <StatsPanel
          total={stats.total}
          phishing={stats.phishing}
          safe={stats.safe}
          ratio={stats.ratio}
          datasetTotal={datasetStats?.total_emails}
          modelAccuracy={datasetStats?.model_metrics?.accuracy}
        />

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <EmailInput onAnalyze={handleAnalyze} isAnalyzing={isAnalyzing} samples={samples} />
          </div>
          <div>
            <AnalysisLog history={history} onClear={clear} />
          </div>
        </div>

        <ResultsDashboard result={result} />

        <Footer />
      </main>
    </div>
  );
};

export default Index;
