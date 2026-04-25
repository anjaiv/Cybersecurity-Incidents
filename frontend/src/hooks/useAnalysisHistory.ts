import { useCallback, useEffect, useState } from "react";
import type { AnalysisResult } from "@/lib/analyzer";

const STORAGE_KEY = "phishing-analysis-history-v1";
const MAX_ENTRIES = 20;

export type HistoryEntry = AnalysisResult & { id: string };

function load(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function useAnalysisHistory() {
  const [history, setHistory] = useState<HistoryEntry[]>([]);

  useEffect(() => {
    setHistory(load());
  }, []);

  const add = useCallback((result: AnalysisResult) => {
    const entry: HistoryEntry = {
      ...result,
      id: `${result.timestamp}-${Math.random().toString(36).slice(2, 8)}`,
    };
    setHistory((prev) => {
      const next = [entry, ...prev].slice(0, MAX_ENTRIES);
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      } catch {
        /* ignore quota errors */
      }
      return next;
    });
    return entry;
  }, []);

  const clear = useCallback(() => {
    setHistory([]);
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {
      /* ignore */
    }
  }, []);

  const stats = {
    total: history.length,
    phishing: history.filter((h) => h.verdict === "phishing").length,
    safe: history.filter((h) => h.verdict === "safe").length,
    ratio:
      history.length === 0
        ? 0
        : Math.round(
            (history.filter((h) => h.verdict === "phishing").length / history.length) * 100,
          ),
  };

  return { history, add, clear, stats };
}
