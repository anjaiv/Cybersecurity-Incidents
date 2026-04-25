export const Footer = () => {
  return (
    <footer className="text-center py-6 border-t border-border/60">
      <p className="font-mono-cyber text-xs text-muted-foreground">
        &gt; Developed as a Graduation Thesis Project in Cybersecurity, Machine Learning, and AI
      </p>
      <p className="font-mono-cyber text-[10px] text-muted-foreground/60 mt-1">
        {new Date().getFullYear()} - Backend API with local demo fallback
      </p>
    </footer>
  );
};
