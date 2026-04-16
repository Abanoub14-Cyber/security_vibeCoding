import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "VibeCode Security Gate",
  description: "Find the mistakes vibe coding introduces — before attackers do.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-background text-foreground antialiased">
        <div className="flex min-h-screen flex-col">
          <header className="sticky top-0 z-50 border-b border-border bg-card/80 backdrop-blur-sm">
            <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary text-primary-foreground font-bold text-sm">
                  VS
                </div>
                <div>
                  <h1 className="text-lg font-bold text-foreground">VibeCode Security Gate</h1>
                </div>
              </div>
              <nav className="flex items-center gap-6 text-sm">
                <a href="/" className="text-primary hover:text-accent transition-colors">Dashboard</a>
                <a href="/scan" className="text-muted-foreground hover:text-foreground transition-colors">New Scan</a>
                <a href="/reports" className="text-muted-foreground hover:text-foreground transition-colors">Reports</a>
              </nav>
            </div>
          </header>
          <main className="flex-1">
            {children}
          </main>
          <footer className="border-t border-border py-6">
            <div className="mx-auto max-w-7xl px-6 text-center text-sm text-muted-foreground">
              VibeCode Security Gate v1.0.0 — Find the mistakes vibe coding introduces before attackers do.
            </div>
          </footer>
        </div>
      </body>
    </html>
  );
}
