import { Link, useLocation } from 'react-router-dom';
import type { ReactNode } from 'react';

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard' },
  { to: '/repos', label: 'Repositories' },
];

export default function Layout({ children }: { children: ReactNode }) {
  const location = useLocation();

  return (
    <div className="min-h-screen bg-base">
      {/* Top Navigation */}
      <nav className="border-b-2 border-dashed border-border bg-card/60 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-content mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <Link to="/" className="flex items-center gap-3 group">
              <img
                src="/steer-mascot.svg"
                alt="git-steer mascot"
                className="w-8 h-8 group-hover:scale-110 transition-transform"
                onError={(e) => {
                  (e.target as HTMLImageElement).style.display = 'none';
                }}
              />
              <span className="font-display font-bold text-xl text-contrast tracking-tight">
                git-steer
              </span>
            </Link>

            {/* Nav Links */}
            <div className="flex items-center gap-1">
              {NAV_ITEMS.map((item) => {
                const active = location.pathname === item.to;
                return (
                  <Link
                    key={item.to}
                    to={item.to}
                    className={`px-4 py-2 rounded-full text-sm font-semibold tracking-wide uppercase transition-all ${
                      active
                        ? 'bg-contrast text-base'
                        : 'text-muted hover:text-contrast hover:bg-card'
                    }`}
                  >
                    {item.label}
                  </Link>
                );
              })}
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-content mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {children}
      </main>

      {/* Footer */}
      <footer className="border-t-2 border-dashed border-border mt-16 py-8">
        <div className="max-w-content mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <p className="text-muted text-sm">
            git-steer &mdash; CVE scanning &amp; remediation for the fabric ecosystem
          </p>
        </div>
      </footer>
    </div>
  );
}
