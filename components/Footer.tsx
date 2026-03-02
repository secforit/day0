import { Shield, ExternalLink, Github, Linkedin, Mail, Lock } from 'lucide-react';

export default function Footer() {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="mt-auto border-t border-[#1e2030]/60 bg-[#0a0a0f]/80">
      <div className="container mx-auto px-6 py-10 max-w-7xl">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-10">
          {/* Brand */}
          <div className="lg:col-span-1">
            <div className="flex items-center gap-2 mb-4">
              <Shield className="h-5 w-5 text-emerald-500" />
              <h3 className="text-sm font-bold tracking-tight text-zinc-200">ZeroDay Tracker</h3>
            </div>
            <p className="text-zinc-500 text-xs leading-relaxed mb-3">
              Real-time security intelligence aggregating vulnerability data from authoritative sources worldwide.
            </p>
            <div className="flex items-center gap-1 text-[10px] text-emerald-500/80">
              <Lock className="h-3 w-3" />
              <span>Stay Secure!</span>
            </div>
          </div>

          {/* Navigation */}
          <div>
            <h4 className="text-[11px] font-semibold mb-4 uppercase tracking-wider text-zinc-400">Navigation</h4>
            <ul className="space-y-2.5">
              {[
                { href: '/', label: 'Dashboard' },
                { href: '/search', label: 'Search Console' },
                { href: '/rss', label: 'RSS Feed', external: true },
              ].map((link) => (
                <li key={link.href}>
                  <a
                    href={link.href}
                    target={link.external ? '_blank' : undefined}
                    rel={link.external ? 'noopener noreferrer' : undefined}
                    className="text-zinc-500 hover:text-zinc-200 transition-colors text-xs flex items-center gap-1.5 group"
                  >
                    {link.label}
                    {link.external && <ExternalLink className="h-3 w-3 opacity-0 group-hover:opacity-100 transition-opacity" />}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Data Sources */}
          <div>
            <h4 className="text-[11px] font-semibold mb-4 uppercase tracking-wider text-zinc-400">Trusted Sources</h4>
            <ul className="space-y-2.5">
              {[
                { href: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', label: 'CISA KEV Catalog' },
                { href: 'https://nvd.nist.gov/', label: 'NVD (NIST)' },
                { href: 'https://cve.mitre.org/', label: 'MITRE CVE' },
                { href: 'https://www.first.org/cvss/', label: 'FIRST CVSS' },
              ].map((source) => (
                <li key={source.href}>
                  <a
                    href={source.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-zinc-500 hover:text-zinc-200 transition-colors text-xs flex items-center gap-1.5 group"
                  >
                    {source.label}
                    <ExternalLink className="h-3 w-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Contact */}
          <div>
            <h4 className="text-[11px] font-semibold mb-4 uppercase tracking-wider text-zinc-400">Connect</h4>
            <div className="space-y-2.5">
              <a href="https://secforit.ro" target="_blank" rel="noopener noreferrer"
                className="text-zinc-500 hover:text-zinc-200 transition-colors text-xs flex items-center gap-2">
                <ExternalLink className="h-3.5 w-3.5" /> secforit.ro
              </a>
              <a href="mailto:razvan@secforit.ro"
                className="text-zinc-500 hover:text-zinc-200 transition-colors text-xs flex items-center gap-2">
                <Mail className="h-3.5 w-3.5" /> razvan at secforit.ro
              </a>
            </div>
            <div className="flex items-center gap-2.5 mt-4">
              <a href="https://www.linkedin.com/in/r%C4%83zvan-l-5825a2229/" target="_blank" rel="noopener noreferrer"
                className="p-1.5 rounded-lg bg-[#12141d] border border-[#1e2030] text-zinc-500 hover:text-zinc-200 hover:border-[#2a2d3e] transition-all"
                aria-label="LinkedIn">
                <Linkedin className="h-3.5 w-3.5" />
              </a>
              <a href="https://github.com/secforit/day0" target="_blank" rel="noopener noreferrer"
                className="p-1.5 rounded-lg bg-[#12141d] border border-[#1e2030] text-zinc-500 hover:text-zinc-200 hover:border-[#2a2d3e] transition-all"
                aria-label="GitHub">
                <Github className="h-3.5 w-3.5" />
              </a>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom bar */}
      <div className="border-t border-[#1e2030]/40">
        <div className="container mx-auto px-6 py-4 max-w-7xl flex flex-col md:flex-row justify-between items-center gap-2">
          <p className="text-[10px] text-zinc-600">
            &copy; {currentYear} <span className="text-zinc-500 font-medium">SECFORIT SRL</span> &middot; All rights reserved
          </p>
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-zinc-600">Developed by</span>
            <span className="text-[10px] font-semibold text-emerald-500">Razvan</span>
            <span className="text-zinc-700">|</span>
            <span className="text-[10px] text-zinc-600">Security First</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
