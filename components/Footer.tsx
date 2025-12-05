import { Shield, ExternalLink, Github, Linkedin, Mail, Lock } from 'lucide-react';

export default function Footer() {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="mt-auto bg-gradient-to-b from-gray-900 to-gray-950 text-white border-t border-gray-800">
      {/* Main Footer Content */}
      <div className="container mx-auto px-6 py-12 max-w-7xl">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-10">
          
          {/* Brand Section */}
          <div className="lg:col-span-1">
            <div className="flex items-center gap-2 mb-4">
              <Shield className="h-6 w-6 text-emerald-500" />
              <h3 className="text-lg font-bold tracking-tight">ZeroDay Tracker</h3>
            </div>
            <p className="text-gray-400 text-sm leading-relaxed mb-4">
              Real-time security intelligence aggregating vulnerability data from authoritative sources worldwide.
            </p>
            <div className="flex items-center gap-1 text-xs text-emerald-500/80">
              <Lock className="h-3 w-3" />
              <span>Stay Secure!</span>
            </div>
          </div>

          {/* Navigation */}
          <div>
            <h4 className="text-sm font-semibold mb-4 uppercase tracking-wider text-gray-300">
              Navigation
            </h4>
            <ul className="space-y-3">
              {[
                { href: '/', label: 'Home' },
                { href: '/dashboard', label: 'Dashboard' },
                { href: '/ai-summaries', label: 'AI Analysis' },
                { href: '/rss', label: 'RSS Feed', external: true },
              ].map((link) => (
                <li key={link.href}>
                  <a
                    href={link.href}
                    target={link.external ? '_blank' : undefined}
                    rel={link.external ? 'noopener noreferrer' : undefined}
                    className="text-gray-400 hover:text-white transition-colors duration-200 text-sm flex items-center gap-1.5 group"
                  >
                    {link.label}
                    {link.external && (
                      <ExternalLink className="h-3 w-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                    )}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Data Sources */}
          <div>
            <h4 className="text-sm font-semibold mb-4 uppercase tracking-wider text-gray-300">
              Trusted Sources
            </h4>
            <ul className="space-y-3">
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
                    className="text-gray-400 hover:text-white transition-colors duration-200 text-sm flex items-center gap-1.5 group"
                  >
                    {source.label}
                    <ExternalLink className="h-3 w-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Contact & Social */}
          <div>
            <h4 className="text-sm font-semibold mb-4 uppercase tracking-wider text-gray-300">
              Connect
            </h4>
            <div className="space-y-3">
              <a
                href="https://secforit.ro"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-400 hover:text-white transition-colors duration-200 text-sm flex items-center gap-2"
              >
                <ExternalLink className="h-4 w-4" />
                secforit.ro
              </a>
              <a
                href="mailto:razvan@secforit.ro"
                className="text-gray-400 hover:text-white transition-colors duration-200 text-sm flex items-center gap-2"
              >
                <Mail className="h-4 w-4" />
                razvan at secforit.ro
              </a>
            </div>
            
            {/* Social Icons */}
            <div className="flex items-center gap-3 mt-5">
              <a
                href="https://www.linkedin.com/in/răzvan-l-5825a2229/"
                target="_blank"
                rel="noopener noreferrer"
                className="p-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-white transition-all duration-200"
                aria-label="LinkedIn"
              >
                <Linkedin className="h-4 w-4" />
              </a>
              <a
                href="https://github.com/secforit/day0"
                target="_blank"
                rel="noopener noreferrer"
                className="p-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-white transition-all duration-200"
                aria-label="GitHub"
              >
                <Github className="h-4 w-4" />
              </a>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Bar */}
      <div className="border-t border-gray-800/50 bg-gray-950/50">
        <div className="container mx-auto px-6 py-5 max-w-7xl">
          <div className="flex flex-col md:flex-row justify-between items-center gap-3">
            <p className="text-xs text-gray-500">
              © {currentYear} <span className="text-gray-400 font-medium">SECFORIT SRL</span> · All rights reserved
            </p>
            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-500">Developed by</span>
              <span className="text-xs font-semibold text-emerald-500">Razvan</span>
              <span className="text-gray-700">|</span>
              <span className="text-xs text-gray-500">Security First</span>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}