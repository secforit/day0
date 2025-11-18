import Link from 'next/link'

export default function Footer() {
  return (
    <footer className="relative z-10 border-t border-slate-800 bg-black/50 backdrop-blur-md mt-16 py-12">
      <div className="max-w-7xl mx-auto px-6">
        <div className="grid md:grid-cols-4 gap-8 mb-8">
          {/* Company Info */}
          <div>
            <div className="flex items-center space-x-2 mb-4">
              <div className="w-8 h-8 bg-gradient-to-br from-red-500 to-orange-500 rounded-lg flex items-center justify-center font-bold text-white text-sm">
                SF
              </div>
              <span className="font-bold text-white">SECFORIT</span>
            </div>
            <p className="text-sm text-slate-400 leading-relaxed">
              Real-time security intelligence from trusted sources including CISA KEV and National Vulnerability Database.
            </p>
          </div>

          {/* Quick Links */}
          <div>
            <h4 className="font-semibold text-white mb-4">Quick Links</h4>
            <ul className="space-y-2 text-sm text-slate-400">
              <li>
                <Link href="/" className="hover:text-white transition-colors">
                  Home
                </Link>
              </li>
              <li>
                <Link href="/dashboard" className="hover:text-white transition-colors">
                  Dashboard
                </Link>
              </li>
              <li>
                <Link href="/ai-summaries" className="hover:text-white transition-colors">
                  AI Analysis
                </Link>
              </li>
              <li>
                <a href="/rss" target="_blank" rel="noopener noreferrer" className="hover:text-white transition-colors">
                  RSS Feed
                </a>
              </li>
            </ul>
          </div>

          {/* Data Sources */}
          <div>
            <h4 className="font-semibold text-white mb-4">Trusted Sources</h4>
            <ul className="space-y-2 text-sm text-slate-400">
              <li>
                <a 
                  href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="hover:text-white transition-colors"
                >
                  CISA KEV Catalog
                </a>
              </li>
              <li>
                <a 
                  href="https://nvd.nist.gov/" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="hover:text-white transition-colors"
                >
                  National Vulnerability Database
                </a>
              </li>
              <li>
                <a 
                  href="https://cve.mitre.org/" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="hover:text-white transition-colors"
                >
                  MITRE CVE
                </a>
              </li>
            </ul>
          </div>

          {/* Company */}
          <div>
            <h4 className="font-semibold text-white mb-4">Company</h4>
            <ul className="space-y-2 text-sm text-slate-400">
              <li>
                <a href="https://secforit.ro" target="_blank" rel="noopener noreferrer" className="hover:text-white transition-colors">
                  About SECFORIT
                </a>
              </li>
              <li>
                <a href="mailto:razvan@secforit.ro" className="hover:text-white transition-colors">
                  Contact
                </a>
              </li>
            </ul>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="border-t border-slate-800 pt-8">
          <div className="flex flex-col md:flex-row justify-between items-center gap-4">
            <div className="text-center md:text-left">
              <p className="text-sm text-slate-400">
                &copy; {new Date().getFullYear()} <span className="font-medium text-slate-300">SECFORIT SRL</span>. All rights reserved.
              </p>
            </div>
            <div className="text-center md:text-right">
              <p className="text-sm text-slate-400">
                Developed by <span className="font-semibold text-red-400">Lisman Razvan</span>
              </p>
              <p className="text-xs text-slate-500 mt-1">
                Professional Cybersecurity Solutions
              </p>
            </div>
          </div>
        </div>
      </div>
    </footer>
  )
}