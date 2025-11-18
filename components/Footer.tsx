export default function Footer() {
  return (
    <footer className="mt-auto bg-gradient-to-r from-gray-800 to-gray-900 text-white border-t border-gray-700">
      <div className="container mx-auto px-6 py-8 max-w-7xl">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {/* Company Info */}
          <div>
            <h3 className="text-lg font-semibold mb-3">Zero-Day Vulnerability Tracker</h3>
            <p className="text-gray-400 text-sm leading-relaxed">
              Real-time security intelligence from trusted sources including CISA KEV and National Vulnerability Database.
            </p>
          </div>

          {/* Quick Links */}
          <div>
            <h3 className="text-sm font-semibold mb-3 uppercase tracking-wide text-gray-300">Quick Links</h3>
            <ul className="space-y-2 text-sm">
              <li>
                <a href="/" className="text-gray-400 hover:text-white transition-colors">
                  Home
                </a>
              </li>
              <li>
                <a href="/dashboard" className="text-gray-400 hover:text-white transition-colors">
                  Dashboard
                </a>
              </li>
              <li>
                <a href="/ai-summaries" className="text-gray-400 hover:text-white transition-colors">
                  AI Analysis
                </a>
              </li>
              <li>
                <a href="/rss" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  RSS Feed
                </a>
              </li>
            </ul>
          </div>

          {/* Data Sources */}
          <div>
            <h3 className="text-sm font-semibold mb-3 uppercase tracking-wide text-gray-300">Trusted Sources</h3>
            <ul className="space-y-2 text-sm">
              <li>
                <a 
                  href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  CISA KEV Catalog
                </a>
              </li>
              <li>
                <a 
                  href="https://nvd.nist.gov/" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  National Vulnerability Database
                </a>
              </li>
              <li>
                <a 
                  href="https://cve.mitre.org/" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  MITRE CVE
                </a>
              </li>
            </ul>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="mt-8 pt-6 border-t border-gray-700">
          <div className="flex flex-col md:flex-row justify-between items-center gap-4">
            <div className="text-center md:text-left">
              <p className="text-sm text-gray-400">
                &copy; {new Date().getFullYear()} <span className="font-medium text-gray-300">SECFORIT SRL</span>. All rights reserved.
              </p>
            </div>
            <div className="text-center md:text-right">
              <p className="text-sm text-gray-400">
                Developed by <span className="font-semibold text-blue-400">Lisman Razvan</span>
              </p>
              <p className="text-xs text-gray-500 mt-1">
                Professional Cybersecurity Solutions
              </p>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}