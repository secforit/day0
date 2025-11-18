import { 
  fetchLatestVulnerabilitiesWithSummaries,
  regenerateVulnerabilitySummary,
  type VulnerabilitySummary,
  type VulnerabilityData 
} from '../actions/ai-summary-actions';
import AIVulnerabilitySummaries from './AIVulnerabilitySummaries';
import Footer from '../../components/Footer';
import type { Metadata } from 'next';

// SEO Metadata for AI Summaries
export const metadata: Metadata = {
  title: "AI Vulnerability Analysis | AI-Powered Threat Intelligence",
  description: "Advanced AI-powered vulnerability analysis using Mixtral-8x7b for comprehensive threat intelligence. Get detailed CVE summaries, impact assessments, and actionable security recommendations from trusted sources including CISA KEV and NVD.",
  keywords: [
    "AI vulnerability analysis",
    "AI threat intelligence",
    "machine learning security",
    "automated CVE analysis",
    "AI cybersecurity",
    "vulnerability assessment AI",
    "Mixtral AI",
    "security intelligence automation",
    "AI-powered threat detection",
    "automated security analysis"
  ],
  openGraph: {
    title: "AI Vulnerability Analysis | AI-Powered Threat Intelligence",
    description: "Get AI-powered analysis of critical vulnerabilities with comprehensive threat intelligence and actionable security recommendations.",
    url: "https://secforit.ro/ai-summaries",
    type: "website",
  },
  alternates: {
    canonical: "https://secforit.ro/ai-summaries"
  }
};

// Structured Data for AI Summaries
function generateAIStructuredData() {
  return {
    "@context": "https://schema.org",
    "@type": "WebPage",
    "name": "AI Vulnerability Analysis",
    "description": "AI-powered vulnerability analysis and threat intelligence",
    "url": "https://secforit.ro/ai-summaries",
    "breadcrumb": {
      "@type": "BreadcrumbList",
      "itemListElement": [
        {
          "@type": "ListItem",
          "position": 1,
          "name": "Home",
          "item": "https://secforit.ro"
        },
        {
          "@type": "ListItem",
          "position": 2,
          "name": "AI Analysis",
          "item": "https://secforit.ro/ai-summaries"
        }
      ]
    },
    "mainEntity": {
      "@type": "SoftwareApplication",
      "name": "AI Vulnerability Analyzer",
      "applicationCategory": "SecurityApplication",
      "offers": {
        "@type": "Offer",
        "price": "0",
        "priceCurrency": "USD"
      },
      "featureList": [
        "AI-powered CVE analysis",
        "Threat intelligence automation",
        "Real-time vulnerability assessment",
        "CVSS score interpretation",
        "Actionable security recommendations"
      ]
    }
  };
}

export default async function AISummariesPage() {
  const result = await fetchLatestVulnerabilitiesWithSummaries(10);
  const structuredData = generateAIStructuredData();
  
  return (
    <>
      {/* Structured Data */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }}
      />
      
      <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 flex flex-col">
        {/* Breadcrumb Navigation */}
        <div className="container mx-auto px-6 pt-6 max-w-7xl">
          <nav aria-label="Breadcrumb" className="mb-4">
            <ol className="flex items-center space-x-2 text-sm text-gray-600">
              <li>
                <a href="/" className="hover:text-blue-600 transition-colors">
                  Home
                </a>
              </li>
              <li aria-hidden="true">/</li>
              <li className="text-gray-900 font-medium">AI Analysis</li>
            </ol>
          </nav>
        </div>

        <div className="container mx-auto px-6 pb-8 max-w-7xl flex-grow">
          <AIVulnerabilitySummaries 
            initialSummaries={result.summaries}
            timestamp={result.timestamp}
            error={result.error}
            regenerateAction={regenerateVulnerabilitySummary}
          />
        </div>
        <Footer />
      </div>
    </>
  );
}