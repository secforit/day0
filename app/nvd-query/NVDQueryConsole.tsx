'use client'

import { useState, useEffect } from 'react';
import { Search, Filter, Download, RefreshCw, AlertCircle, CheckCircle, Info, X, Key, Lock } from 'lucide-react';

interface QueryParams {
  // CVE Specific
  cveId?: string;
  
  // CPE Filters
  cpeName?: string;
  isVulnerable?: boolean;
  virtualMatchString?: string;
  
  // Version Filters
  versionStart?: string;
  versionStartType?: 'including' | 'excluding';
  versionEnd?: string;
  versionEndType?: 'including' | 'excluding';
  
  // CVSS Filters
  cvssV2Metrics?: string;
  cvssV2Severity?: 'LOW' | 'MEDIUM' | 'HIGH';
  cvssV3Metrics?: string;
  cvssV3Severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  cvssV4Metrics?: string;
  cvssV4Severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  
  // CWE Filter
  cweId?: string;
  
  // Date Filters
  pubStartDate?: string;
  pubEndDate?: string;
  lastModStartDate?: string;
  lastModEndDate?: string;
  kevStartDate?: string;
  kevEndDate?: string;
  
  // Keyword Search
  keywordSearch?: string;
  keywordExactMatch?: boolean;
  
  // Source Filter
  sourceIdentifier?: string;
  
  // Boolean Filters
  hasKev?: boolean;
  hasCertAlerts?: boolean;
  hasCertNotes?: boolean;
  hasOval?: boolean;
  noRejected?: boolean;
  
  // CVE Tags
  cveTag?: 'disputed' | 'unsupported-when-assigned' | 'exclusively-hosted-service';
  
  // Pagination
  resultsPerPage?: number;
  startIndex?: number;
}

interface VulnerabilityResult {
  id: string;
  title: string;
  description: string;
  severity: string;
  published: string;
  updated: string;
  cvssScore?: number;
  cvssVector?: string;
  cweId?: string;
  isKev?: boolean;
  references: Array<{
    url: string;
    tags: string[];
  }>;
}

interface QueryResponse {
  results: VulnerabilityResult[];
  totalResults: number;
  resultsPerPage: number;
  startIndex: number;
  timestamp: string;
  error?: string;
}

export default function NVDQueryConsole({ initialResults }: { initialResults?: QueryResponse }) {
  const [queryParams, setQueryParams] = useState<QueryParams>({
    resultsPerPage: 20,
    startIndex: 0,
    noRejected: true
  });
  
  const [results, setResults] = useState<QueryResponse | null>(initialResults || null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'basic' | 'advanced' | 'filters'>('basic');
  const [error, setError] = useState<string | null>(null);
  const [apiKey, setApiKey] = useState<string>('');
  const [showApiKeyModal, setShowApiKeyModal] = useState(false);
  const [apiKeyStored, setApiKeyStored] = useState(false);

  // Load API key from localStorage on mount
  useEffect(() => {
    const storedKey = localStorage.getItem('nvd_api_key');
    if (storedKey) {
      setApiKey(storedKey);
      setApiKeyStored(true);
    }
  }, []);

  const saveApiKey = () => {
    if (apiKey.trim()) {
      localStorage.setItem('nvd_api_key', apiKey.trim());
      setApiKeyStored(true);
      setShowApiKeyModal(false);
      setError(null);
    } else {
      setError('Please enter a valid API key');
    }
  };

  const removeApiKey = () => {
    localStorage.removeItem('nvd_api_key');
    setApiKey('');
    setApiKeyStored(false);
    setShowApiKeyModal(false);
  };

  const handleQuery = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch('/api/nvd-query', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          ...(apiKey && { 'X-NVD-API-Key': apiKey })
        },
        body: JSON.stringify(queryParams)
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `Query failed: ${response.status}`);
      }
      
      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Query failed');
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setQueryParams({
      resultsPerPage: 20,
      startIndex: 0,
      noRejected: true
    });
    setResults(null);
    setError(null);
  };

  const handleExport = (format: 'json' | 'csv') => {
    if (!results) return;
    
    let content: string;
    let filename: string;
    let mimeType: string;
    
    if (format === 'json') {
      content = JSON.stringify(results, null, 2);
      filename = `nvd-query-${Date.now()}.json`;
      mimeType = 'application/json';
    } else {
      const headers = ['CVE ID', 'Severity', 'CVSS Score', 'Published', 'Description'];
      const rows = results.results.map(r => [
        r.id,
        r.severity,
        r.cvssScore?.toString() || '',
        r.published,
        `"${r.description.replace(/"/g, '""')}"`
      ]);
      content = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
      filename = `nvd-query-${Date.now()}.csv`;
      mimeType = 'text/csv';
    }
    
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-red-500/20 text-red-300 border-red-500/50';
      case 'high': return 'bg-orange-500/20 text-orange-300 border-orange-500/50';
      case 'medium': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/50';
      case 'low': return 'bg-green-500/20 text-green-300 border-green-500/50';
      default: return 'bg-slate-700/20 text-slate-300 border-slate-700/50';
    }
  };

  return (
    <div className="space-y-6">
      {/* API Key Configuration Banner */}
      <div className={`rounded-xl border p-4 ${
        apiKeyStored 
          ? 'bg-green-500/10 border-green-500/30' 
          : 'bg-yellow-500/10 border-yellow-500/30'
      }`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
              apiKeyStored 
                ? 'bg-green-500/20 border border-green-500/30' 
                : 'bg-yellow-500/20 border border-yellow-500/30'
            }`}>
              <Key className={`w-5 h-5 ${apiKeyStored ? 'text-green-400' : 'text-yellow-400'}`} />
            </div>
            <div>
              <h3 className={`font-semibold ${apiKeyStored ? 'text-green-300' : 'text-yellow-300'}`}>
                {apiKeyStored ? 'API Key Configured' : 'NVD API Key Required'}
              </h3>
              <p className="text-sm text-slate-400">
                {apiKeyStored 
                  ? 'Using your personal API key (50 requests/30s)' 
                  : 'Add your API key for higher rate limits (5 → 50 req/30s)'}
              </p>
            </div>
          </div>
          <div className="flex gap-2">
            {apiKeyStored ? (
              <>
                <button
                  onClick={() => setShowApiKeyModal(true)}
                  className="px-4 py-2 rounded-lg border border-slate-700 hover:border-slate-600 bg-slate-900 hover:bg-slate-800 text-white text-sm font-medium transition-colors"
                >
                  Update Key
                </button>
                <button
                  onClick={removeApiKey}
                  className="px-4 py-2 rounded-lg border border-red-500/30 hover:border-red-500/50 bg-red-500/10 hover:bg-red-500/20 text-red-300 text-sm font-medium transition-colors"
                >
                  Remove
                </button>
              </>
            ) : (
              <button
                onClick={() => setShowApiKeyModal(true)}
                className="px-4 py-2 rounded-lg bg-gradient-to-r from-yellow-600 to-orange-600 hover:from-yellow-500 hover:to-orange-500 text-white text-sm font-semibold transition-all"
              >
                Add API Key
              </button>
            )}
          </div>
        </div>
      </div>

      {/* API Key Modal */}
      {showApiKeyModal && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-950 border border-slate-800 rounded-xl max-w-lg w-full shadow-2xl">
            <div className="bg-gradient-to-r from-blue-600/20 to-cyan-600/20 border-b border-slate-800 px-6 py-4 flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <Lock className="w-6 h-6 text-blue-400" />
                <h3 className="text-xl font-bold text-white">NVD API Key</h3>
              </div>
              <button
                onClick={() => setShowApiKeyModal(false)}
                className="text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-6 h-6" />
              </button>
            </div>
            
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Your NVD API Key
                </label>
                <input
                  type="password"
                  placeholder="Enter your API key..."
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono text-sm"
                />
              </div>

              <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
                <h4 className="text-sm font-semibold text-blue-300 mb-2 flex items-center">
                  <Info className="w-4 h-4 mr-2" />
                  Why is this needed?
                </h4>
                <ul className="text-xs text-slate-400 space-y-1">
                  <li>• Your API key is stored locally in your browser</li>
                  <li>• It's never sent to our servers or stored remotely</li>
                  <li>• Increases rate limit from 5 to 50 requests per 30 seconds</li>
                  <li>• Free API keys available at <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">nvd.nist.gov</a></li>
                </ul>
              </div>

              {error && (
                <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3">
                  <p className="text-sm text-red-300">{error}</p>
                </div>
              )}

              <div className="flex gap-3 pt-2">
                <button
                  onClick={saveApiKey}
                  className="flex-1 px-6 py-3 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white font-semibold transition-all shadow-lg"
                >
                  Save API Key
                </button>
                <button
                  onClick={() => {
                    setShowApiKeyModal(false);
                    setError(null);
                  }}
                  className="px-6 py-3 rounded-lg border border-slate-700 hover:border-slate-600 bg-slate-900 hover:bg-slate-800 text-white font-semibold transition-colors"
                >
                  Cancel
                </button>
              </div>

              <p className="text-xs text-slate-500 text-center">
                Don't have an API key? <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">Request one here</a>
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Query Builder */}
      <div className="bg-slate-950 rounded-xl border border-slate-800 overflow-hidden">
        <div className="bg-gradient-to-r from-blue-600/20 to-cyan-600/20 border-b border-slate-800 px-6 py-4">
          <h2 className="text-2xl font-bold text-white flex items-center space-x-3">
            <Search className="w-6 h-6 text-blue-400" />
            <span>NVD Query Console</span>
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Advanced query interface for the National Vulnerability Database API
          </p>
        </div>

        {/* Tabs */}
        <div className="border-b border-slate-800 px-6">
          <div className="flex space-x-1">
            {(['basic', 'advanced', 'filters'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-6 py-3 font-medium transition-colors relative ${
                  activeTab === tab
                    ? 'text-blue-400'
                    : 'text-slate-400 hover:text-slate-300'
                }`}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
                {activeTab === tab && (
                  <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-blue-500" />
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Query Form */}
        <div className="p-6">
          {/* Basic Tab */}
          {activeTab === 'basic' && (
            <div className="space-y-4">
              {/* CVE ID */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  CVE ID
                </label>
                <input
                  type="text"
                  placeholder="e.g., CVE-2024-1234"
                  value={queryParams.cveId || ''}
                  onChange={(e) => setQueryParams({ ...queryParams, cveId: e.target.value })}
                  className="w-full px-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              {/* Keyword Search */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Keyword Search
                </label>
                <input
                  type="text"
                  placeholder="Search in vulnerability descriptions"
                  value={queryParams.keywordSearch || ''}
                  onChange={(e) => setQueryParams({ ...queryParams, keywordSearch: e.target.value })}
                  className="w-full px-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                />
                <label className="flex items-center mt-2 text-sm text-slate-400">
                  <input
                    type="checkbox"
                    checked={queryParams.keywordExactMatch || false}
                    onChange={(e) => setQueryParams({ ...queryParams, keywordExactMatch: e.target.checked })}
                    className="mr-2 rounded"
                  />
                  Exact phrase match
                </label>
              </div>

              {/* Date Range */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Published After
                  </label>
                  <input
                    type="date"
                    value={queryParams.pubStartDate || ''}
                    onChange={(e) => setQueryParams({ ...queryParams, pubStartDate: e.target.value })}
                    className="w-full px-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Published Before
                  </label>
                  <input
                    type="date"
                    value={queryParams.pubEndDate || ''}
                    onChange={(e) => setQueryParams({ ...queryParams, pubEndDate: e.target.value })}
                    className="w-full px-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              {/* CVSS V3 Severity */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  CVSS v3 Severity
                </label>
                <select
                  value={queryParams.cvssV3Severity || ''}
                  onChange={(e) => setQueryParams({ 
                    ...queryParams, 
                    cvssV3Severity: e.target.value as any || undefined 
                  })}
                  className="w-full px-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="">All Severities</option>
                  <option value="LOW">Low</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="HIGH">High</option>
                  <option value="CRITICAL">Critical</option>
                </select>
              </div>
            </div>
          )}

          {/* Advanced Tab */}
          {activeTab === 'advanced' && (
            <div className="space-y-4">
              {/* CPE Name */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  CPE Name
                  <span className="ml-2 text-xs text-slate-500">
                    (Common Platform Enumeration)
                  </span>
                </label>
                <input
                  type="text"
                  placeholder="e.g., cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*"
                  value={queryParams.cpeName || ''}
                  onChange={(e) => setQueryParams({ ...queryParams, cpeName: e.target.value })}
                  className="w-full px-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono text-sm"
                />
                <label className="flex items-center mt-2 text-sm text-slate-400">
                  <input
                    type="checkbox"
                    checked={queryParams.isVulnerable || false}
                    onChange={(e) => setQueryParams({ ...queryParams, isVulnerable: e.target.checked })}
                    className="mr-2 rounded"
                  />
                  Only vulnerable configurations
                </label>
              </div>

              {/* CWE ID */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  CWE ID
                  <span className="ml-2 text-xs text-slate-500">
                    (Common Weakness Enumeration)
                  </span>
                </label>
                <input
                  type="text"
                  placeholder="e.g., CWE-79, CWE-89"
                  value={queryParams.cweId || ''}
                  onChange={(e) => setQueryParams({ ...queryParams, cweId: e.target.value })}
                  className="w-full px-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              {/* CVSS Metrics */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  CVSS v3 Vector String
                </label>
                <input
                  type="text"
                  placeholder="e.g., AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                  value={queryParams.cvssV3Metrics || ''}
                  onChange={(e) => setQueryParams({ ...queryParams, cvssV3Metrics: e.target.value })}
                  className="w-full px-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono text-sm"
                />
              </div>

              {/* Source Identifier */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Source Identifier
                </label>
                <input
                  type="text"
                  placeholder="e.g., [email protected]"
                  value={queryParams.sourceIdentifier || ''}
                  onChange={(e) => setQueryParams({ ...queryParams, sourceIdentifier: e.target.value })}
                  className="w-full px-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              {/* Version Range */}
              <div className="border border-slate-700 rounded-lg p-4 space-y-3">
                <h4 className="text-sm font-medium text-slate-300">Version Range Filter</h4>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Start Version</label>
                    <input
                      type="text"
                      placeholder="e.g., 2.6"
                      value={queryParams.versionStart || ''}
                      onChange={(e) => setQueryParams({ ...queryParams, versionStart: e.target.value })}
                      className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded text-white text-sm focus:outline-none focus:border-blue-500"
                    />
                    <select
                      value={queryParams.versionStartType || 'including'}
                      onChange={(e) => setQueryParams({ 
                        ...queryParams, 
                        versionStartType: e.target.value as any 
                      })}
                      className="w-full mt-2 px-3 py-1 bg-slate-900 border border-slate-700 rounded text-white text-xs focus:outline-none focus:border-blue-500"
                    >
                      <option value="including">Including</option>
                      <option value="excluding">Excluding</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">End Version</label>
                    <input
                      type="text"
                      placeholder="e.g., 2.7"
                      value={queryParams.versionEnd || ''}
                      onChange={(e) => setQueryParams({ ...queryParams, versionEnd: e.target.value })}
                      className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded text-white text-sm focus:outline-none focus:border-blue-500"
                    />
                    <select
                      value={queryParams.versionEndType || 'excluding'}
                      onChange={(e) => setQueryParams({ 
                        ...queryParams, 
                        versionEndType: e.target.value as any 
                      })}
                      className="w-full mt-2 px-3 py-1 bg-slate-900 border border-slate-700 rounded text-white text-xs focus:outline-none focus:border-blue-500"
                    >
                      <option value="including">Including</option>
                      <option value="excluding">Excluding</option>
                    </select>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Filters Tab */}
          {activeTab === 'filters' && (
            <div className="space-y-4">
              {/* Boolean Filters */}
              <div className="space-y-3">
                <h4 className="text-sm font-medium text-slate-300">Quick Filters</h4>
                
                <label className="flex items-center p-3 bg-slate-900/50 rounded-lg border border-slate-700 hover:border-slate-600 cursor-pointer transition-colors">
                  <input
                    type="checkbox"
                    checked={queryParams.hasKev || false}
                    onChange={(e) => setQueryParams({ ...queryParams, hasKev: e.target.checked })}
                    className="mr-3 rounded"
                  />
                  <div className="flex-1">
                    <div className="text-sm font-medium text-white">CISA KEV Listed</div>
                    <div className="text-xs text-slate-400">Only vulnerabilities in CISA's Known Exploited Vulnerabilities catalog</div>
                  </div>
                </label>

                <label className="flex items-center p-3 bg-slate-900/50 rounded-lg border border-slate-700 hover:border-slate-600 cursor-pointer transition-colors">
                  <input
                    type="checkbox"
                    checked={queryParams.noRejected || false}
                    onChange={(e) => setQueryParams({ ...queryParams, noRejected: e.target.checked })}
                    className="mr-3 rounded"
                  />
                  <div className="flex-1">
                    <div className="text-sm font-medium text-white">Exclude Rejected CVEs</div>
                    <div className="text-xs text-slate-400">Filter out rejected or disputed vulnerabilities</div>
                  </div>
                </label>

                <label className="flex items-center p-3 bg-slate-900/50 rounded-lg border border-slate-700 hover:border-slate-600 cursor-pointer transition-colors">
                  <input
                    type="checkbox"
                    checked={queryParams.hasCertAlerts || false}
                    onChange={(e) => setQueryParams({ ...queryParams, hasCertAlerts: e.target.checked })}
                    className="mr-3 rounded"
                  />
                  <div className="flex-1">
                    <div className="text-sm font-medium text-white">Has CERT Alerts</div>
                    <div className="text-xs text-slate-400">Contains US-CERT technical alerts</div>
                  </div>
                </label>

                <label className="flex items-center p-3 bg-slate-900/50 rounded-lg border border-slate-700 hover:border-slate-600 cursor-pointer transition-colors">
                  <input
                    type="checkbox"
                    checked={queryParams.hasCertNotes || false}
                    onChange={(e) => setQueryParams({ ...queryParams, hasCertNotes: e.target.checked })}
                    className="mr-3 rounded"
                  />
                  <div className="flex-1">
                    <div className="text-sm font-medium text-white">Has CERT Notes</div>
                    <div className="text-xs text-slate-400">Contains CERT/CC vulnerability notes</div>
                  </div>
                </label>

                <label className="flex items-center p-3 bg-slate-900/50 rounded-lg border border-slate-700 hover:border-slate-600 cursor-pointer transition-colors">
                  <input
                    type="checkbox"
                    checked={queryParams.hasOval || false}
                    onChange={(e) => setQueryParams({ ...queryParams, hasOval: e.target.checked })}
                    className="mr-3 rounded"
                  />
                  <div className="flex-1">
                    <div className="text-sm font-medium text-white">Has OVAL Data</div>
                    <div className="text-xs text-slate-400">Contains OVAL vulnerability assessment data</div>
                  </div>
                </label>
              </div>

              {/* CVE Tag */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  CVE Tag
                </label>
                <select
                  value={queryParams.cveTag || ''}
                  onChange={(e) => setQueryParams({ 
                    ...queryParams, 
                    cveTag: e.target.value as any || undefined 
                  })}
                  className="w-full px-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="">No Tag Filter</option>
                  <option value="disputed">Disputed</option>
                  <option value="unsupported-when-assigned">Unsupported When Assigned</option>
                  <option value="exclusively-hosted-service">Exclusively Hosted Service</option>
                </select>
              </div>

              {/* KEV Date Range */}
              <div className="border border-slate-700 rounded-lg p-4 space-y-3">
                <h4 className="text-sm font-medium text-slate-300">KEV Catalog Date Range</h4>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Added After</label>
                    <input
                      type="date"
                      value={queryParams.kevStartDate || ''}
                      onChange={(e) => setQueryParams({ ...queryParams, kevStartDate: e.target.value })}
                      className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded text-white text-sm focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Added Before</label>
                    <input
                      type="date"
                      value={queryParams.kevEndDate || ''}
                      onChange={(e) => setQueryParams({ ...queryParams, kevEndDate: e.target.value })}
                      className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded text-white text-sm focus:outline-none focus:border-blue-500"
                    />
                  </div>
                </div>
              </div>

              {/* Pagination */}
              <div className="border border-slate-700 rounded-lg p-4 space-y-3">
                <h4 className="text-sm font-medium text-slate-300">Pagination</h4>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Results Per Page</label>
                    <input
                      type="number"
                      min="1"
                      max="2000"
                      value={queryParams.resultsPerPage || 20}
                      onChange={(e) => setQueryParams({ 
                        ...queryParams, 
                        resultsPerPage: parseInt(e.target.value) || 20 
                      })}
                      className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded text-white text-sm focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Start Index</label>
                    <input
                      type="number"
                      min="0"
                      value={queryParams.startIndex || 0}
                      onChange={(e) => setQueryParams({ 
                        ...queryParams, 
                        startIndex: parseInt(e.target.value) || 0 
                      })}
                      className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded text-white text-sm focus:outline-none focus:border-blue-500"
                    />
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex items-center justify-between mt-6 pt-6 border-t border-slate-700">
            <button
              onClick={handleReset}
              className="px-6 py-2 rounded-lg border border-slate-700 hover:border-slate-600 bg-slate-900 hover:bg-slate-800 text-white font-semibold transition-colors inline-flex items-center space-x-2"
            >
              <RefreshCw className="w-4 h-4" />
              <span>Reset</span>
            </button>
            
            <div className="flex gap-3">
              {results && (
                <>
                  <button
                    onClick={() => handleExport('json')}
                    className="px-4 py-2 rounded-lg border border-slate-700 hover:border-slate-600 bg-slate-900 hover:bg-slate-800 text-white font-medium transition-colors inline-flex items-center space-x-2"
                  >
                    <Download className="w-4 h-4" />
                    <span>JSON</span>
                  </button>
                  <button
                    onClick={() => handleExport('csv')}
                    className="px-4 py-2 rounded-lg border border-slate-700 hover:border-slate-600 bg-slate-900 hover:bg-slate-800 text-white font-medium transition-colors inline-flex items-center space-x-2"
                  >
                    <Download className="w-4 h-4" />
                    <span>CSV</span>
                  </button>
                </>
              )}
              
              <button
                onClick={handleQuery}
                disabled={loading}
                className="px-6 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white font-semibold transition-all shadow-lg shadow-blue-500/20 hover:shadow-blue-500/40 inline-flex items-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Search className="w-5 h-5" />
                <span>{loading ? 'Querying...' : 'Query NVD'}</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-500/10 border-2 border-red-500/30 rounded-xl p-5">
          <div className="flex items-center space-x-3">
            <AlertCircle className="w-6 h-6 text-red-400 flex-shrink-0" />
            <div>
              <p className="text-red-300 font-medium">Query Error</p>
              <p className="text-red-400 text-sm mt-1">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <div className="bg-slate-950 rounded-xl border border-slate-800 overflow-hidden">
          <div className="bg-gradient-to-r from-green-600/20 to-emerald-600/20 border-b border-slate-800 px-6 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <CheckCircle className="w-6 h-6 text-green-400" />
                <div>
                  <h3 className="text-xl font-bold text-white">Query Results</h3>
                  <p className="text-sm text-slate-400">
                    Found {results.totalResults} results, showing {results.results.length}
                  </p>
                </div>
              </div>
              <div className="text-xs text-slate-500">
                {new Date(results.timestamp).toLocaleString()}
              </div>
            </div>
          </div>

          {results.results.length > 0 ? (
            <div className="divide-y divide-slate-800">
              {results.results.map((vuln) => (
                <div key={vuln.id} className="p-6 hover:bg-slate-900/50 transition-colors">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3 flex-wrap">
                      <h4 className="text-lg font-bold text-white">{vuln.id}</h4>
                      {vuln.isKev && (
                        <span className="bg-red-500/20 text-red-300 text-xs px-3 py-1 rounded-full font-bold border border-red-500/30">
                          CISA KEV
                        </span>
                      )}
                    </div>
                    <span className={`px-3 py-1 text-xs font-semibold rounded-full border ${getSeverityColor(vuln.severity)}`}>
                      {vuln.severity}
                      {vuln.cvssScore && ` (${vuln.cvssScore})`}
                    </span>
                  </div>

                  <p className="text-slate-300 text-sm leading-relaxed mb-3">
                    {vuln.description}
                  </p>

                  {vuln.cweId && (
                    <div className="inline-flex items-center px-3 py-1 bg-purple-500/10 rounded border border-purple-500/30 text-xs font-medium text-purple-300 mb-3">
                      <span className="mr-1">CWE:</span>
                      {vuln.cweId}
                    </div>
                  )}

                  <div className="flex items-center justify-between text-xs text-slate-500">
                    <div className="flex items-center space-x-4">
                      <span>Published: {new Date(vuln.published).toLocaleDateString()}</span>
                      {vuln.cvssVector && (
                        <span className="font-mono text-slate-600">{vuln.cvssVector}</span>
                      )}
                    </div>
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${vuln.id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-400 hover:text-blue-300 font-medium"
                    >
                      View Details →
                    </a>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-12 text-center">
              <Info className="w-12 h-12 text-slate-600 mx-auto mb-4" />
              <p className="text-slate-400">No vulnerabilities found matching your query</p>
            </div>
          )}
        </div>
      )}

      {/* Info Box */}
      <div className="bg-slate-950 rounded-xl border border-slate-800 p-6">
        <div className="flex items-start space-x-3">
          <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
          <div className="text-sm text-slate-300 space-y-2">
            <p className="font-medium text-white">Query Tips:</p>
            <ul className="list-disc list-inside space-y-1 text-slate-400">
              <li>Date ranges are limited to 120 consecutive days per NVD API specification</li>
              <li>Maximum 2,000 results per query</li>
              <li>CPE queries require exact CPE 2.3 format</li>
              <li>Use keyword search for broad discovery, CVE ID for specific vulnerabilities</li>
              <li>Combine filters to narrow results (e.g., hasKev + cvssV3Severity=CRITICAL)</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}