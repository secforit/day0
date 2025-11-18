import { IVulnerability } from '../models/vulnerability.model';

export interface VulnerabilityDTO {
  id: string;
  cveId: string;
  title: string;
  description: string;
  severity: string;
  cvssScore?: number;
  published: string;
  updated: string;
  source: string;
  link: string;
  vendor?: string;
  product?: string;
  dueDate?: string;
  exploitAvailable: boolean;
  cisaKev: boolean;
  aiSummary?: {
    content: string;
    model: string;
    generatedAt: string;
  };
}

export function transformVulnerabilityToDTO(vuln: IVulnerability): VulnerabilityDTO {
  return {
    id: vuln._id?.toString() || '',
    cveId: vuln.cveId,
    title: vuln.title,
    description: vuln.description,
    severity: vuln.severity,
    cvssScore: vuln.cvssScore,
    published: vuln.published.toISOString(),
    updated: vuln.lastModified.toISOString(),
    source: vuln.source,
    link: vuln.sourceUrl,
    vendor: vuln.vendor,
    product: vuln.product,
    dueDate: vuln.dueDate?.toISOString(),
    exploitAvailable: vuln.exploitAvailable,
    cisaKev: vuln.cisaKev,
    aiSummary: vuln.aiSummary ? {
      content: vuln.aiSummary.content,
      model: vuln.aiSummary.model,
      generatedAt: vuln.aiSummary.generatedAt.toISOString()
    } : undefined
  };
}

export function transformVulnerabilitiesToDTO(vulns: IVulnerability[]): VulnerabilityDTO[] {
  return vulns.map(transformVulnerabilityToDTO);
}

export function normalizeSeverity(cvssScore?: number): 'Critical' | 'High' | 'Medium' | 'Low' {
  if (!cvssScore) return 'Low';
  if (cvssScore >= 9.0) return 'Critical';
  if (cvssScore >= 7.0) return 'High';
  if (cvssScore >= 4.0) return 'Medium';
  return 'Low';
}

export function sanitizeString(str: string, maxLength: number = 1000): string {
  return str.trim().substring(0, maxLength);
}

export function extractCVEId(text: string): string | null {
  const cveRegex = /CVE-\d{4}-\d{4,}/i;
  const match = text.match(cveRegex);
  return match ? match[0].toUpperCase() : null;
}

export function validateCVEId(cveId: string): boolean {
  const cveRegex = /^CVE-\d{4}-\d{4,}$/i;
  return cveRegex.test(cveId);
}