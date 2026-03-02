import { NextRequest, NextResponse } from 'next/server';
import { queryCVEs } from '@/lib/db/cves';
import { getSeverityStats, getDataFreshness } from '@/lib/db/cves';

export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams;

  const severity = params.get('severity');
  const kev = params.get('kev');
  const search = params.get('search');
  const page = parseInt(params.get('page') || '1', 10);
  const limit = Math.min(parseInt(params.get('limit') || '30', 10), 100);
  const offset = (page - 1) * limit;

  try {
    const [cveResult, stats, freshness] = await Promise.all([
      queryCVEs({
        severity: severity ? severity.split(',').filter(Boolean) : undefined,
        isKev: kev === 'true' ? true : undefined,
        search: search || undefined,
        limit,
        offset,
        sortBy: 'published',
        sortOrder: 'desc',
      }),
      getSeverityStats(),
      getDataFreshness(),
    ]);

    return NextResponse.json({
      cves: cveResult.data,
      count: cveResult.count,
      stats,
      freshness,
    });
  } catch (err: any) {
    console.error('Dashboard API error:', err);
    return NextResponse.json(
      { error: err.message || 'Failed to fetch dashboard data' },
      { status: 500 }
    );
  }
}
