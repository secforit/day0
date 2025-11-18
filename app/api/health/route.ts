import { NextRequest, NextResponse } from 'next/server';
import { healthCheck } from '@/lib/db/init';

export async function GET(request: NextRequest) {
  try {
    const health = await healthCheck();
    
    if (!health.connected) {
      return NextResponse.json(
        { 
          status: 'error',
          message: 'Database connection failed',
          ...health 
        },
        { status: 503 }
      );
    }

    return NextResponse.json({
      status: 'ok',
      message: 'Database is healthy',
      ...health,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    return NextResponse.json(
      {
        status: 'error',
        message: 'Health check failed',
        error: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    );
  }
}