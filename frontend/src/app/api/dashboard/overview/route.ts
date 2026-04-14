import { NextRequest, NextResponse } from 'next/server';
import { getDashboardOverview } from '@/lib/audit/persistence';

export const runtime = 'nodejs';

export async function GET(req: NextRequest): Promise<NextResponse> {
  const range = req.nextUrl.searchParams.get('range') || '24h';
  const validRange = ['24h', '7d', '30d'].includes(range) ? range : '24h';
  try {
    return NextResponse.json(getDashboardOverview(validRange));
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}
