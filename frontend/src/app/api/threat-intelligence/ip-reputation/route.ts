import { NextRequest, NextResponse } from 'next/server';
import { getIpReputation } from '@/lib/audit/persistence';

export const runtime = 'nodejs';

export async function GET(req: NextRequest): Promise<NextResponse> {
  const limit = Number(req.nextUrl.searchParams.get('limit') || 20);
  try {
    return NextResponse.json(getIpReputation(limit));
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}
