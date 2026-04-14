import { NextRequest, NextResponse } from 'next/server';
import { listIocs } from '@/lib/audit/persistence';

export const runtime = 'nodejs';

export async function GET(req: NextRequest): Promise<NextResponse> {
  const p = req.nextUrl.searchParams;
  try {
    return NextResponse.json(listIocs({
      page: Number(p.get('page') || 1),
      page_size: Number(p.get('page_size') || 20),
      q: p.get('q') || '',
      indicator_type: p.get('type') || '',
      severity: p.get('severity') || '',
      sort_by: p.get('sort_by') || 'created_at',
      sort_order: p.get('sort_order') || 'desc',
    }));
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}
