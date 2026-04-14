import { NextRequest, NextResponse } from 'next/server';
import { getScanReport } from '@/lib/audit/persistence';

export const runtime = 'nodejs';

export async function GET(_req: NextRequest, { params }: { params: { scanId: string } }): Promise<NextResponse> {
  const id = Number(params.scanId);
  if (!Number.isInteger(id) || id < 1) return NextResponse.json({ error: 'Invalid scan ID' }, { status: 400 });
  try {
    const report = getScanReport(id);
    if (!report) return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
    return NextResponse.json(report);
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}
