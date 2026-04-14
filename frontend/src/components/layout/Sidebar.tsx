'use client';

import DashboardRoundedIcon from '@mui/icons-material/DashboardRounded';
import DescriptionRoundedIcon from '@mui/icons-material/DescriptionRounded';
import HistoryRoundedIcon from '@mui/icons-material/HistoryRounded';
import HubRoundedIcon from '@mui/icons-material/HubRounded';
import SettingsRoundedIcon from '@mui/icons-material/SettingsRounded';
import TravelExploreRoundedIcon from '@mui/icons-material/TravelExploreRounded';
import TripOriginRoundedIcon from '@mui/icons-material/TripOriginRounded';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { NAV_ITEMS } from './nav';

interface SidebarProps {
  open: boolean;
  onNavigate: () => void;
}

const NAV_ICON_MAP: Record<string, React.ReactNode> = {
  '/': <DashboardRoundedIcon fontSize="small" />,
  '/scanner': <TravelExploreRoundedIcon fontSize="small" />,
  '/threat-intelligence': <HubRoundedIcon fontSize="small" />,
  '/history': <HistoryRoundedIcon fontSize="small" />,
  '/reports': <DescriptionRoundedIcon fontSize="small" />,
  '/indicators': <TripOriginRoundedIcon fontSize="small" />,
  '/settings': <SettingsRoundedIcon fontSize="small" />,
};

export default function Sidebar({ open, onNavigate }: SidebarProps) {
  const pathname = usePathname();

  return (
    <aside className={`soc-sidebar ${open ? 'open' : ''}`} aria-label="Main navigation">
      <div className="sidebar-header">
        <h2>Navigation</h2>
      </div>

      <nav className="sidebar-nav">
        {NAV_ITEMS.map((item) => {
          const active = pathname === item.href || (item.href !== '/' && pathname.startsWith(item.href));
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`nav-item ${active ? 'active' : ''}`}
              onClick={onNavigate}
            >
              <span className="nav-icon" aria-hidden>
                {NAV_ICON_MAP[item.href]}
              </span>
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
