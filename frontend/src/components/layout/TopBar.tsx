'use client';

import MenuRoundedIcon from '@mui/icons-material/MenuRounded';
import NotificationsNoneRoundedIcon from '@mui/icons-material/NotificationsNoneRounded';
import SearchRoundedIcon from '@mui/icons-material/SearchRounded';
import ShieldRoundedIcon from '@mui/icons-material/ShieldRounded';

interface TopBarProps {
  onMenuToggle: () => void;
}

export default function TopBar({ onMenuToggle }: TopBarProps) {
  return (
    <header className="soc-topbar">
      <div className="topbar-left">
        <button className="menu-button" onClick={onMenuToggle} aria-label="Toggle navigation">
          <MenuRoundedIcon fontSize="small" />
        </button>

        <div className="brand-group">
          <div className="brand-logo" aria-hidden>
            <ShieldRoundedIcon fontSize="small" />
          </div>
          <div>
            <div className="brand-title">URL Audit Kit</div>
          </div>
        </div>
      </div>

      <label className="topbar-search">
        <SearchRoundedIcon className="search-icon" fontSize="small" />
        <input placeholder="Search..." aria-label="Search" />
      </label>

      <div className="topbar-right">
        <button className="icon-button" aria-label="Notifications">
          <NotificationsNoneRoundedIcon fontSize="small" />
        </button>
        <button className="profile-pill" aria-label="User menu">
          <span className="avatar">A</span>
          <span className="profile-meta">
            <strong>Admin</strong>
          </span>
        </button>
      </div>
    </header>
  );
}
