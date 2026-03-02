'use client';

import { usePathname } from 'next/navigation';
import { Clock, Wifi } from 'lucide-react';

interface TopBarProps {
  lastSync: string | null;
}

const PAGE_TITLES: Record<string, string> = {
  '/': 'Threat Dashboard',
  '/search': 'CVE Search Console',
};

export default function TopBar({ lastSync }: TopBarProps) {
  const pathname = usePathname();
  const title = PAGE_TITLES[pathname] || 'Dashboard';

  const syncAge = lastSync
    ? Math.round((Date.now() - new Date(lastSync).getTime()) / 60000)
    : null;

  return (
    <header className="sticky top-0 z-20 glass border-b border-[#1e2030]/60">
      <div className="flex items-center justify-between px-4 lg:px-6 h-14">
        <h1 className="text-lg font-semibold text-zinc-100 lg:pl-0 pl-12">{title}</h1>
        <div className="flex items-center gap-4">
          {lastSync && (
            <div className="flex items-center gap-2 text-xs text-zinc-500">
              <Clock size={13} />
              <span>
                {syncAge !== null && syncAge < 60
                  ? `${syncAge}m ago`
                  : syncAge !== null
                  ? `${Math.round(syncAge / 60)}h ago`
                  : 'Unknown'}
              </span>
            </div>
          )}
          <div className="flex items-center gap-1.5">
            <Wifi size={13} className="text-emerald-500" />
            <span className="text-[10px] font-medium text-emerald-500 uppercase tracking-wider">Live</span>
          </div>
        </div>
      </div>
    </header>
  );
}
