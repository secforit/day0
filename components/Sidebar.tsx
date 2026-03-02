'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState, useCallback } from 'react';
import { Shield, Search, Rss, Menu, X, Database, AlertTriangle, RefreshCw } from 'lucide-react';

interface SidebarProps {
  totalCves: number;
  kevCount: number;
  lastSync: string | null;
}

const NAV_ITEMS = [
  { href: '/', label: 'Dashboard', icon: Database },
  { href: '/search', label: 'Search Console', icon: Search },
  { href: '/rss', label: 'RSS Feed', icon: Rss, external: true },
];

export default function Sidebar({ totalCves, kevCount, lastSync }: SidebarProps) {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const [syncing, setSyncing] = useState(false);

  const handleSync = useCallback(async () => {
    setSyncing(true);
    try {
      await fetch('/api/ingest', { method: 'POST' });
      window.location.reload();
    } catch {
      // silently fail
    } finally {
      setSyncing(false);
    }
  }, []);

  const isActive = (href: string) => {
    if (href === '/') return pathname === '/';
    return pathname.startsWith(href);
  };

  return (
    <>
      {/* Mobile toggle */}
      <button
        onClick={() => setOpen(!open)}
        className="fixed top-4 left-4 z-50 lg:hidden p-2 rounded-lg bg-[#12141d] border border-[#1e2030] text-zinc-300"
        aria-label="Toggle menu"
      >
        {open ? <X size={20} /> : <Menu size={20} />}
      </button>

      {/* Overlay */}
      {open && (
        <div
          className="fixed inset-0 bg-black/60 z-30 lg:hidden"
          onClick={() => setOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed top-0 left-0 z-40 h-full w-64 glass flex flex-col transition-transform duration-300 ${
          open ? 'translate-x-0' : '-translate-x-full'
        } lg:translate-x-0`}
      >
        {/* Logo */}
        <div className="p-5 border-b border-[#1e2030]/60">
          <Link href="/" className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
              <Shield className="h-5 w-5 text-emerald-500" />
            </div>
            <div>
              <span className="text-sm font-bold text-zinc-100 tracking-tight">ZeroDay</span>
              <span className="text-sm font-light text-zinc-500 ml-1">Tracker</span>
            </div>
          </Link>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-3 space-y-1">
          {NAV_ITEMS.map(({ href, label, icon: Icon, external }) => {
            const active = isActive(href);
            const Component = external ? 'a' : Link;
            const extraProps = external ? { target: '_blank', rel: 'noopener noreferrer' } : {};

            return (
              <Component
                key={href}
                href={href}
                {...extraProps}
                onClick={() => setOpen(false)}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${
                  active
                    ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                    : 'text-zinc-400 hover:text-zinc-200 hover:bg-[#1e2030]/50'
                }`}
              >
                <Icon size={18} className={active ? 'text-blue-400' : 'text-zinc-500'} />
                {label}
              </Component>
            );
          })}
        </nav>

        {/* Stats */}
        <div className="p-4 mx-3 mb-3 rounded-lg bg-[#0a0a0f]/60 border border-[#1e2030]/40">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium text-zinc-500 uppercase tracking-wider">Database</span>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 pulse-live" />
              <span className="text-[10px] text-emerald-500">Live</span>
            </div>
          </div>
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-xs text-zinc-500">Total CVEs</span>
              <span className="text-xs font-mono text-zinc-300">{totalCves.toLocaleString()}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-xs text-zinc-500">KEV Entries</span>
              <span className="text-xs font-mono text-red-400">{kevCount.toLocaleString()}</span>
            </div>
            {lastSync && (
              <div className="flex justify-between">
                <span className="text-xs text-zinc-500">Last Sync</span>
                <span className="text-[10px] font-mono text-zinc-400">
                  {new Date(lastSync).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Sync button */}
        <div className="p-3 border-t border-[#1e2030]/60">
          <button
            onClick={handleSync}
            disabled={syncing}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20 hover:bg-blue-500/20 transition-colors disabled:opacity-50"
          >
            <RefreshCw size={14} className={syncing ? 'animate-spin' : ''} />
            {syncing ? 'Syncing...' : 'Sync Now'}
          </button>
        </div>
      </aside>
    </>
  );
}
