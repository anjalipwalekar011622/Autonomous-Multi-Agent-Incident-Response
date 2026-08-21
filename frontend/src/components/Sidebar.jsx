import React from 'react';
import { NavLink } from 'react-router-dom';
import { ShieldCheck, LayoutDashboard, Siren, FileBarChart, History } from 'lucide-react';
import '../styles/app.css';

const LINKS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/alerts', label: 'Alerts', icon: Siren },
  { to: '/reports', label: 'Reports', icon: FileBarChart },
  { to: '/timeline', label: 'Timeline', icon: History },
];

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebarBrand">
        <div className="sidebarLogo">
          <ShieldCheck size={16} strokeWidth={2.25} />
        </div>
        <div>
          <div className="sidebarBrandText">Incident Response</div>
          <div className="sidebarBrandSub">multi-agent engine</div>
        </div>
      </div>

      {LINKS.map(({ to, label, icon: Icon, end }) => (
        <NavLink
          key={to}
          to={to}
          end={end}
          className={({ isActive }) =>
            `sidebarLink${isActive ? ' sidebarLinkActive' : ''}`
          }
        >
          <Icon size={15} strokeWidth={2.1} />
          {label}
        </NavLink>
      ))}
    </aside>
  );
}