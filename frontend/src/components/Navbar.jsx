import React from 'react';
import '../styles/app.css';

export default function Navbar() {
  return (
    <header className="navbar">
      <span className="navTitle">Incident Response Command Center</span>
      <span className="statusPill">
        <span className="pulseDot" />
        System Online
      </span>
    </header>
  );
}