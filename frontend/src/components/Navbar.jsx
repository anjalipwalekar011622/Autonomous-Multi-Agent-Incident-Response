import React, { useState, useEffect } from 'react';
import { Sun, Moon } from 'lucide-react';
import '../styles/app.css';

export default function Navbar() {
  const [isLight, setIsLight] = useState(false);

  useEffect(() => {
    if (isLight) {
      document.body.classList.add('light-mode');
    } else {
      document.body.classList.remove('light-mode');
    }
  }, [isLight]);

  return (
    <header className="navbar" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
      <span className="navTitle">Incident Response Command Center</span>
      
      <div style={{ display: 'flex', gap: '15px', alignItems: 'center' }}>
        <button 
          onClick={() => setIsLight(!isLight)}
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--text-muted)',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '5px'
          }}
          title="Toggle Light/Dark Mode"
        >
          {isLight ? <Moon size={18} /> : <Sun size={18} />}
        </button>
        
        <span className="statusPill">
          <span className="pulseDot" />
          System Online
        </span>
      </div>
    </header>
  );
}