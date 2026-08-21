import React from 'react';
import { Siren } from 'lucide-react';
import '../styles/app.css';

export default function Alerts() {
  return (
    <div>
      <div className="pageHead">
        <div>
          <h1 className="pageTitle">Alerts</h1>
          <p className="pageSubtitle">active and historical threat alerts</p>
        </div>
      </div>
      <div className="placeholder">
        <Siren size={20} style={{ marginBottom: 8, opacity: 0.6 }} />
        <div>Alert history view is not built yet — this page is a routing placeholder.</div>
      </div>
    </div>
  );
}