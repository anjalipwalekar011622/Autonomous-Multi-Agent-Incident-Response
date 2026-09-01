import React from 'react';
import { History } from 'lucide-react';
import '../styles/app.css';

export default function Timeline() {
  return (
    <div>
      <div className="pageHead">
        <div>
          <h1 className="pageTitle">Timeline</h1>
          <p className="pageSubtitle">chronological view of agent activity</p>
        </div>
      </div>
      <div className="placeholder">
        <History size={20} style={{ marginBottom: 8, opacity: 0.6 }} />
        <div>Timeline view is not built yet — this page is a routing placeholder.</div>
      </div>
    </div>
  );
}