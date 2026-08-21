import React from 'react';
import { FileBarChart } from 'lucide-react';
import '../styles/app.css';

export default function Reports() {
  return (
    <div>
      <div className="pageHead">
        <div>
          <h1 className="pageTitle">Reports</h1>
          <p className="pageSubtitle">exportable incident summaries</p>
        </div>
      </div>
      <div className="placeholder">
        <FileBarChart size={20} style={{ marginBottom: 8, opacity: 0.6 }} />
        <div>Reports view is not built yet — this page is a routing placeholder.</div>
      </div>
    </div>
  );
}