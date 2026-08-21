import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';

import Sidebar from './components/Sidebar';
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import Reports from './pages/Reports';
import Timeline from './pages/Timeline';
import './styles/app.css';

function App() {
  return (
    <BrowserRouter>
      <div className="appShell">
        <Sidebar />
        <div className="appMain">
          <Navbar />
          <main className="appContent">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/timeline" element={<Timeline />} />
            </Routes>
          </main>
        </div>
      </div>
    </BrowserRouter>
  );
}

export default App;