import React, { useEffect, useRef, useState } from 'react';
import { Terminal, ArrowDown } from 'lucide-react';
import '../styles/app.css';

const LEVEL_COLORS = {
  INFO: '#5b9dd9',
  WARN: '#f2a93b',
  ERROR: '#ff6b6b',
  SUCCESS: '#35d0ba',
};

export default function AgentLogs({ logs = [] }) {
  const bodyRef = useRef(null);
  const [autoScroll, setAutoScroll] = useState(true);

  const safeLogs = logs || [];

  useEffect(() => {
    if (autoScroll && bodyRef.current) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
    }
  }, [safeLogs, autoScroll]);

  const handleScroll = () => {
    const el = bodyRef.current;
    if (!el) return;
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    setAutoScroll(nearBottom);
  };

  const jumpToLive = () => {
    setAutoScroll(true);
    if (bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
  };

  return (
    <div className="terminal">
      <div className="terminalHeader">
        <div className="terminalTitleRow">
          <Terminal size={14} />
          system_audit_feed.log
        </div>
        <div className="terminalDots">
          <span /><span /><span />
        </div>
      </div>

      <div className="terminalBody" ref={bodyRef} onScroll={handleScroll}>
        {safeLogs.length === 0 ? (
          <div className="emptyLog">
            No activity yet. Trigger an incident simulation to watch the agents work.
          </div>
        ) : (
          safeLogs.map((log) => (
            <div key={log.id || log.timestamp} className="logLine">
              <span className="logTime">{log.timestamp}</span>
              <span className="logLevel" style={{ color: LEVEL_COLORS[log.level] || '#7c8b9c' }}>
                {log.level}
              </span>
              <span className="logAgent">[{log.agent}]</span>
              <span className="logMsg">{log.message}</span>
            </div>
          ))
        )}
        {safeLogs.length > 0 && <span className="cursor" />}
        {!autoScroll && (
          <button className="jumpBtn" onClick={jumpToLive}>
            <ArrowDown size={11} style={{ verticalAlign: '-1px', marginRight: 4 }} />
            Jump to live
          </button>
        )}
      </div>
    </div>
  );
}