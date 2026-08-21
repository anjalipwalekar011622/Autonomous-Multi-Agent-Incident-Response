import React, { useEffect, useRef, useState } from 'react';
import { Terminal, ArrowDown } from 'lucide-react';
import '../styles/app.css';

const LEVEL_COLORS = {
  INFO: '#5b9dd9',
  WARN: '#f2a93b',
  ERROR: '#ff6b6b',
  SUCCESS: '#35d0ba',
};

/**
 * AgentLogs
 * Dark, monospace, terminal-style feed of system events.
 * Auto-scrolls to the newest entry unless the user has scrolled up to read
 * history — scrolling back down (or clicking "Jump to live") resumes it.
 *
 * Props:
 *  - logs: Array<{ id, timestamp, level: 'INFO'|'WARN'|'ERROR'|'SUCCESS', agent, message }>
 */
export default function AgentLogs({ logs }) {
  const bodyRef = useRef(null);
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    if (autoScroll && bodyRef.current) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

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
        {logs.length === 0 ? (
          <div className="emptyLog">
            No activity yet. Trigger an incident simulation to watch the agents work.
          </div>
        ) : (
          logs.map((log) => (
            <div key={log.id} className="logLine">
              <span className="logTime">{log.timestamp}</span>
              <span className="logLevel" style={{ color: LEVEL_COLORS[log.level] || '#7c8b9c' }}>
                {log.level}
              </span>
              <span className="logAgent">[{log.agent}]</span>
              <span className="logMsg">{log.message}</span>
            </div>
          ))
        )}
        {logs.length > 0 && <span className="cursor" />}
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