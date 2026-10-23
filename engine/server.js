const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const app = express();

app.use(express.json());

// Initialize SQLite database connection
const db = new sqlite3.Database('./incidents.db', (err) => {
  if (err) {
    console.error('[-] Failed to connect to SQLite database:', err.message);
  } else {
    console.log('[+] Connected to SQLite database (incidents.db)');
  }
});

// Create database schema if not present
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    description TEXT,
    event_count INTEGER DEFAULT 1,
    severity TEXT NOT NULL,
    status TEXT DEFAULT 'OPEN',
    last_updated DATETIME NOT NULL
  )`);
});

// Ingestion API endpoint for Wazuh Python Webhook
app.post('/api/alerts', (req, res) => {
  const alert = req.body;
  
  // Extract payload parameters from Wazuh JSON structure
  const srcIp = alert.data?.srcip || alert.Agent?.ip || '127.0.0.1';
  const ruleId = alert.rule?.id || 'Unknown';
  const description = alert.rule?.description || 'Security Event Detected';
  const now = new Date().toISOString();

  // Query existing open incidents matching same source IP and rule ID
  db.get(
    `SELECT * FROM incidents WHERE src_ip = ? AND rule_id = ? AND status = 'OPEN'`,
    [srcIp, ruleId],
    (err, row) => {
      if (err) {
        console.error('[-] Database query error:', err.message);
        return res.status(500).send({ error: 'Database error' });
      }

      if (row) {
        // Increment event counter and evaluate severity escalation
        const newCount = row.event_count + 1;
        const newSeverity = newCount >= 3 ? 'HIGH' : (ruleId === '100001' ? 'MEDIUM' : 'LOW');

        db.run(
          `UPDATE incidents SET event_count = ?, severity = ?, last_updated = ? WHERE id = ?`,
          [newCount, newSeverity, now, row.id],
          (updateErr) => {
            if (updateErr) console.error('[-] Database update error:', updateErr.message);
            else console.log(`[+] Incident ID ${row.id} [Rule ${ruleId}] updated: ${newCount} events from ${srcIp}`);
          }
        );
      } else {
        // Register new incident entry
        const initialSeverity = ruleId === '100001' ? 'MEDIUM' : 'LOW';
        
        db.run(
          `INSERT INTO incidents (src_ip, rule_id, description, event_count, severity, status, last_updated) 
           VALUES (?, ?, ?, 1, ?, 'OPEN', ?)`,
          [srcIp, ruleId, description, initialSeverity, now],
          function (insertErr) {
            if (insertErr) console.error('[-] Database insert error:', insertErr.message);
            else console.log(`[+] New Incident created (ID: ${this.lastID}) for Rule ${ruleId} from IP: ${srcIp}`);
          }
        );
      }
    }
  );

  res.status(200).send({ status: 'received' });
});

// API endpoint to clear incidents for demo resets
app.post('/api/clear', (req, res) => {
  db.run(`DELETE FROM incidents`, (err) => {
    if (err) {
      console.error('[-] Error clearing database:', err.message);
      return res.status(500).send('Error resetting database');
    }
    console.log('[!] Dashboard cleared via user request');
    res.redirect('/dashboard');
  });
});

// HTML Web Dashboard endpoint
app.get('/dashboard', (req, res) => {
  db.all(`SELECT * FROM incidents ORDER BY last_updated DESC`, [], (err, rows) => {
    if (err) {
      return res.status(500).send('Database error loading dashboard');
    }

    const tableRows = (rows || []).map(r => `
      <tr style="border-bottom: 1px solid #e2e8f0;">
        <td style="padding: 12px;">#${r.id}</td>
        <td style="padding: 12px; font-family: monospace;"><b>${r.src_ip}</b></td>
        <td style="padding: 12px;"><span style="background: #edf2f7; padding: 2px 6px; border-radius: 4px; font-family: monospace;">${r.rule_id}</span></td>
        <td style="padding: 12px;">${r.description}</td>
        <td style="padding: 12px; text-align: center;"><b>${r.event_count}</b></td>
        <td style="padding: 12px;">
          <span style="background: ${r.severity === 'HIGH' ? '#fed7d7' : (r.severity === 'MEDIUM' ? '#feebc8' : '#e2e8f0')}; 
                       color: ${r.severity === 'HIGH' ? '#9b2c2c' : (r.severity === 'MEDIUM' ? '#744210' : '#2d3748')}; 
                       padding: 4px 8px; border-radius: 4px; font-weight: bold;">
            ${r.severity}
          </span>
        </td>
        <td style="padding: 12px;">${r.status}</td>
        <td style="padding: 12px; color: #718096; font-size: 13px;">${r.last_updated}</td>
      </tr>
    `).join('');

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>KloudSentinel - Incident Dashboard</title>
        <meta http-equiv="refresh" content="3">
        <style>
          body { font-family: system-ui, -apple-system, sans-serif; margin: 40px; background: #f7fafc; color: #2d3748; }
          .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
          h1 { margin: 0; font-size: 24px; }
          .card { background: white; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); overflow: hidden; }
          table { width: 100%; border-collapse: collapse; text-align: left; }
          th { background: #2b6cb0; color: white; padding: 14px; font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; }
          .badge { font-size: 12px; color: #718096; }
          .btn-clear { background: #e53e3e; color: white; border: none; padding: 8px 14px; border-radius: 6px; cursor: pointer; font-weight: bold; }
          .btn-clear:hover { background: #c53030; }
        </style>
      </head>
      <body>
        <div class="header">
          <div>
            <h1>🛡️ KloudSentinel Security Incidents</h1>
            <p class="badge">Live Multi-Rule Correlation Engine Output (Auto-refreshes every 3s)</p>
          </div>
          <form action="/api/clear" method="POST">
            <button type="submit" class="btn-clear">🗑️ Clear Dashboard</button>
          </form>
        </div>
        <div class="card">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Source IP</th>
                <th>Rule ID</th>
                <th>Event Description</th>
                <th>Count</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Last Updated</th>
              </tr>
            </thead>
            <tbody>
              ${tableRows || '<tr><td colspan="8" style="padding: 24px; text-align: center; color: #a0aec0;">No security incidents created yet.</td></tr>'}
            </tbody>
          </table>
        </div>
      </body>
      </html>
    `);
  });
});

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[+] KloudSentinel Engine active on port ${PORT}`);
});