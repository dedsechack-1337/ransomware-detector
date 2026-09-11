/**
 * detect.js
 * ----------
 * Orchestrates the full detection pipeline: raw events -> rule
 * engine + honeypot check + statistical anomaly scorer -> one
 * unified report. This is what server.js polls, and it's also
 * runnable standalone for a CLI report.
 *
 * Usage:
 *   node src/detect.js [path/to/watch_dir] [duration_seconds]
 */

const { FileMonitor } = require("./fileMonitor");
const { runAllRules } = require("./ruleEngine");
const { seedCanaries, checkCanaryHits } = require("./honeypot");
const { AnomalyScorer, buildSessionTable } = require("./statsAnomaly");

const SEVERITY_WEIGHT = { low: 10, medium: 30, high: 60, critical: 90 };

function buildReport(events, scorer, config) {
  if (!events || events.length === 0) {
    return {
      alerts: [],
      sessions: [],
      summary: { totalEvents: 0, filesTouched: 0, alerts: 0, overallRisk: 0, verdict: "quiet" },
    };
  }

  const ruleAlerts = runAllRules(events, config);
  const honeypotAlerts = checkCanaryHits(events, scorer.canaryPaths || []);
  const alerts = [...honeypotAlerts, ...ruleAlerts];

  const sessions = buildSessionTable(events, scorer);

  const allPaths = new Set();
  for (const e of events) {
    allPaths.add(e.path);
    if (e.fromPath) allPaths.add(e.fromPath);
  }

  const ruleRisk = Math.min(
    100,
    alerts.reduce((sum, a) => sum + (SEVERITY_WEIGHT[a.severity] || 20), 0)
  );
  const mlRisk = sessions.length ? Math.max(...sessions.map((s) => s.anomalyScore)) : 0;
  const overallRisk = Math.round(Math.max(ruleRisk, mlRisk * 0.9) * 10) / 10;

  let verdict = "normal";
  if (overallRisk >= 70) verdict = "ransomware_likely";
  else if (overallRisk >= 35) verdict = "suspicious";

  const sortedAlerts = [...alerts].sort(
    (a, b) => (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0)
  );

  return {
    alerts: sortedAlerts,
    sessions,
    summary: {
      totalEvents: events.length,
      filesTouched: allPaths.size,
      alerts: alerts.length,
      overallRisk,
      verdict,
    },
  };
}

module.exports = { buildReport, SEVERITY_WEIGHT };

if (require.main === module) {
  (async () => {
    const watchDir = process.argv[2] || "data/watched_directory";
    const duration = parseInt(process.argv[3] || "20", 10);

    const monitor = new FileMonitor(watchDir).start();
    const scorer = new AnomalyScorer();
    scorer.canaryPaths = seedCanaries(watchDir);

    console.log(`Watching ${watchDir} for ${duration}s -- run simulateAttack.js in another terminal.\n`);
    await new Promise((r) => setTimeout(r, duration * 1000));

    const events = monitor.getEvents();
    monitor.stop();

    const report = buildReport(events, scorer);
    const s = report.summary;
    console.log(`Events captured: ${s.totalEvents} | Files touched: ${s.filesTouched}`);
    console.log(`Overall risk: ${s.overallRisk}/100 -- verdict: ${s.verdict.toUpperCase()}\n`);

    if (report.alerts.length) {
      console.log("=".repeat(78));
      console.log("ALERTS");
      console.log("=".repeat(78));
      for (const a of report.alerts) {
        console.log(`[${a.severity.toUpperCase().padEnd(8)}] ${a.type.padEnd(24)} ${a.detail}`);
      }
    } else {
      console.log("No alerts raised.");
    }
    process.exit(0);
  })();
}
