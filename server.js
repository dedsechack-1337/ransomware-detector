/**
 * server.js
 * ----------
 * Express server for the Ransomware Behavior Detector dashboard.
 * Starts the filesystem monitor once at boot and keeps it running
 * for the life of the process, exposes the live event/alert state
 * over a small JSON API, and lets the dashboard trigger the (safe,
 * simulated) attack or reset the demo directory.
 *
 * Run:
 *   node server.js
 * Then open http://127.0.0.1:5004
 */

const path = require("path");
const fs = require("fs");
const express = require("express");

const { FileMonitor } = require("./src/fileMonitor");
const { seedCanaries } = require("./src/honeypot");
const { AnomalyScorer, generateSyntheticNormalSessions } = require("./src/statsAnomaly");
const { buildReport } = require("./src/detect");
const { seedFiles, existingFiles, WATCH_DIR } = require("./src/simulateNormal");
const { runAttack } = require("./src/simulateAttack");

const PORT = 5004;
const app = express();
app.use(express.static(path.join(__dirname, "public")));

let attackRunning = false;

function ensureSeeded() {
  if (existingFiles(WATCH_DIR).length === 0) {
    seedFiles(WATCH_DIR);
  }
}

ensureSeeded();
const monitor = new FileMonitor(WATCH_DIR).start();
const scorer = new AnomalyScorer();
scorer.canaryPaths = seedCanaries(WATCH_DIR);
scorer.seedFromNormalSessions(generateSyntheticNormalSessions(40));

app.get("/api/report", (req, res) => {
  const events = monitor.getEvents();
  const report = buildReport(events, scorer);
  res.json(report);
});

app.post("/api/simulate-attack", (req, res) => {
  if (attackRunning) {
    return res.status(409).json({ status: "already_running" });
  }
  attackRunning = true;
  runAttack(WATCH_DIR)
    .catch((err) => console.error("Attack simulation error:", err))
    .finally(() => { attackRunning = false; });

  res.json({ status: "started" });
});

app.post("/api/reset", (req, res) => {
  try {
    // Stop watching *before* the bulk filesystem churn -- otherwise
    // the reset's own mass delete+create looks exactly like a
    // ransomware burst to our own detector and self-triggers alerts.
    monitor.stop();

    fs.rmSync(WATCH_DIR, { recursive: true, force: true });
    seedFiles(WATCH_DIR);
    scorer.canaryPaths = seedCanaries(WATCH_DIR);
    monitor.clear();

    // ignoreInitial:true (set in FileMonitor.start) means restarting
    // the watcher won't fire events for these already-existing files.
    monitor.start();

    res.json({ status: "reset" });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", watching: WATCH_DIR });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`FileGuard (Node) listening on http://127.0.0.1:${PORT}`);
  console.log(`Watching ${WATCH_DIR}`);
});

process.on("SIGINT", () => {
  monitor.stop();
  process.exit(0);
});
