/**
 * ruleEngine.js
 * ---------------
 * Pattern-based detection rules over a window of enriched file
 * events from fileMonitor.js. These catch the well-known behavioral
 * fingerprint of ransomware, independent of any specific malware
 * family:
 *
 *   1. MASS_EXTENSION_CHANGE   - many files renamed to the same new,
 *                                previously-unseen extension in a
 *                                short window
 *   2. HIGH_ENTROPY_BURST      - many files rewritten with high-
 *                                entropy (encrypted-looking) content
 *                                in a short window
 *   3. RANSOM_NOTE_DROPPED     - a new file matches known ransom-note
 *                                name/content patterns
 *   4. MASS_MODIFICATION_BURST - a very high rate of file events
 *                                against the tree in a short window
 *   5. DELETE_AFTER_ENCRYPT    - a file is deleted shortly after a
 *                                high-entropy same-named file appeared
 *
 * (Honeypot triggers are handled separately in honeypot.js -- they
 * don't need a threshold or window, any single touch is conclusive.)
 */

const fs = require("fs");
const path = require("path");
const { HIGH_ENTROPY_THRESHOLD } = require("./entropy");

const DEFAULT_CONFIG = {
  windowMs: 15000,
  massExtensionMinFiles: 6,
  highEntropyMinFiles: 6,
  burstMinEvents: 20,
  deleteAfterEncryptMs: 10000,
};

const RANSOM_NOTE_NAME_RE =
  /(read[_\-]?me|decrypt|how[_\-]?to[_\-]?(decrypt|recover|restore)|recover[_\-]?files|restore[_\-]?files|your[_\-]?files|ransom)/i;

const RANSOM_NOTE_CONTENT_KEYWORDS = [
  "bitcoin", "decrypt", "private key", "ransom", "your files have been",
  "encrypted", "payment", "wallet address", "tor browser", "restore your files",
];

const BENIGN_EXTENSIONS = new Set([
  "", ".txt", ".log", ".tmp", ".bak", ".doc", ".docx", ".xls", ".xlsx",
  ".ppt", ".pptx", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".csv",
  ".json", ".xml", ".zip", ".js", ".md", ".ini", ".cfg",
]);

function slidingPeak(sortedTimestamps, windowMs) {
  let left = 0;
  let peak = 0;
  let peakRight = -1;
  for (let right = 0; right < sortedTimestamps.length; right++) {
    while (sortedTimestamps[right] - sortedTimestamps[left] > windowMs / 1000) {
      left++;
    }
    const count = right - left + 1;
    if (count > peak) {
      peak = count;
      peakRight = right;
    }
  }
  return { peak, peakRight, peakLeft: peakRight >= 0 ? peakRight - peak + 1 : -1 };
}

function looksLikeRansomNoteName(filePath) {
  return RANSOM_NOTE_NAME_RE.test(path.basename(filePath));
}

function contentMatchesRansomNote(filePath, maxBytes = 4096) {
  try {
    const buf = fs.readFileSync(filePath, { encoding: "utf-8", flag: "r" });
    const content = buf.slice(0, maxBytes).toLowerCase();
    return RANSOM_NOTE_CONTENT_KEYWORDS.some((kw) => content.includes(kw));
  } catch (_) {
    return false;
  }
}

function detectMassExtensionChange(events, config) {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const alerts = [];

  const renames = events.filter(
    (e) => e.type === "renamed" && e.extension && e.extension !== e.fromExtension
  );

  const byExt = new Map();
  for (const e of renames) {
    if (BENIGN_EXTENSIONS.has(e.extension)) continue;
    if (!byExt.has(e.extension)) byExt.set(e.extension, []);
    byExt.get(e.extension).push(e);
  }

  for (const [ext, group] of byExt.entries()) {
    group.sort((a, b) => a.timestamp - b.timestamp);
    const timestamps = group.map((e) => e.timestamp);
    const { peak, peakLeft, peakRight } = slidingPeak(timestamps, cfg.windowMs);

    if (peak >= cfg.massExtensionMinFiles) {
      const windowEvents = group.slice(peakLeft, peakRight + 1);
      alerts.push({
        type: "MASS_EXTENSION_CHANGE",
        severity: peak >= cfg.massExtensionMinFiles * 2 ? "critical" : "high",
        detail: `${peak} files renamed to '${ext}' within ${cfg.windowMs / 1000}s -- classic ransomware encryption sweep.`,
        count: peak,
        extension: ext,
        samplePaths: windowEvents.slice(0, 5).map((e) => e.path),
        windowEnd: windowEvents[windowEvents.length - 1].timestamp,
      });
    }
  }

  return alerts;
}

function detectHighEntropyBurst(events, config) {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const rewrites = events
    .filter((e) => ["add", "change", "renamed"].includes(e.type) && e.entropy >= HIGH_ENTROPY_THRESHOLD)
    .sort((a, b) => a.timestamp - b.timestamp);

  if (rewrites.length === 0) return [];

  const timestamps = rewrites.map((e) => e.timestamp);
  const { peak, peakLeft, peakRight } = slidingPeak(timestamps, cfg.windowMs);

  if (peak < cfg.highEntropyMinFiles) return [];

  const windowEvents = rewrites.slice(peakLeft, peakRight + 1);
  return [{
    type: "HIGH_ENTROPY_BURST",
    severity: peak >= cfg.highEntropyMinFiles * 2 ? "critical" : "high",
    detail: `${peak} files rewritten with encrypted-looking content (entropy >= ${HIGH_ENTROPY_THRESHOLD}) within ${cfg.windowMs / 1000}s.`,
    count: peak,
    samplePaths: windowEvents.slice(0, 5).map((e) => e.path),
    windowEnd: windowEvents[windowEvents.length - 1].timestamp,
  }];
}

function detectRansomNote(events) {
  const alerts = [];
  for (const e of events) {
    if (e.type !== "add") continue;
    const nameHit = looksLikeRansomNoteName(e.path);
    const contentHit =
      [".txt", ".html", ".htm", ".hta", ""].includes(e.extension) &&
      contentMatchesRansomNote(e.path);

    if (nameHit || contentHit) {
      alerts.push({
        type: "RANSOM_NOTE_DROPPED",
        severity: "critical",
        detail: `New file '${path.basename(e.path)}' matches known ransom-note ${nameHit ? "filename" : "content"} patterns.`,
        count: 1,
        samplePaths: [e.path],
        windowEnd: e.timestamp,
      });
    }
  }
  return alerts;
}

function detectMassModificationBurst(events, config) {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const relevant = events
    .filter((e) => ["add", "change", "unlink", "renamed"].includes(e.type))
    .sort((a, b) => a.timestamp - b.timestamp);

  if (relevant.length === 0) return [];

  const timestamps = relevant.map((e) => e.timestamp);
  const { peak, peakRight } = slidingPeak(timestamps, cfg.windowMs);

  if (peak < cfg.burstMinEvents) return [];

  return [{
    type: "MASS_MODIFICATION_BURST",
    severity: peak >= cfg.burstMinEvents * 2 ? "critical" : "high",
    detail: `${peak} file events within ${cfg.windowMs / 1000}s -- unusually fast filesystem activity consistent with an automated sweep.`,
    count: peak,
    samplePaths: [],
    windowEnd: relevant[peakRight].timestamp,
  }];
}

function detectDeleteAfterEncrypt(events, config) {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const alerts = [];

  const stem = (p) => path.basename(p, path.extname(p));

  const highEntropyWrites = events.filter(
    (e) => ["add", "change"].includes(e.type) && e.entropy >= HIGH_ENTROPY_THRESHOLD
  );
  const deletes = events.filter((e) => e.type === "unlink");

  for (const d of deletes) {
    const dStem = stem(d.path);
    const dDir = path.dirname(d.path);
    for (const c of highEntropyWrites) {
      const withinWindow =
        d.timestamp - c.timestamp >= 0 &&
        d.timestamp - c.timestamp <= cfg.deleteAfterEncryptMs / 1000;

      if (path.dirname(c.path) === dDir && stem(c.path) === dStem && withinWindow) {
        alerts.push({
          type: "DELETE_AFTER_ENCRYPT",
          severity: "critical",
          detail: `'${path.basename(d.path)}' was deleted shortly after an encrypted-looking copy appeared -- likely original-file cleanup.`,
          count: 1,
          samplePaths: [d.path, c.path],
          windowEnd: d.timestamp,
        });
        break;
      }
    }
  }

  return alerts;
}

function runAllRules(events, config) {
  if (!events || events.length === 0) return [];
  return [
    ...detectMassExtensionChange(events, config),
    ...detectHighEntropyBurst(events, config),
    ...detectRansomNote(events),
    ...detectMassModificationBurst(events, config),
    ...detectDeleteAfterEncrypt(events, config),
  ];
}

module.exports = {
  DEFAULT_CONFIG,
  runAllRules,
  detectMassExtensionChange,
  detectHighEntropyBurst,
  detectRansomNote,
  detectMassModificationBurst,
  detectDeleteAfterEncrypt,
};
