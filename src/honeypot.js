/**
 * honeypot.js
 * -------------
 * Canary-file trap -- a detection technique distinct from the
 * content/rate-based rules in ruleEngine.js. A handful of decoy files
 * with ordinary-looking names are seeded into every watched
 * subdirectory. A real user never has a reason to touch them, but
 * ransomware indiscriminately walks the whole tree and encrypts
 * everything it finds -- including the decoys.
 *
 * Any create/change/rename/delete event on a canary path is treated
 * as a near-certain positive: there's no plausible legitimate
 * explanation, so this fires at CRITICAL severity with no threshold
 * or time window involved, unlike every other rule in this project.
 */

const fs = require("fs");
const path = require("path");

const CANARY_NAMES = [
  "Family_Photos_2023.jpg",
  "Tax_Documents_2022.pdf",
  "Passwords_Backup.txt",
  "Company_Financials_Q4.xlsx",
];

// Plausible-looking placeholder content -- just needs to exist and
// look like a normal small file, not actually be a real photo/pdf.
const CANARY_CONTENT =
  "This is a decoy file used for ransomware detection. " +
  "It is not a real document. If you are a human user, please " +
  "do not open, edit, move, or delete this file.\n";

function seedCanaries(watchDir) {
  const canaryPaths = [];
  const dirs = _allDirs(watchDir);

  for (const dir of dirs) {
    // one canary per directory is plenty -- keeps the decoy density
    // low enough that a real user is very unlikely to stumble on one
    const name = CANARY_NAMES[Math.floor(Math.random() * CANARY_NAMES.length)];
    const canaryPath = path.join(dir, `.${name}`); // dotfile-ish, low visibility
    fs.writeFileSync(canaryPath, CANARY_CONTENT);
    canaryPaths.push(path.resolve(canaryPath));
  }

  return canaryPaths;
}

function _allDirs(root) {
  const out = [root];
  const entries = fs.readdirSync(root, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory()) {
      out.push(...(_allDirs(path.join(root, entry.name))));
    }
  }
  return out;
}

/**
 * Given the event log and the set of canary paths, returns alerts for
 * any event that touched a canary -- checking `path` and, for renamed
 * events, `fromPath` too (a canary that got renamed/encrypted still
 * counts, even though its new path is no longer in the canary set).
 */
function checkCanaryHits(events, canaryPaths) {
  const canarySet = new Set(canaryPaths.map((p) => path.resolve(p)));
  const alerts = [];

  for (const e of events) {
    const hitPath = e.path && canarySet.has(path.resolve(e.path));
    const hitFrom = e.fromPath && canarySet.has(path.resolve(e.fromPath));

    if (hitPath || hitFrom) {
      const touched = hitFrom ? e.fromPath : e.path;
      alerts.push({
        type: "HONEYPOT_TRIGGERED",
        severity: "critical",
        detail:
          `Decoy file '${path.basename(touched)}' was ${e.type} -- ` +
          `no legitimate process should ever touch this file. ` +
          `Near-certain ransomware activity.`,
        count: 1,
        samplePaths: [touched],
        windowEnd: e.timestamp,
      });
    }
  }

  return alerts;
}

module.exports = { seedCanaries, checkCanaryHits, CANARY_NAMES };
