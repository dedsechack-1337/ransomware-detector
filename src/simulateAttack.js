/**
 * simulateAttack.js
 * -------------------
 * Simulates ransomware-like *behavior* against the watched directory
 * -- NO actual malware, encryption library, or C2 code is involved.
 * It purely reproduces the observable filesystem pattern so the
 * detection pipeline can be exercised safely:
 *
 *   1. overwrite each seeded file's content with high-entropy random
 *      bytes (crypto.randomBytes) -- mimicking what encryption looks
 *      like from the outside, without implementing any real cipher
 *   2. rename each overwritten file to a shared new extension
 *      (".locked") -- mimicking a mass extension change
 *   3. drop a ransom-note-styled file in each touched directory
 *   4. also touch any honeypot/canary files it stumbles across --
 *      exactly like real ransomware would, since it can't tell a
 *      decoy from a real document
 *
 * This never touches anything outside data/watched_directory, and
 * running simulateNormal.js's seed() again fully resets the demo.
 *
 * Usage:
 *   node src/simulateAttack.js [path/to/dir]
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const { WATCH_DIR } = require("./simulateNormal");

const NEW_EXTENSION = ".locked";

const RANSOM_NOTE_TEXT = `YOUR FILES HAVE BEEN ENCRYPTED

All your documents, photos, and databases have been encrypted with a
strong algorithm. To recover your files you must pay 0.5 BTC to the
wallet address below within 72 hours, or the price doubles.

Bitcoin wallet: [demo-only, not a real address]

Do not attempt to decrypt files yourself or contact law enforcement --
this will result in permanent data loss. Follow the instructions on
the Tor payment portal to restore your files after payment.
`;

function existingTargets(watchDir) {
  const out = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(p);
      } else if (!entry.name.endsWith(NEW_EXTENSION) && !entry.name.includes("README_DECRYPT")) {
        out.push(p);
      }
    }
  }
  if (fs.existsSync(watchDir)) walk(watchDir);
  return out;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function runAttack(watchDir = WATCH_DIR, delayRangeMs = [200, 500]) {
  const files = existingTargets(watchDir);
  if (files.length === 0) {
    console.log(`No files found under ${watchDir} -- run 'node src/simulateNormal.js seed' first.`);
    return { encrypted: 0, notesDropped: 0 };
  }

  console.log(`Simulating ransomware behavior against ${files.length} files in ${watchDir} ...`);

  const touchedDirs = new Set();

  for (const filePath of files) {
    const stat = fs.statSync(filePath);
    const size = Math.max(stat.size, 512);

    // 1. overwrite with high-entropy bytes (simulated "encryption")
    fs.writeFileSync(filePath, crypto.randomBytes(size));

    // 2. rename to the shared malicious extension
    const base = path.basename(filePath, path.extname(filePath));
    const finalPath = path.join(path.dirname(filePath), base + NEW_EXTENSION);
    fs.renameSync(filePath, finalPath);
    touchedDirs.add(path.dirname(finalPath));

    const [lo, hi] = delayRangeMs;
    await sleep(lo + Math.random() * (hi - lo));
  }

  // 3. drop a ransom note in every touched directory
  for (const dir of touchedDirs) {
    fs.writeFileSync(path.join(dir, "README_DECRYPT.txt"), RANSOM_NOTE_TEXT);
  }

  console.log(`Done. Encrypted+renamed ${files.length} files and dropped ${touchedDirs.size} ransom note(s).`);
  return { encrypted: files.length, notesDropped: touchedDirs.size };
}

module.exports = { runAttack };

if (require.main === module) {
  const target = process.argv[2] || WATCH_DIR;
  runAttack(target);
}
