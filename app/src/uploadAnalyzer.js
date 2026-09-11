/**
 * uploadAnalyzer.js
 * -------------------
 * Runs the same style of checks the live monitor uses (entropy,
 * ransom-note name/content patterns, suspicious extensions) but
 * against a single in-memory uploaded file instead of a filesystem
 * event stream. Used by the "Upload & analyze a file" panel.
 */

const path = require("path");
const { shannonEntropy, isHighEntropy, HIGH_ENTROPY_THRESHOLD } = require("./entropy");

const RANSOM_NOTE_NAME_RE =
  /(read[_\-]?me|decrypt|how[_\-]?to[_\-]?(decrypt|recover|restore)|recover[_\-]?files|restore[_\-]?files|your[_\-]?files|ransom)/i;

const RANSOM_NOTE_CONTENT_KEYWORDS = [
  "bitcoin", "decrypt", "private key", "ransom", "your files have been",
  "encrypted", "payment", "wallet address", "tor browser", "restore your files",
];

const SUSPICIOUS_EXTENSIONS = new Set([
  ".locked", ".encrypted", ".crypt", ".enc", ".crypted", ".locky",
  ".cerber", ".zzz", ".micro", ".xxx", ".wcry", ".wncry",
]);

const MAX_READ_BYTES = 65536;

function analyzeBuffer(originalName, buffer) {
  const safeName = path.basename(originalName || "upload");
  const ext = path.extname(safeName).toLowerCase();

  const sample = buffer.slice(0, MAX_READ_BYTES);
  const entropy = Math.round(shannonEntropy(sample) * 1000) / 1000;
  const highEntropy = isHighEntropy(entropy);

  const nameHit = RANSOM_NOTE_NAME_RE.test(path.basename(safeName, ext));

  let contentHit = false;
  let matchedKeywords = [];
  // Only worth reading as text if it isn't already flagged as high-entropy
  // binary content (encrypted/compressed data won't contain readable words).
  if (!highEntropy) {
    const text = buffer.slice(0, 4096).toString("utf-8").toLowerCase();
    matchedKeywords = RANSOM_NOTE_CONTENT_KEYWORDS.filter((kw) => text.includes(kw));
    contentHit = matchedKeywords.length > 0;
  }

  const suspiciousExt = SUSPICIOUS_EXTENSIONS.has(ext);

  const findings = [];
  let score = 0;

  if (highEntropy) {
    findings.push({
      rule: "HIGH_ENTROPY_CONTENT",
      severity: "high",
      detail: `File content has entropy ${entropy.toFixed(2)} bits/byte (threshold ${HIGH_ENTROPY_THRESHOLD}) -- consistent with encrypted or compressed data rather than a normal document.`,
    });
    score += 50;
  }
  if (nameHit) {
    findings.push({
      rule: "RANSOM_NOTE_FILENAME",
      severity: "critical",
      detail: `Filename "${safeName}" matches known ransom-note naming patterns (e.g. README, DECRYPT, RESTORE).`,
    });
    score += 40;
  }
  if (contentHit) {
    findings.push({
      rule: "RANSOM_NOTE_CONTENT",
      severity: "critical",
      detail: `File content contains ransom-note language: ${matchedKeywords.slice(0, 4).join(", ")}.`,
    });
    score += 40;
  }
  if (suspiciousExt) {
    findings.push({
      rule: "SUSPICIOUS_EXTENSION",
      severity: "medium",
      detail: `Extension "${ext}" is commonly used by ransomware families to mark encrypted files.`,
    });
    score += 20;
  }

  score = Math.min(score, 100);
  let verdict = "clean";
  if (score >= 70) verdict = "ransomware_likely";
  else if (score >= 30) verdict = "suspicious";

  return {
    filename: safeName,
    sizeBytes: buffer.length,
    entropy,
    highEntropy,
    verdict,
    score,
    findings,
  };
}

module.exports = { analyzeBuffer };
