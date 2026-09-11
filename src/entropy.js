/**
 * entropy.js
 * -----------
 * Shannon entropy helpers used to distinguish normal file content
 * (text, office docs -- typically 3-6 bits/byte) from encrypted or
 * compressed content (typically 7.5-8 bits/byte, since ciphertext
 * looks like uniform random noise).
 */

const fs = require("fs");

const MAX_READ_BYTES = 65536;
const HIGH_ENTROPY_THRESHOLD = 7.5;

/**
 * Returns the Shannon entropy of a Buffer in bits per byte (0-8).
 */
function shannonEntropy(buffer) {
  if (!buffer || buffer.length === 0) return 0.0;

  const counts = new Array(256).fill(0);
  for (let i = 0; i < buffer.length; i++) {
    counts[buffer[i]]++;
  }

  const length = buffer.length;
  let entropy = 0.0;
  for (const count of counts) {
    if (count === 0) continue;
    const p = count / length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Reads up to MAX_READ_BYTES from the start of a file and returns its
 * Shannon entropy. Returns -1 if the file can't be read (e.g. it was
 * deleted between the event firing and this read, or it's a directory).
 */
function fileEntropy(path, maxBytes = MAX_READ_BYTES) {
  try {
    const stat = fs.statSync(path);
    if (!stat.isFile()) return -1;

    const fd = fs.openSync(path, "r");
    const size = Math.min(stat.size, maxBytes);
    const buffer = Buffer.alloc(size);
    fs.readSync(fd, buffer, 0, size, 0);
    fs.closeSync(fd);

    return Math.round(shannonEntropy(buffer) * 1000) / 1000;
  } catch (err) {
    return -1;
  }
}

function isHighEntropy(entropy) {
  return entropy >= HIGH_ENTROPY_THRESHOLD;
}

module.exports = { shannonEntropy, fileEntropy, isHighEntropy, HIGH_ENTROPY_THRESHOLD };

if (require.main === module) {
  const crypto = require("crypto");
  const text = Buffer.from("the quick brown fox jumps over the lazy dog ".repeat(20));
  const repeated = Buffer.from("A".repeat(24));
  const random = crypto.randomBytes(4096);

  console.log("Plain English text:  ", shannonEntropy(text).toFixed(3));
  console.log("Repeated bytes:      ", shannonEntropy(repeated).toFixed(3));
  console.log("Pseudo-random bytes: ", shannonEntropy(random).toFixed(3));
}
