/**
 * statsAnomaly.js
 * -----------------
 * Statistical anomaly scoring -- deliberately NOT a black-box ML
 * model this time. Instead of training an IsolationForest on
 * historical sessions, this maintains a running exponentially-
 * weighted moving average (EWMA) and variance for each behavioral
 * feature, updated continuously as normal activity happens, and
 * scores new activity sessions by how many standard deviations
 * (z-score) they sit above that adaptive baseline.
 *
 * Trade-offs versus the ML approach used in the Python version of
 * this project:
 *   + fully transparent -- every score can be explained as "feature X
 *     was N standard deviations above its recent baseline"
 *   + adapts continuously as the baseline updates itself online, no
 *     separate offline training step or model file needed
 *   + trivial to reason about and tune (just feature weights)
 *   - less able to capture multi-feature interactions than a forest
 *     of decision trees would
 *   - a genuinely bursty-but-legitimate workload (e.g. nightly batch
 *     jobs) will keep nudging the baseline up, which can gradually
 *     desensitize the detector -- mitigated by NORMAL_SESSION_CAP_Z
 *     below, which stops any single session (however large) from
 *     shifting the baseline by more than a bounded amount.
 */

const SESSION_GAP_SECONDS = 20;
const EWMA_ALPHA = 0.2; // weight given to each new observation
const NORMAL_SESSION_CAP_Z = 1.5; // sessions this anomalous don't update the baseline

// Features here are mostly small counts/rates (files touched, events
// per second, etc). A variance floor that's too tight makes trivial,
// completely normal fluctuation (e.g. editing 1 file vs 2) register
// as many standard deviations away. This floor is deliberately
// generous relative to the scale of these features.
const MIN_VARIANCE = 0.35;

const FEATURES = [
  "filesTouched",
  "eventsPerSecond",
  "uniqueDirsTouched",
  "uniqueNewExtensions",
  "pctHighEntropy",
  "deleteCount",
  "renameCount",
];

class BaselineStats {
  constructor() {
    this.mean = {};
    this.variance = {};
    this.initialized = {};
    for (const f of FEATURES) {
      this.mean[f] = 0;
      this.variance[f] = 1; // avoid div-by-zero before any data arrives
      this.initialized[f] = false;
    }
  }

  update(features) {
    for (const f of FEATURES) {
      const x = features[f] || 0;
      if (!this.initialized[f]) {
        this.mean[f] = x;
        this.variance[f] = 1;
        this.initialized[f] = true;
        continue;
      }
      const delta = x - this.mean[f];
      this.mean[f] += EWMA_ALPHA * delta;
      // EWMA variance update
      this.variance[f] =
        (1 - EWMA_ALPHA) * (this.variance[f] + EWMA_ALPHA * delta * delta);
      if (this.variance[f] < MIN_VARIANCE) this.variance[f] = MIN_VARIANCE; // floor
    }
  }

  zScore(features) {
    const scores = {};
    for (const f of FEATURES) {
      const x = features[f] || 0;
      const std = Math.sqrt(this.variance[f]);
      scores[f] = (x - this.mean[f]) / std;
    }
    return scores;
  }

  toJSON() {
    return { mean: this.mean, variance: this.variance };
  }
}

function splitIntoSessions(events, gapSeconds = SESSION_GAP_SECONDS) {
  if (!events || events.length === 0) return [];
  const sorted = [...events].sort((a, b) => a.timestamp - b.timestamp);
  const sessions = [[sorted[0]]];
  for (let i = 1; i < sorted.length; i++) {
    const last = sessions[sessions.length - 1];
    if (sorted[i].timestamp - last[last.length - 1].timestamp > gapSeconds) {
      sessions.push([]);
    }
    sessions[sessions.length - 1].push(sorted[i]);
  }
  return sessions;
}

function _dirname(p) {
  const idx = p.lastIndexOf("/");
  return idx === -1 ? p : p.slice(0, idx);
}

function sessionFeatures(session) {
  const paths = new Set();
  const dirs = new Set();
  for (const e of session) {
    paths.add(e.path);
    if (e.fromPath) paths.add(e.fromPath);
    dirs.add(_dirname(e.path));
  }

  const duration = Math.max(
    session[session.length - 1].timestamp - session[0].timestamp,
    0.5
  );

  const newExts = new Set(
    session
      .filter((e) => e.type === "renamed" && e.extension !== e.fromExtension)
      .map((e) => e.extension)
  );

  const entropyVals = session.filter((e) => e.entropy >= 0).map((e) => e.entropy);
  const pctHighEntropy = entropyVals.length
    ? entropyVals.filter((v) => v >= 7.5).length / entropyVals.length
    : 0;

  return {
    filesTouched: paths.size,
    eventsPerSecond: session.length / duration,
    uniqueDirsTouched: dirs.size,
    uniqueNewExtensions: newExts.size,
    pctHighEntropy,
    deleteCount: session.filter((e) => e.type === "unlink").length,
    renameCount: session.filter((e) => e.type === "renamed").length,
    startTime: session[0].timestamp,
    endTime: session[session.length - 1].timestamp,
    eventCount: session.length,
  };
}

// Feature weights for combining z-scores into one anomaly score.
// Rename/extension-change and entropy carry the most ransomware
// signal; raw file count matters less on its own.
const FEATURE_WEIGHTS = {
  filesTouched: 0.8,
  eventsPerSecond: 1.2,
  uniqueDirsTouched: 0.6,
  uniqueNewExtensions: 1.5,
  pctHighEntropy: 1.5,
  deleteCount: 1.0,
  renameCount: 1.3,
};

class AnomalyScorer {
  constructor() {
    this.baseline = new BaselineStats();
  }

  /** Feeds a session into the running baseline (call for normal activity). */
  observe(features) {
    const z = this.baseline.zScore(features);
    const maxAbsZ = Math.max(...Object.values(z).map(Math.abs));
    // don't let wildly anomalous sessions drag the baseline toward them
    if (maxAbsZ <= NORMAL_SESSION_CAP_Z) {
      this.baseline.update(features);
    } else {
      // still nudge gently so the baseline isn't frozen forever, but
      // by much less than a full update
      const dampened = {};
      for (const f of FEATURES) {
        dampened[f] = this.baseline.mean[f] + 0.1 * ((features[f] || 0) - this.baseline.mean[f]);
      }
      this.baseline.update(dampened);
    }
  }

  /** Scores a session against the current baseline without updating it. */
  score(features) {
    const z = this.baseline.zScore(features);
    let weightedSum = 0;
    let weightTotal = 0;
    for (const f of FEATURES) {
      const w = FEATURE_WEIGHTS[f] || 1;
      weightedSum += Math.max(z[f], 0) * w; // only positive deviations count as "more suspicious"
      weightTotal += w;
    }
    const avgWeightedZ = weightedSum / weightTotal;

    // squash the weighted z-score into a friendly 0-100 range;
    // z=0 -> 0, z=1 -> ~40, z=2 -> ~70, z=3+ -> approaches 100
    const score = 100 * (1 - Math.exp(-avgWeightedZ / 1.8));

    return {
      score: Math.round(Math.min(score, 100) * 10) / 10,
      zScores: z,
      isAnomaly: score >= 50,
    };
  }

  seedFromNormalSessions(sessionsFeatures) {
    for (const f of sessionsFeatures) this.observe(f);
  }
}

function buildSessionTable(events, scorer) {
  const sessions = splitIntoSessions(events);
  return sessions.map((s) => {
    const features = sessionFeatures(s);
    const { score, isAnomaly } = scorer.score(features);
    return { ...features, anomalyScore: score, isAnomaly };
  });
}

/**
 * Generates a batch of synthetic "normal" session feature vectors
 * with realistic variety -- mostly single quick saves, some back-to-
 * back edits of the same file, and an occasional small legitimate
 * batch (e.g. copying a handful of files) -- so a freshly-started
 * AnomalyScorer has a sensible, non-degenerate baseline to compare
 * against immediately, rather than starting from all-zero variance.
 * (In a long-running deployment, `observe()` on real traffic would
 * eventually make this unnecessary, but it avoids a cold-start
 * false-positive spike on day one.)
 */
function generateSyntheticNormalSessions(n = 40) {
  const sessions = [];
  for (let i = 0; i < n; i++) {
    const roll = Math.random();
    if (roll < 0.7) {
      sessions.push({
        filesTouched: 1,
        eventsPerSecond: 0.2 + Math.random() * 1.5,
        uniqueDirsTouched: 1,
        uniqueNewExtensions: 0,
        pctHighEntropy: Math.random() * 0.15,
        deleteCount: 0,
        renameCount: 0,
      });
    } else if (roll < 0.9) {
      const n_ = 2 + Math.floor(Math.random() * 3);
      sessions.push({
        filesTouched: 1,
        eventsPerSecond: n_ / (5 + Math.random() * 10),
        uniqueDirsTouched: 1,
        uniqueNewExtensions: 0,
        pctHighEntropy: Math.random() * 0.15,
        deleteCount: 0,
        renameCount: 0,
      });
    } else {
      const n_ = 3 + Math.floor(Math.random() * 4);
      sessions.push({
        filesTouched: n_,
        eventsPerSecond: n_ / (2 + Math.random() * 3),
        uniqueDirsTouched: 1 + Math.floor(Math.random() * 2),
        uniqueNewExtensions: 0,
        pctHighEntropy: Math.random() * 0.15,
        deleteCount: 0,
        renameCount: 0,
      });
    }
  }
  return sessions;
}

module.exports = {
  FEATURES,
  BaselineStats,
  AnomalyScorer,
  splitIntoSessions,
  sessionFeatures,
  buildSessionTable,
  generateSyntheticNormalSessions,
};
