/**
 * fileMonitor.js
 * ----------------
 * Real-time filesystem monitor built on `chokidar`. Unlike Linux
 * inotify (used by Python's watchdog), chokidar has no native
 * "rename" event -- a rename surfaces as two separate events, and
 * critically, the ORDER isn't guaranteed: testing against this
 * project's own attack simulator showed chokidar firing `add`
 * *before* `unlink` for a rename, the opposite of what you'd assume.
 *
 * So pairing has to work bidirectionally: whichever of add/unlink
 * arrives first is held briefly (RENAME_PAIR_WINDOW_MS) waiting to
 * see if its counterpart (same directory + same base filename)
 * shows up; if so, the pair is merged into one synthetic `renamed`
 * event. This matters a lot for ransomware detection specifically,
 * since "many files renamed to the same new extension" is the single
 * strongest signal -- losing that signal to event-ordering quirks
 * would blind the mass-extension-change rule.
 */

const path = require("path");
const fs = require("fs");
const chokidar = require("chokidar");
const { fileEntropy } = require("./entropy");

const RENAME_PAIR_WINDOW_MS = 800;
const MAX_EVENTS = 5000;

function keyFor(filePath) {
  const dir = path.dirname(filePath);
  const stem = path.basename(filePath, path.extname(filePath));
  return `${dir}::${stem}`;
}

class FileMonitor {
  constructor(watchDir) {
    this.watchDir = watchDir;
    this.events = []; // finalized ring buffer of enriched events
    this.pendingAdds = new Map(); // key -> {event, timer}
    this.pendingUnlinks = new Map(); // key -> {event, timer}
    this.watcher = null;
  }

  _push(event) {
    this.events.push(event);
    if (this.events.length > MAX_EVENTS) this.events.shift();
  }

  _enrich(type, filePath) {
    const ext = path.extname(filePath).toLowerCase();
    let size = -1;
    let entropy = -1;

    if (type === "add" || type === "change") {
      try {
        size = fs.statSync(filePath).size;
      } catch (_) {
        /* file may already be gone */
      }
      entropy = fileEntropy(filePath);
    }

    return {
      timestamp: Date.now() / 1000,
      type, // 'add' | 'change' | 'unlink' | 'renamed'
      path: filePath,
      fromPath: null,
      extension: ext,
      fromExtension: "",
      size,
      entropy,
    };
  }

  _handleAdd(filePath) {
    const key = keyFor(filePath);
    const evt = this._enrich("add", filePath);

    // Case 1: a matching unlink already arrived first -- pair now.
    const pendingUnlink = this.pendingUnlinks.get(key);
    if (pendingUnlink) {
      clearTimeout(pendingUnlink.timer);
      this.pendingUnlinks.delete(key);
      this._push({
        ...evt,
        type: "renamed",
        fromPath: pendingUnlink.event.path,
        fromExtension: path.extname(pendingUnlink.event.path).toLowerCase(),
      });
      return;
    }

    // Case 2: hold this add briefly in case the unlink follows.
    const timer = setTimeout(() => {
      this.pendingAdds.delete(key);
      this._push(evt);
    }, RENAME_PAIR_WINDOW_MS);

    this.pendingAdds.set(key, { event: evt, timer });
  }

  _handleUnlink(filePath) {
    const key = keyFor(filePath);
    const evt = this._enrich("unlink", filePath);

    // Case 1: a matching add is already waiting -- pair now.
    const pendingAdd = this.pendingAdds.get(key);
    if (pendingAdd) {
      clearTimeout(pendingAdd.timer);
      this.pendingAdds.delete(key);
      this._push({
        ...pendingAdd.event,
        type: "renamed",
        fromPath: filePath,
        fromExtension: path.extname(filePath).toLowerCase(),
      });
      return;
    }

    // Case 2: hold this unlink briefly in case the add follows.
    const timer = setTimeout(() => {
      this.pendingUnlinks.delete(key);
      this._push(evt);
    }, RENAME_PAIR_WINDOW_MS);

    this.pendingUnlinks.set(key, { event: evt, timer });
  }

  start() {
    fs.mkdirSync(this.watchDir, { recursive: true });

    this.watcher = chokidar.watch(this.watchDir, {
      ignoreInitial: true,
      persistent: true,
      awaitWriteFinish: { stabilityThreshold: 80, pollInterval: 20 },
    });

    this.watcher.on("add", (filePath) => this._handleAdd(filePath));
    this.watcher.on("change", (filePath) => this._push(this._enrich("change", filePath)));
    this.watcher.on("unlink", (filePath) => this._handleUnlink(filePath));

    return this;
  }

  stop() {
    if (this.watcher) this.watcher.close();
    for (const { timer } of this.pendingAdds.values()) clearTimeout(timer);
    for (const { timer } of this.pendingUnlinks.values()) clearTimeout(timer);
  }

  getEvents(sinceTs = 0) {
    return this.events.filter((e) => e.timestamp >= sinceTs);
  }

  clear() {
    this.events = [];
  }
}

module.exports = { FileMonitor };

if (require.main === module) {
  const dir = process.argv[2] || "data/watched_directory";
  const monitor = new FileMonitor(dir).start();
  console.log(`Watching ${dir} -- press Ctrl+C to stop.`);

  let lastTs = 0;
  setInterval(() => {
    const events = monitor.getEvents(lastTs);
    for (const e of events) {
      const extra = e.fromPath ? ` (was ${e.fromPath})` : "";
      const ent = e.entropy >= 0 ? ` entropy=${e.entropy}` : "";
      console.log(`[${e.type.padEnd(8)}] ${e.path}${extra}${ent}`);
      lastTs = Math.max(lastTs, e.timestamp);
    }
  }, 500);
}
