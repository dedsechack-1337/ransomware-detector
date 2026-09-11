/**
 * simulateNormal.js
 * -------------------
 * Seeds the watched directory with a handful of "documents" and can
 * simulate slow, human-paced editing so the anomaly baseline has
 * something realistic to learn from before an attack is ever run.
 *
 * Usage:
 *   node src/simulateNormal.js seed              # just create files
 *   node src/simulateNormal.js activity [secs]   # seed + slow edits
 */

const fs = require("fs");
const path = require("path");

const WATCH_DIR = path.join(__dirname, "..", "data", "watched_directory");

const SAMPLE_TEXTS = [
  "Quarterly Report\n\nRevenue grew 12% year over year, driven by strong performance in the enterprise segment.\n",
  "Meeting Notes - Project Falcon\n\nAttendees: Alice, Bob, Priya\n- Reviewed timeline for Q3 launch\n- Action item: finalize vendor contract\n",
  "Family Recipe - Sunday Pasta\n\nIngredients: tomatoes, garlic, basil, olive oil, pasta. Simmer 30 minutes, toss with pasta.\n",
  "Vacation Itinerary\n\nDay 1: Arrive, check into hotel\nDay 2: City tour and museum visit\nDay 3: Coastal drive\n",
  "Household Budget 2026\n\nRent: 1800\nUtilities: 220\nGroceries: 450\nSavings: 600\n",
  "Book Club Notes - Chapter 7\n\nThe protagonist's decision to return home marks a turning point in the narrative.\n",
];

const FILENAMES = [
  "quarterly_report.docx", "meeting_notes_falcon.txt", "family_recipe.txt",
  "vacation_itinerary.txt", "household_budget.csv", "book_club_notes.txt",
  "presentation_draft.pptx", "invoice_march.txt", "photo_album_readme.txt",
  "personal_journal.txt",
];

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function seedFiles(watchDir = WATCH_DIR, n = 10) {
  const subdirs = ["", "Documents", "Documents/Work", "Pictures", "Finance"];
  for (const d of subdirs) {
    fs.mkdirSync(path.join(watchDir, d), { recursive: true });
  }

  for (let i = 0; i < n; i++) {
    const name = FILENAMES[i % FILENAMES.length];
    const subdir = pick(subdirs);
    const filePath = path.join(watchDir, subdir, name);
    fs.writeFileSync(filePath, pick(SAMPLE_TEXTS));
  }
  console.log(`Seeded ${n} files under ${watchDir}`);
}

function existingFiles(watchDir) {
  const out = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(p);
      else out.push(p);
    }
  }
  if (fs.existsSync(watchDir)) walk(watchDir);
  return out;
}

async function simulateNormalEditing(watchDir = WATCH_DIR, durationSeconds = 30) {
  let files = existingFiles(watchDir);
  if (files.length === 0) {
    seedFiles(watchDir);
    files = existingFiles(watchDir);
  }

  console.log(`Simulating normal activity for ${durationSeconds}s...`);
  const end = Date.now() + durationSeconds * 1000;

  while (Date.now() < end) {
    const filePath = pick(files);
    fs.appendFileSync(filePath, `\nEdited at ${new Date().toLocaleTimeString()}.`);
    const waitMs = (2 + Math.random() * 3) * 1000;
    await new Promise((r) => setTimeout(r, waitMs));
  }
  console.log("Done.");
}

module.exports = { seedFiles, existingFiles, simulateNormalEditing, WATCH_DIR };

if (require.main === module) {
  const mode = process.argv[2] || "seed";
  const duration = parseInt(process.argv[3] || "30", 10);

  if (mode === "seed") {
    seedFiles();
  } else if (mode === "activity") {
    seedFiles();
    simulateNormalEditing(WATCH_DIR, duration);
  } else {
    console.log(`Unknown mode '${mode}'. Use: seed | activity [seconds]`);
  }
}
