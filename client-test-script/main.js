import { WebSocketServer } from "ws";

import { DatabaseSync } from "node:sqlite";
import { spawn } from "node:child_process";
import { MultiBar, Presets } from "cli-progress";

const database = new DatabaseSync("out.db");

const args = process.argv.slice(2);

// Check for specific arguments
let title = null;
if (args.length > 0) {
  if (args.some((arg) => arg === "prune")) {
    console.log("Pruning database...");
    database.exec("DROP TABLE IF EXISTS data");
    args.splice(args.indexOf("prune"), 1);
  }

  if (args.length > 0) {
    title = args.join(" ");
  }
}

database.exec(`CREATE TABLE IF NOT EXISTS data(
  key INTEGER PRIMARY KEY AUTOINCREMENT,
  testName TEXT,
  timestamp TEXT,
  metricsName TEXT,
  metricsTime TEXT,
  metricsValue TEXT
);`);

const insert = database.prepare(
  "INSERT INTO data (testName, timestamp, metricsName, metricsTime, metricsValue) VALUES (?, ?, ?, ?, ?)"
);

const port = 6789;

const wss = new WebSocketServer({ port: port });

wss.on("connection", function connection(ws) {
  ws.on("message", function message(data) {
    const dataPoint = JSON.parse(data);

    // We only care about bitrate and stall rate
    if (
      true ||
      dataPoint["metricsName"] === "bitrate" ||
      dataPoint["metricsName"] === "stallRate"
    ) {
      insert.run(
        dataPoint["testName"],
        new Date().toLocaleString(),
        dataPoint["metricsName"],
        dataPoint["metricsTime"],
        dataPoint["metricsValue"]
      );
    }
  });
});

// RUN TESTS HERE

// The player is HTTP1.1

const ALGORITHM_BASE_PORT = 3000;
const ALGORITHMS = ["Dynamic", "Bola", "Festive", "L2A", "RB", "Throughput"];

const VIDEO_PLAYER =
  "http://int.dhinak.net:3000/samples/dash-if-reference-player/index.html";

const HTTP1_SERVER = "https://int.dhinak.net:1443";

const HTTP2_SERVER = "https://int.dhinak.net:2443";

const HTTP3_SERVER = "https://int.dhinak.net:8443";

const tests = [];
const multibar = new MultiBar({
  forceRedraw: true,
}, Presets.shades_classic);

for (let i = 0; i < ALGORITHMS.length; i++) {
  const algorithm = ALGORITHMS[i];
  const port = ALGORITHM_BASE_PORT + i;

  tests.push({
    playerURL: `http://int.dhinak.net:${port}/samples/dash-if-reference-player/index.html`,
    testName: `TheEmptinessMachine - ${title} - ${algorithm} - HTTP/1.1`,
    videoManifestURL: `${HTTP1_SERVER}/media/TheEmptinessMachine.mp4_output.mpd`,
    duration: 220,
  });
  tests.push({
    playerURL: `http://int.dhinak.net:${port}/samples/dash-if-reference-player/index.html`,
    testName: `TheEmptinessMachine - ${title} - ${algorithm} - HTTP/2`,
    videoManifestURL: `${HTTP2_SERVER}/media/TheEmptinessMachine.mp4_output.mpd`,
    duration: 220,
  });
  tests.push({
    playerURL: `http://int.dhinak.net:${port}/samples/dash-if-reference-player/index.html`,
    testName: `TheEmptinessMachine - ${title} - ${algorithm} - HTTP/3`,
    videoManifestURL: `${HTTP3_SERVER}/media/TheEmptinessMachine.mp4_output.mpd`,
    duration: 220,
  });
}
const bar = multibar.create(tests.length, 0);

// END

let remainingProcesses = tests.length;
let mutex = false;

function checkIfAllExited() {
  if (remainingProcesses === 0) {
    multibar.log("All processes have exited.\n");
    multibar.stop();
    process.exit(0); // exit process when all tests are done
  }
}
async function runTestSync(test) {
  while (mutex) {
    // Wait for mutex to be released before continuing
    await new Promise((resolve) => setTimeout(resolve, 100)); // Wait for a short period before checking again
  }

  mutex = true; // Acquire the mutex

  const collector = spawn("node", [
    "autoCollect.js",
    test.playerURL,
    test.testName,
    test.videoManifestURL,
    test.duration,
  ]);

  collector.stdout.on("data", (data) => {
    multibar.log(`stdout: ${data}\n`);
    bar.updateETA();
  });
  collector.stderr.on("data", (data) => {
    multibar.log(`stderr: ${data}\n`);
    bar.updateETA();
  });
  collector.on("close", (code) => {
    multibar.log(`child process exited with code ${code}\n`);
    bar.increment();
    remainingProcesses--;
    mutex = false; // Release the mutex when the process finishes
    checkIfAllExited();
  });
}

(async function runTests() {
  for (const test of tests) {
    await runTestSync(test);
  }
})();
