import { WebSocketServer } from "ws";

import { DatabaseSync } from "node:sqlite";
import { spawn } from "node:child_process";

const database = new DatabaseSync("out.db");

const args = process.argv.slice(2);

// Check for specific arguments
if (args.length > 0) {
  console.log("First argument:", args[0]);

  if (args[0] === "prune") {
    database.exec("DROP TABLE IF EXISTS data");
  }
}

database.exec(`CREATE TABLE IF NOT EXISTS data(
  key INTEGER PRIMARY KEY AUTOINCREMENT,
  testName TEXT,
  metricsName TEXT,
  metricsTime TEXT,
  metricsValue TEXT
);`);

const insert = database.prepare(
  "INSERT INTO data (testName, metricsName, metricsTime, metricsValue) VALUES (?, ?, ?, ?)"
);

const port = 6789;

const wss = new WebSocketServer({ port: port });

wss.on("connection", function connection(ws) {
  ws.on("message", function message(data) {
    const dataPoint = JSON.parse(data);

    // We only care about bitrate and stall rate
    if (
      dataPoint["metricsName"] === "bitrate" ||
      dataPoint["metricsName"] === "stallrate"
    ) {
      insert.run(
        dataPoint["testName"],
        dataPoint["metricsName"],
        dataPoint["metricsTime"],
        dataPoint["metricsValue"]
      );
    }
  });
});

// RUN TESTS HERE

const HTTP1_PLAYER =
  "http://localhost:3000/samples/dash-if-reference-player/index.html";

const HTTP2_PLAYER =
  "http://localhost:3000/samples/dash-if-reference-player/index.html";

const HTTP3_PLAYER =
  "http://localhost:3000/samples/dash-if-reference-player/index.html";

const BIG_VIDEO = "https://dash.akamaized.net/akamai/bbb_30fps/bbb_30fps.mpd";

const tests = [
  {
    playerURL: HTTP1_PLAYER,
    testName: "Very Original Name",
    videoManifestURL: BIG_VIDEO,
    duration: 30,
  },
];

// END

let remainingProcesses = tests.length;
let mutex = false;

function checkIfAllExited() {
  if (remainingProcesses === 0) {
    console.log("All processes have exited.");
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
    console.log(`stdout: ${data}`);
  });
  collector.stderr.on("data", (data) => {
    console.error(`stderr: ${data}`);
  });
  collector.on("close", (code) => {
    console.log(`child process exited with code ${code}`);
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
