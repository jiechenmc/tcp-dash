const { runTest } = require("./core");
const { WebSocketServer } = require("ws");
const fs = require("fs");

const port = 6789;

const wss = new WebSocketServer({ port: port });

wss.on("connection", function connection(ws) {
  ws.on("message", function message(data) {
    const dataPoint = JSON.parse(data);

    // We only care about bitrate and stall rate
    if (
      dataPoint["metricsName"] === "bitrate" ||
      dataPoint["metricsName"] === "stallrate"
    )
      fs.appendFileSync("out.txt", data + "\n");
  });
});

runTest(
  "Test1",
  "https://dash.akamaized.net/akamai/bbb_30fps/bbb_30fps.mpd",
  30
);
