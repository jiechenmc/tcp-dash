const { chromium } = require("playwright");

const playerURL =
  "http://localhost:3000/samples/dash-if-reference-player/index.html";

const runTest = async (testName, videoManifestURL, duration) => {
  // Setup
  const browser = await chromium.launch({ channel: "chrome", headless: false });
  const context = await browser.newContext();
  const page = await context.newPage();

  await page.goto(playerURL);
  await page.waitForLoadState("domcontentloaded");

  await page.evaluate((testName) => {
    document.title = testName;
  }, testName);

  // Loading Video
  const videoManifestInput = await page.locator(
    "body > div.container > div:nth-child(2) > div.input-group > input"
  );

  await videoManifestInput.fill(videoManifestURL);

  const loadVideoButton = await page.locator(
    "body > div.container > div:nth-child(2) > div.input-group > span > button.btn.btn-primary"
  );

  await loadVideoButton.click();

  console.log(`Waiting ${duration} seconds before closing...`);
  setTimeout(async () => {
    await await context.close();
    await browser.close();
    process.exit(0);
  }, duration * 1000 + 1000);
};

exports.runTest = runTest;
