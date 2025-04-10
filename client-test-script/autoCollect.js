import { chromium } from "playwright";

const runTest = async (playerURL, testName, videoManifestURL, duration) => {
  // Setup
  const browser = await chromium.launch({
    channel: "chrome",
    headless: false,
    args: ["--origin-to-force-quic-on=localhost:8443"],
  });
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

const args = process.argv.slice(2);
const [playerURL, testName, videoManifestURL, duration] = args;

if (args.length == 4) {
  runTest(playerURL, testName, videoManifestURL, duration);
}

export default runTest;
