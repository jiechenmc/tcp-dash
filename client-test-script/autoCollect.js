import { chromium } from "playwright";

const runTest = async (playerURL, testName, videoManifestURL, duration) => {
  console.log(`Running test: ${testName}`);

  // Setup
  const browser = await chromium.launch({
    channel: "chrome",
    headless: false,
    args: ["--origin-to-force-quic-on=int.dhinak.net:8443"],
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

  await new Promise((r) => setTimeout(r, 3000));

  const loadVideoButton = await page.locator(
    "body > div.container > div:nth-child(2) > div.input-group > span > button.btn.btn-primary"
  );

  await loadVideoButton.click();

  // process.on("SIGINT", async () => {
  //   console.log(
  //     `[${testName}] Video Playback Finished, Closing Browser and moving onto the next test`
  //   );
  //   await await context.close();
  //   await browser.close();
  //   process.exit(0);
  // });
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
