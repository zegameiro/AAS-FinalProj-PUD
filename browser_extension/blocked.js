const params = new URLSearchParams(window.location.search);
const targetUrl = params.get("target");

document.getElementById("msg").textContent =
  "The site you tried to access was flagged for phishing:\n   " + targetUrl;

document.getElementById("proceed").addEventListener("click", async () => {
  if (!targetUrl) return;

  // Add a bypass flag so background.js allows it
  const url = new URL(targetUrl);
  await addToAllowed(url.hostname);

  window.location.href = url.toString();
});


async function addToAllowed(domain) {
    const { allowedDomains = [] } = await browser.storage.local.get("allowedDomains");

    // 2. Save domain if not already present
    if (!allowedDomains.includes(domain)) {
        console.log("Adding " + domain + " to Allowed Domains!!")
        allowedDomains.push(domain);
        await browser.storage.local.set({ allowedDomains });
    }
}
