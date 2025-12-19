// background.js

async function handleRequest(details) {
  const url = details.url;

  const hostname = new URL(url).hostname;
  const { allowedDomains = [] } = await browser.storage.local.get("allowedDomains");

  if (allowedDomains.includes(hostname)) {
    console.log("Domain in allowed Domain!!!!")
    return { cancel: false };
  }

  if (url.startsWith("moz-extension://")) {
    return { cancel: false };
  }
  //  TODO: Change to api Call
  const isBadUrl = url.includes("print"); 

  if (isBadUrl) {
    console.log("Bad URL detected.");
    browser.tabs.update(details.tabId, {
      url: browser.runtime.getURL("blocked.html?target="+ url)
    });
    
    // 3. IF BAD: Redirect to the internal page that contains the alert
    return { cancel: true };
  }
  console.log("All Good!!!")
  // 4. IF GOOD: Do nothing. The browser loads the page instantly.
  return { cancel: false };
}

browser.webRequest.onBeforeRequest.addListener(
  handleRequest,
  { urls: ["<all_urls>"], types: ["main_frame"] }, // Only check main page loads
  ["blocking"]
);