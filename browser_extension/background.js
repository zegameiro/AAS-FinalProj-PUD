// background.js
let isEnabled = true;
let allowedDomains = [];
const apiEndpoint = "http://127.0.0.1:3000";

browser.storage.local.get({ extensionEnabled: true, allowedDomains: [] }).then((data) => {
  isEnabled = data.extensionEnabled;
  allowedDomains = data.allowedDomains;
});

browser.storage.onChanged.addListener((changes, area) => {
  if (area === "local") {
    if (changes.extensionEnabled) {
      isEnabled = changes.extensionEnabled.newValue;
      console.log("Extension enabled:", isEnabled);
    }
    if (changes.allowedDomains) {
      allowedDomains = changes.allowedDomains.newValue;
    }
  }
});


async function handleRequest(details) {

  if (!isEnabled) {
    return { cancel: false };
  }

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

  try{
    //  TODO: Change to api Call
    const isBadUrl = url.includes("print");
    if (isBadUrl) {
      console.log("Bad URL detected.");
      browser.tabs.update(details.tabId, {
        url: browser.runtime.getURL("blocked.html?target="+ url)
      });
      
      return { cancel: true };
    }
    
    const data = await fetch(apiEndpoint, {
      method: "GET",
      headers: {
        "Content-Type": "application/json"
      }
    }).then((response) =>{
      if (!response.ok){
        throw new Error("API Server Error: " + response.status);
      }
      return response.json()
    });
    
    console.log(data)
  }
  catch (error) {
    console.error("Network error checking URL:", error);
    return { cancel: true }; 
  }

  console.log("All Good!!!")
  return { cancel: false };
}

browser.webRequest.onBeforeRequest.addListener(
  handleRequest,
  { urls: ["<all_urls>"], types: ["main_frame"] },
  ["blocking"]
);