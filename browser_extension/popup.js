// UI References
const statusText = document.getElementById("status-text");
const toggleBtn = document.getElementById("toggle-global-btn");
const listContainer = document.getElementById("domain-list");
const emptyMsg = document.getElementById("empty-msg");

init();

async function init() {
  const data = await browser.storage.local.get({ 
    extensionEnabled: true, 
    allowedDomains: [] 
  });

  updateStatusUI(data.extensionEnabled);
  renderList(data.allowedDomains);
}

toggleBtn.addEventListener("click", async () => {
  const data = await browser.storage.local.get({ extensionEnabled: true });
  const newState = !data.extensionEnabled;

  await browser.storage.local.set({ extensionEnabled: newState });

  updateStatusUI(newState);
});

function updateStatusUI(isEnabled) {
  if (isEnabled) {
    statusText.innerText = "Status: ACTIVE";
    statusText.className = "status-active";
    toggleBtn.innerText = "Disable";
    toggleBtn.className = "btn-turn-off";
  } else {
    statusText.innerText = "Status: DISABLED";
    statusText.className = "status-disabled";
    toggleBtn.innerText = "Enable";
    toggleBtn.className = "btn-turn-on";
  }
}

function renderList(domains) {
  listContainer.innerHTML = "";
  if (!domains || domains.length === 0) {
    emptyMsg.style.display = "block";
    return;
  }
  emptyMsg.style.display = "none";

  domains.forEach((domain) => {
    const li = document.createElement("li");
    li.className = "domain-item";
    
    const span = document.createElement("span");
    span.textContent = domain;

    const btn = document.createElement("button");
    btn.textContent = "Remove";
    btn.className = "remove-btn";
    btn.onclick = async () => {
      const data = await browser.storage.local.get({ allowedDomains: [] });
      const newDomains = data.allowedDomains.filter(d => d !== domain);
      await browser.storage.local.set({ allowedDomains: newDomains });
      renderList(newDomains);
    };

    li.appendChild(span);
    li.appendChild(btn);
    listContainer.appendChild(li);
  });
}