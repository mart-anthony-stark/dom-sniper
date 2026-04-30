// Listen for custom events from the main world (tracer.js)
window.addEventListener('DOMSNIPER_ALERT', (e) => {
  // Send message to the background service worker
  if (chrome && chrome.runtime) {
    chrome.runtime.sendMessage({
      type: "XSS_ALERT",
      data: e.detail,
      url: window.location.href
    }).catch(err => console.debug("[DOMSniper] Could not send message to background", err));
  }
});

// Settings propagation to MAIN world
function updateSettings() {
  if (chrome && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(['enable-visuals', 'show-borders', 'popover-position-left'], (data) => {
      const settings = {
        enableVisuals: data['enable-visuals'] !== undefined ? data['enable-visuals'] : true,
        showBorders: data['show-borders'] !== undefined ? data['show-borders'] : true,
        popoverLeft: data['popover-position-left'] !== undefined ? data['popover-position-left'] : false
      };
      document.documentElement.setAttribute('data-domsniper-settings', JSON.stringify(settings));
    });
  }
}

// Initial update
updateSettings();

// Listen for storage changes
if (chrome && chrome.storage && chrome.storage.onChanged) {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local') {
      updateSettings();
    }
  });
}
