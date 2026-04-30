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
    chrome.storage.local.get(['scanning-enabled', 'enable-visuals', 'show-borders', 'show-popovers'], (data) => {
      const settings = {
        scanningEnabled: data['scanning-enabled'] !== undefined ? data['scanning-enabled'] : true,
        enableVisuals: data['enable-visuals'] !== undefined ? data['enable-visuals'] : true,
        showBorders: data['show-borders'] !== undefined ? data['show-borders'] : true,
        showPopovers: data['show-popovers'] !== undefined ? data['show-popovers'] : true
      };
      
      // 1. Set attribute for reactivity
      document.documentElement.setAttribute('data-domsniper-settings', JSON.stringify(settings));
      
      // 2. Inject global variable for immediate access
      const script = document.createElement('script');
      script.textContent = `window.DOMSNIPER_SETTINGS = ${JSON.stringify(settings)};`;
      (document.head || document.documentElement).appendChild(script);
      script.remove();
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
