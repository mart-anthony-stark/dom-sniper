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
