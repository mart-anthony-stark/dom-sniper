// Listen for custom events from the main world (tracer.js)
window.addEventListener('DOM_XSS_TRACER_ALERT', (e) => {
  // Send message to the background service worker
  if (chrome && chrome.runtime) {
    chrome.runtime.sendMessage({
      type: "XSS_ALERT",
      data: e.detail,
      url: window.location.href
    }).catch(err => console.debug("[DOM XSS Tracer] Could not send message to background", err));
  }
});
