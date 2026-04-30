document.addEventListener('DOMContentLoaded', () => {
  // Query active tab ID
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    if (tabs.length === 0) return;
    const tabId = tabs[0].id;
    
    // Request alerts for this tab from the background script
    chrome.runtime.sendMessage({ type: "GET_ALERTS", tabId: tabId }, (response) => {
      const container = document.getElementById('alerts-container');
      
      if (!response || !response.alerts || response.alerts.length === 0) {
        return; // 'No alerts' is already showing
      }
      
      container.innerHTML = ''; // clear "No alerts" message
      
      response.alerts.forEach((alert) => {
        const card = document.createElement('div');
        card.className = 'alert-card';
        
        const title = document.createElement('strong');
        title.textContent = `Sink: ${alert.sinkName}`;
        card.appendChild(title);
        
        const taint = document.createElement('div');
        taint.className = 'detail';
        taint.innerHTML = `<span class="detail-label">Taint Source:</span> <span class="code-block">${escapeHtml(alert.taint)}</span>`;
        card.appendChild(taint);
        
        const payloadSnippet = alert.payload.length > 80 ? alert.payload.substring(0, 80) + '...' : alert.payload;
        const payload = document.createElement('div');
        payload.className = 'detail';
        payload.innerHTML = `<span class="detail-label">Payload:</span> <span class="code-block">${escapeHtml(payloadSnippet)}</span>`;
        card.appendChild(payload);
        
        const source = document.createElement('div');
        source.className = 'detail';
        source.innerHTML = `<span class="detail-label">Line of Code:</span> <span class="code-block">${escapeHtml(alert.caller)}</span>`;
        card.appendChild(source);
        
        if (alert.reference) {
          const ref = document.createElement('div');
          ref.className = 'detail';
          ref.style.marginTop = '6px';
          ref.innerHTML = `<a href="${escapeHtml(alert.reference)}" target="_blank" style="color: #1976d2; font-weight: bold; text-decoration: none;">📘 Fix & Reference Guide →</a>`;
          card.appendChild(ref);
        }
        
        container.appendChild(card);
      });
    });
  });

  // Settings handling
  const settingsKeys = ['enable-visuals', 'show-borders', 'popover-position-left'];
  
  chrome.storage.local.get(settingsKeys, (data) => {
    settingsKeys.forEach(key => {
      const el = document.getElementById(key);
      if (el) {
        // Default to true for visuals and borders, false for left position
        const defaultValue = (key === 'popover-position-left' ? false : true);
        el.checked = data[key] !== undefined ? data[key] : defaultValue;
        
        el.addEventListener('change', () => {
          chrome.storage.local.set({ [key]: el.checked });
        });
      }
    });
  });
});

function escapeHtml(unsafe) {
    return (unsafe || "").toString()
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}
