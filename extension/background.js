// Dictionary to hold alerts per tab ID
let tabAlerts = {};

chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabAlerts[tabId];
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading') {
    // Clear badge and alerts on new page load
    chrome.action.setBadgeText({ text: '', tabId: tabId });
    tabAlerts[tabId] = [];
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "XSS_ALERT" && sender.tab) {
    const tabId = sender.tab.id;
    if (!tabAlerts[tabId]) {
      tabAlerts[tabId] = [];
    }
    
    // Check for duplicates to prevent spam
    const isDuplicate = tabAlerts[tabId].some(a => a.caller === message.data.caller && a.sinkName === message.data.sinkName);
    
    if (!isDuplicate) {
      tabAlerts[tabId].push(message.data);
      // Update badge
      chrome.action.setBadgeText({ text: tabAlerts[tabId].length.toString(), tabId: tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#ff0000', tabId: tabId });
    }
    
    sendResponse({ status: "logged" });
  } else if (message.type === "GET_ALERTS") {
    // Popup wants alerts for the current tab
    // We get the tab id from the message payload since the popup sends it
    const tabId = message.tabId;
    sendResponse({ alerts: tabAlerts[tabId] || [] });
  }
});
