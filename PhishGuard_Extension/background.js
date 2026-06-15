// Keep track of tabs currently being scanned to prevent duplicate requests
const scanningTabs = new Set();

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only process main frame navigations (not iframes)
  if (details.frameId !== 0) return;

  const url = details.url;
  
  // Ignore internal chrome pages and local files
  if (url.startsWith('chrome://') || 
      url.startsWith('chrome-extension://') || 
      url.startsWith('about:') || 
      url.startsWith('file://')) {
    return;
  }

  // Local development whitelist to prevent friendly fire
  try {
    const urlObj = new URL(url);
    if (urlObj.hostname === 'localhost' || urlObj.hostname === '127.0.0.1') {
      return;
    }
  } catch (e) {
    // Ignore invalid URLs
  }

  const tabId = details.tabId;
  
  if (scanningTabs.has(tabId)) return;
  scanningTabs.add(tabId);

  try {
    const response = await fetch('http://localhost:8000/predict', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url: url })
    });

    if (response.ok) {
      const data = await response.json();
      const isPhishing = data.is_phishing || data.status === 'Phishing';
      
      if (isPhishing) {
        // Redirect the tab to the blocked page
        const blockedUrl = chrome.runtime.getURL(`blocked.html?url=${encodeURIComponent(url)}`);
        chrome.tabs.update(tabId, { url: blockedUrl });
      }
    }
  } catch (error) {
    console.error('PhishGuard Background Shield Error:', error);
  } finally {
    scanningTabs.delete(tabId);
  }
});
