// Define suspicious patterns
const suspiciousPatterns = [
  /track/i,
  /ad/i,
  /spy/i,
  /session.*?id/i,
  /^__utm/i,
  /pixel/i,
  /analytics/i
];

function isSuspicious(cookie) {
  const name = cookie.name.toLowerCase();
  const value = (cookie.value || "").toLowerCase();
  return suspiciousPatterns.some((pattern) => pattern.test(name) || pattern.test(value));
}

// Analyze and clean cookies on tab change
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url.startsWith("http")) {
    const url = new URL(tab.url);
    chrome.cookies.getAll({ domain: url.hostname }, (cookies) => {
      cookies.forEach((cookie) => {
        if (isSuspicious(cookie)) {
          console.log(`[BLOCKED] Suspicious cookie removed: ${cookie.name}`);
          chrome.cookies.remove({
            url: `${url.protocol}//${cookie.domain.replace(/^\./, "")}${cookie.path}`,
            name: cookie.name
          });
        }
      });
    });
  }
});
