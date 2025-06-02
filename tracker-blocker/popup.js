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

document.addEventListener("DOMContentLoaded", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const url = new URL(tabs[0].url);
    chrome.cookies.getAll({ domain: url.hostname }, (cookies) => {
      const container = document.getElementById("output");
      container.innerHTML = "";

      cookies.forEach(cookie => {
        const div = document.createElement("div");
        const bad = isSuspicious(cookie);
        div.className = bad ? "bad" : "safe";
        div.textContent = `${cookie.name}: ${cookie.value}`;
        container.appendChild(div);
      });

      if (cookies.length === 0) {
        container.textContent = "No cookies found.";
      }
    });
  });
});
