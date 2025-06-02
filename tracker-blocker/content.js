const selectors = [
  'iframe[src*="doubleclick.net"]',
  'script[src*="google-analytics.com"]',
  'img[src*="facebook.net"]'
];

window.addEventListener('DOMContentLoaded', () => {
  selectors.forEach(selector => {
    document.querySelectorAll(selector).forEach(el => el.remove());
  });
});
