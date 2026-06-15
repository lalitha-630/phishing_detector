document.addEventListener('DOMContentLoaded', () => {
    const urlBox = document.getElementById('blocked-url');
    const backBtn = document.getElementById('back-btn');

    // 1. Correctly parse and decode the URL parameter from query string
    const urlParams = new URLSearchParams(window.location.search);
    const targetUrl = urlParams.get('url');
    
    if (targetUrl) {
        urlBox.textContent = decodeURIComponent(targetUrl);
    } else {
        urlBox.textContent = "http://microsoft-support-check.net"; // Example fallback
    }

    // 2. Bulletproof Go-Back or Close-Tab navigation logic
    backBtn.addEventListener('click', () => {
        if (window.history.length > 1) {
            window.history.back();
        } else {
            // If it was opened in a fresh tab, close it or redirect safely
            window.close();
            // Fallback in case window.close() is blocked by browser scripts
            window.location.href = "chrome://newtab/";
        }
    });
});
