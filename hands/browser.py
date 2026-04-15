"""
Browser wrapper for Playwright automation.
"""

import logging
from playwright.sync_api import sync_playwright, Browser, Page, BrowserContext
from config import JUICE_SHOP_URL, HEADLESS, BROWSER_TIMEOUT

logger = logging.getLogger(__name__)

class BrowserManager:
    """
    Manages a Playwright browser instance for automated web interaction.
    Supports context manager usage for guaranteed cleanup.
    """

    def __init__(self):
        self.playwright = None
        self.browser: Browser = None
        self.context: BrowserContext = None
        self.page: Page = None

    def launch(self) -> None:
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(
            headless=HEADLESS,
            slow_mo=500,
        )
        self.context = self.browser.new_context(viewport={"width": 1600, "height": 900})
        self.context.set_default_timeout(2000)
        self.page = self.context.new_page()

    def close(self) -> None:
        if self.page:
            self.page.close()
        if self.context:
            self.context.close()
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()

    def navigate(self, url: str = None) -> None:
        self.page.goto(url or JUICE_SHOP_URL)

    def get_title(self) -> str:
        return self.page.title()

    def get_url(self) -> str:
        return self.page.url

    def click(self, selector: str) -> None:
        """Click an element. Raises immediately on failure — no retries, no drawer magic."""
        self.page.click(selector, timeout=3000)

    def fill(self, selector: str, text: str) -> None:
        self.page.fill(selector, text)

    def wait_for_selector(self, selector: str, timeout: int = None) -> None:
        self.page.wait_for_selector(selector, timeout=timeout or BROWSER_TIMEOUT)

    def screenshot(self, path: str = None, full_page: bool = False) -> bytes:
        return self.page.screenshot(path=path, full_page=full_page)

    def __enter__(self):
        self.launch()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def get_auth_token(self) -> str:
        return self.page.evaluate("""
            () => {
                const candidates = ['token', 'access_token', 'auth_token',
                                    'jwt', 'id_token', 'session_token'];
                for (const key of candidates) {
                    const val = localStorage.getItem(key) || sessionStorage.getItem(key);
                    if (val && val.length > 20) return val;
                }
                for (let i = 0; i < localStorage.length; i++) {
                    const val = localStorage.getItem(localStorage.key(i));
                    if (val && val.startsWith('eyJ')) return val;
                }
                return null;
            }
        """)

    def api_call(self, url: str, method: str = "GET", body: dict = None) -> dict:
        token = self.get_auth_token()
        return self.page.evaluate("""
            async ({url, method, token, body}) => {
                const headers = {'Content-Type': 'application/json'};
                if (token) headers['Authorization'] = 'Bearer ' + token;
                try {
                    const opts = {method, headers};
                    if (body) opts.body = JSON.stringify(body);
                    const resp = await fetch(url, opts);
                    const contentType = resp.headers.get('content-type') || '';
                    const text = await resp.text();
                    let json = null;
                    try { json = JSON.parse(text); } catch(e) {}
                    return {
                        status: resp.status,
                        body: json,
                        raw_body: json ? null : text.substring(0, 500),
                        content_type: contentType,
                        is_html: contentType.includes('text/html'),
                        is_json: contentType.includes('application/json') || json !== null,
                    };
                } catch(e) {
                    return {status: 0, error: e.message};
                }
            }
        """, {"url": url, "method": method, "token": token, "body": body})