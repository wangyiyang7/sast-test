"""
Authentication manager for Juice Shop.
Handles login/logout for different user roles.
"""

from dataclasses import dataclass
from typing import Optional
from src.hands.browser import BrowserManager
from config import JUICE_SHOP_URL,ADMIN_EMAIL,ADMIN_PASSWORD,ADMIN_ROLE, USER_EMAIL, USER_PASSWORD, USER_ROLE

@dataclass
class UserCredentials:
    """User credentials for Juice Shop."""
    email: str
    password: str
    role: str


# Default Juice Shop accounts
JUICE_SHOP_USERS = {
    "admin": UserCredentials(
        email=ADMIN_EMAIL,
        password=ADMIN_PASSWORD,
        role=ADMIN_ROLE
    ),
    "jim": UserCredentials(
        email=USER_EMAIL,
        password=USER_PASSWORD,
        role=USER_ROLE
    ),
    
}


class AuthManager:
    """Manages authentication for Juice Shop."""
    
    def __init__(self, browser: BrowserManager):
        self.browser = browser
        self.current_user: Optional[UserCredentials] = None
    
    def login(self, user_key: str) -> bool:
        """
        Login as a specific user.
        
        Args:
            user_key: Key from JUICE_SHOP_USERS (e.g., 'admin', 'jim')
        
        Returns:
            True if login successful, False otherwise.
        """
        if user_key not in JUICE_SHOP_USERS:
            raise ValueError(f"Unknown user: {user_key}. Available: {list(JUICE_SHOP_USERS.keys())}")
        
        user = JUICE_SHOP_USERS[user_key]
        
        # Navigate to login page
        self.browser.navigate(f"{JUICE_SHOP_URL}/#/login")
        
        # Wait for login form to load
        self.browser.wait_for_selector("#email")
        self.browser.page.wait_for_timeout(500)
        
        # Fill in credentials
        self.browser.fill("#email", user.email)
        self.browser.page.wait_for_timeout(600)
        self.browser.fill("#password", user.password)
        self.browser.page.wait_for_timeout(600)
        
        # Click login button
        self.browser.click("#loginButton")
        
        # Wait for redirect (successful login goes to home page)
        try:
            self.browser.page.wait_for_url(f"{JUICE_SHOP_URL}/#/search**", timeout=5000)
            self.current_user = user
            return True
        except Exception:
            return False
    
    def logout(self) -> bool:
        """
        Logout current user.
        
        Returns:
            True if logout successful, False otherwise.
        """
        if not self.current_user:
            return True  # Already logged out
        
        try:
            # Click account menu
            self.browser.click("#navbarAccount")
            self.browser.wait_for_selector("button:has-text('Logout')")
            
            # Click logout
            self.browser.click("button:has-text('Logout')")
            
            # Wait for redirect to home
            self.browser.page.wait_for_url(f"{JUICE_SHOP_URL}/#/**", timeout=5000)
            self.current_user = None
            return True
        except Exception:
            return False
    
    def is_logged_in(self) -> bool:
        """Check if a user is currently logged in."""
        return self.current_user is not None
    
    def get_current_user(self) -> Optional[UserCredentials]:
        """Get the currently logged in user."""
        return self.current_user
    
    def switch_user(self, user_key: str) -> bool:
        """
        Switch to a different user (logout then login).
        
        Args:
            user_key: Key from JUICE_SHOP_USERS
        
        Returns:
            True if switch successful, False otherwise.
        """
        if self.current_user:
            self.logout()
        return self.login(user_key)