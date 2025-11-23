import random
import string
from locust import HttpUser, task, between

def random_string(length=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

class WebsiteUser(HttpUser):
    wait_time = between(2, 8)  
    token = None
    username = None
    email = None
    password = "password123"

    def on_start(self):
        """
        Called when a User starts running.
        We'll register a new user and log them in to get a token.
        """
        self.username = f"user_{random_string(8)}"
        self.email = f"{self.username}@example.com"
        self.headers = {}  

        try:
            signup_response = self.client.post("/signup", json={
                "username": self.username,
                "email": self.email,
                "password": self.password
            }, timeout=30)

            if signup_response.status_code != 201:
                print(f"Signup failed for {self.username}: {signup_response.status_code}")
                return

            response = self.client.post("/login", data={
                "username": self.email,
                "password": self.password
            }, timeout=30)

            if response.status_code == 200:
                self.token = response.json().get("access_token")
                self.headers = {"Authorization": f"Bearer {self.token}"}
            else:
                print(f"Login failed for {self.username}: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"on_start failed for {self.username}: {e}")

    @task(4)
    def view_feed(self):
        """View the main feed (highest weight as it's the most common action)"""
        if not self.headers:
            return
        try:
            self.client.get("/posts?limit=10", headers=self.headers, timeout=15)
        except Exception as e:
            print(f"view_feed error: {e}")

    @task(2)
    def view_profile(self):
        """View own profile"""
        if not self.token:
            return
        try:
            self.client.get("/users/me", headers=self.headers, timeout=10)
        except Exception as e:
            print(f"view_profile error: {e}")

    @task(1)
    def create_post(self):
        """Create a new text post"""
        if not self.token:
            return
        try:
            self.client.post("/posts", 
                data={
                    "title": f"Test Post {random_string(5)}",
                    "content": f"This is a load test post content {random_string(20)}"
                },
                headers=self.headers,
                timeout=15
            )
        except Exception as e:
            print(f"create_post error: {e}")

    @task(1)
    def search_users(self):
        """Search for users"""
        if not self.token:
            return
        try:
            self.client.get("/users/search?q=user", headers=self.headers, timeout=10)
        except Exception as e:
            print(f"search_users error: {e}")