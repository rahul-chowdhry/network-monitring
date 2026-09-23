const API_BASE_URL = "http://127.0.0.1:8000";

export async function login(username, password) {
  const body = new URLSearchParams();

  body.append("username", username);
  body.append("password", password);

  const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.detail || "Login failed");
  }

  if (!data.access_token) {
    throw new Error("Login succeeded but no access token was returned");
  }

  localStorage.setItem("homenet_token", data.access_token);

  return data;
}

export function logout() {
  localStorage.removeItem("homenet_token");
}

export function getToken() {
  return localStorage.getItem("homenet_token");
}

export async function getDevices() {
  const token = getToken();

  if (!token) {
    throw new Error("Not authenticated");
  }

  const response = await fetch(`${API_BASE_URL}/api/devices`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.detail || "Failed to load devices");
  }

  return data;
}