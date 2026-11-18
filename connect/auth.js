// Shared helpers used by index.html, register.html and profile.html.html.
// If the backend runs somewhere else, change API_BASE.
const API_BASE = "http://127.0.0.1:8000";
const TOKEN_KEY = "authToken";

function saveToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

// Sends a request to the backend and returns { ok, status, data }.
// It only throws if the server can't be reached at all.
async function apiRequest(path, { method = "GET", body = null, useToken = false } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (useToken && getToken()) {
    headers["Authorization"] = `Bearer ${getToken()}`;
  }

  const response = await fetch(API_BASE + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  let data = null;
  try {
    data = await response.json();
  } catch (error) {
    // The response had no JSON body, which is fine
  }

  return { ok: response.ok, status: response.status, data };
}

// FastAPI puts the error text in "detail"
function errorMessage(result, fallback) {
  const detail = result.data && result.data.detail;
  return typeof detail === "string" ? detail : fallback;
}

function showMessage(element, text, isError = true) {
  element.textContent = text;
  element.classList.toggle("error", isError);
  element.classList.toggle("success", !isError);
}
