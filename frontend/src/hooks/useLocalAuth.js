import { useEffect, useState } from "react";
import { getManagedLocalToken, isManagedLocalToken } from "../lib/runtimeConfig";

const LOCAL_TOKEN_STORAGE_KEY = "netbot_local_token";

export function buildAuthHeaders(localToken, extra = {}) {
  const headers = { ...extra };
  if (localToken) {
    headers["X-NetBot-Token"] = localToken;
  }
  return headers;
}

function readStoredLocalToken() {
  if (typeof window === "undefined") {
    return "";
  }
  try {
    const sessionValue = window.sessionStorage.getItem(LOCAL_TOKEN_STORAGE_KEY) || "";
    if (sessionValue) return sessionValue;
  } catch {}
  try {
    const legacyValue = window.localStorage.getItem(LOCAL_TOKEN_STORAGE_KEY) || "";
    if (legacyValue) {
      try {
        window.sessionStorage.setItem(LOCAL_TOKEN_STORAGE_KEY, legacyValue);
      } catch {}
      window.localStorage.removeItem(LOCAL_TOKEN_STORAGE_KEY);
      return legacyValue;
    }
  } catch {}
  return "";
}

export function useLocalAuth() {
  const runtimeLocalToken = getManagedLocalToken();
  const managedLocalToken = isManagedLocalToken();
  const [localToken, setLocalTokenState] = useState(() => runtimeLocalToken || readStoredLocalToken());

  useEffect(() => {
    if (typeof window === "undefined" || !managedLocalToken) {
      return;
    }
    try {
      window.localStorage.removeItem(LOCAL_TOKEN_STORAGE_KEY);
    } catch {}
    try {
      window.sessionStorage.removeItem(LOCAL_TOKEN_STORAGE_KEY);
    } catch {}
    setLocalTokenState(runtimeLocalToken);
  }, [managedLocalToken, runtimeLocalToken]);

  function setLocalToken(nextToken) {
    const normalized = String(nextToken || "");
    setLocalTokenState(normalized);
    if (typeof window === "undefined" || managedLocalToken) {
      return;
    }
    try {
      if (normalized) {
        window.sessionStorage.setItem(LOCAL_TOKEN_STORAGE_KEY, normalized);
      } else {
        window.sessionStorage.removeItem(LOCAL_TOKEN_STORAGE_KEY);
      }
    } catch {}
    try {
      window.localStorage.removeItem(LOCAL_TOKEN_STORAGE_KEY);
    } catch {}
  }

  return { localToken, setLocalToken, managedLocalToken };
}
