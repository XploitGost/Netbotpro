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
  return window.localStorage.getItem(LOCAL_TOKEN_STORAGE_KEY) || "";
}

export function useLocalAuth() {
  const runtimeLocalToken = getManagedLocalToken();
  const managedLocalToken = isManagedLocalToken();
  const [localToken, setLocalTokenState] = useState(() => runtimeLocalToken || readStoredLocalToken());

  useEffect(() => {
    if (typeof window === "undefined" || !managedLocalToken) {
      return;
    }
    window.localStorage.removeItem(LOCAL_TOKEN_STORAGE_KEY);
    setLocalTokenState(runtimeLocalToken);
  }, [managedLocalToken, runtimeLocalToken]);

  function setLocalToken(nextToken) {
    const normalized = String(nextToken || "");
    setLocalTokenState(normalized);
    if (typeof window === "undefined" || managedLocalToken) {
      return;
    }
    if (normalized) {
      window.localStorage.setItem(LOCAL_TOKEN_STORAGE_KEY, normalized);
      return;
    }
    window.localStorage.removeItem(LOCAL_TOKEN_STORAGE_KEY);
  }

  return { localToken, setLocalToken, managedLocalToken };
}
