import { useState } from "react";

export function buildAuthHeaders(localToken, extra = {}) {
  const headers = { ...extra };
  if (localToken) {
    headers["X-NetBot-Token"] = localToken;
  }
  return headers;
}

export function useLocalAuth() {
  const [localToken, setLocalTokenState] = useState(() => window.localStorage.getItem("netbot_local_token") || "");

  function setLocalToken(nextToken) {
    setLocalTokenState(nextToken);
    window.localStorage.setItem("netbot_local_token", nextToken);
  }

  return { localToken, setLocalToken };
}
