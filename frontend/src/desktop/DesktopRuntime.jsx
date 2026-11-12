import { createContext, useContext } from "react";

const FixtureContext = createContext(false);

export function DesktopRuntime({ fixtureMode = false, children }) {
  return <FixtureContext.Provider value={fixtureMode}>{children}</FixtureContext.Provider>;
}

export function useFixtureMode() {
  return useContext(FixtureContext);
}
