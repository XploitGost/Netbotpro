import { useEffect } from "react";
import { DashboardWorkspace } from "../App";
import { useDashboardController } from "../hooks/useDashboardController";
import { DesktopRuntime } from "./DesktopRuntime";
import { CommandCenter } from "./CommandCenter";
import { LiveMonitor } from "./LiveMonitor";
import { Investigate } from "./Investigate";
import { AgentsPanel as Fleet } from "./Fleet";
import { DesktopShell as Shell } from "./DesktopShell";
import { recordPacket, resetTraffic } from "./trafficModel";
import "./reference.css";
import "./fleet.css";
import "./endpoint-focus.css";
import "./shell.css";

function recordBatch(messages) {
  for (const { payload } of messages) recordPacket(payload);
}

const desktopViews = { CommandCenter, LiveMonitor, Investigate, Fleet, Shell };

export default function DesktopApp() {
  const controller = useDashboardController({ defaultPage: "command", onPacketBatch: recordBatch, onCaptureReset: resetTraffic });
  useEffect(() => { resetTraffic(); return resetTraffic; }, []);
  return <DesktopRuntime><DashboardWorkspace controller={controller} desktopViews={desktopViews} /></DesktopRuntime>;
}
