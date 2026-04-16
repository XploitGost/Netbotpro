import { startTransition, useEffect, useRef } from "react";
import { buildWsEventsTransport } from "../lib/runtimeConfig";

const FLUSH_MS = 180;
const IMMEDIATE_FLUSH_THRESHOLD = 120;
const MAX_BUFFERED_EVENTS = 1000;
const MAX_BATCH_SIZE = 200;

export function useLiveEvents({
  localToken,
  onPacket,
  onAlert,
  onPacketsBatch,
  onAlertsBatch,
  onState,
  onStatusChange,
}) {
  const handlersRef = useRef({ onPacket, onAlert, onPacketsBatch, onAlertsBatch, onState, onStatusChange });

  useEffect(() => {
    handlersRef.current = { onPacket, onAlert, onPacketsBatch, onAlertsBatch, onState, onStatusChange };
  }, [onPacket, onAlert, onPacketsBatch, onAlertsBatch, onState, onStatusChange]);

  useEffect(() => {
    let active = true;
    let socket = null;
    let reconnectTimer = null;
    let flushTimer = null;
    let attempts = 0;
    let droppedPackets = 0;
    let droppedAlerts = 0;
    const packetBuffer = [];
    const alertBuffer = [];

    function flushBuffers() {
      flushTimer = null;
      if (!active) return;
      const packets = packetBuffer.splice(0, Math.min(packetBuffer.length, MAX_BATCH_SIZE));
      const alerts = alertBuffer.splice(0, Math.min(alertBuffer.length, MAX_BATCH_SIZE));
      if (!packets.length && !alerts.length) return;
      startTransition(() => {
        if (packets.length) {
          if (handlersRef.current.onPacketsBatch) handlersRef.current.onPacketsBatch(packets);
          else packets.forEach((message) => handlersRef.current.onPacket?.(message));
        }
        if (alerts.length) {
          if (handlersRef.current.onAlertsBatch) handlersRef.current.onAlertsBatch(alerts);
          else alerts.forEach((message) => handlersRef.current.onAlert?.(message));
        }
        if (droppedPackets || droppedAlerts) {
          handlersRef.current.onStatusChange?.(
            "degraded",
            `Live stream overloaded. Dropped ${droppedPackets} packets and ${droppedAlerts} alerts to protect the UI`
          );
          droppedPackets = 0;
          droppedAlerts = 0;
        }
      });
      if (packetBuffer.length || alertBuffer.length) {
        scheduleFlush();
      }
    }

    function scheduleFlush() {
      if (flushTimer || !active) return;
      flushTimer = window.setTimeout(flushBuffers, FLUSH_MS);
    }

    function connectSocket() {
      if (!active) return;
      handlersRef.current.onStatusChange("connecting", "Connecting to live backend...");
      const { url, protocols } = buildWsEventsTransport(localToken);
      socket = new WebSocket(url, protocols);

      socket.onopen = () => {
        attempts = 0;
        if (!active) return;
        handlersRef.current.onStatusChange("live", "Receiving live packets and alerts");
      };

      socket.onmessage = (event) => {
        if (!active) return;
        let message = null;
        try {
          message = JSON.parse(event.data);
        } catch {
          handlersRef.current.onStatusChange?.("degraded", "Received malformed live event payload");
          return;
        }
        if (message.type === "packet:new") {
          packetBuffer.push(message);
          if (packetBuffer.length > MAX_BUFFERED_EVENTS) {
            droppedPackets += packetBuffer.length - MAX_BUFFERED_EVENTS;
            packetBuffer.splice(0, packetBuffer.length - MAX_BUFFERED_EVENTS);
          }
          if (packetBuffer.length >= IMMEDIATE_FLUSH_THRESHOLD) {
            if (flushTimer) window.clearTimeout(flushTimer);
            flushBuffers();
            return;
          }
          scheduleFlush();
          return;
        }
        if (message.type === "alert:new") {
          alertBuffer.push(message);
          if (alertBuffer.length > MAX_BUFFERED_EVENTS) {
            droppedAlerts += alertBuffer.length - MAX_BUFFERED_EVENTS;
            alertBuffer.splice(0, alertBuffer.length - MAX_BUFFERED_EVENTS);
          }
          if (alertBuffer.length >= IMMEDIATE_FLUSH_THRESHOLD) {
            if (flushTimer) window.clearTimeout(flushTimer);
            flushBuffers();
            return;
          }
          scheduleFlush();
          return;
        }
        startTransition(() => {
          if (message.type === "sniffer:started" || message.type === "sniffer:stopped" || message.type === "sniffer:reset" || message.type === "hello") {
            handlersRef.current.onState(message);
          }
        });
      };

      socket.onerror = () => {
        if (active) handlersRef.current.onStatusChange("degraded", "Live socket had an error, retrying...");
      };

      socket.onclose = () => {
        if (!active) return;
        attempts += 1;
        const delay = Math.min(5000, 600 * attempts);
        handlersRef.current.onStatusChange("reconnecting", `Live stream disconnected, retrying in ${Math.ceil(delay / 1000)}s`);
        reconnectTimer = window.setTimeout(connectSocket, delay);
      };
    }

    connectSocket();
    return () => {
      active = false;
      if (reconnectTimer) window.clearTimeout(reconnectTimer);
      if (flushTimer) window.clearTimeout(flushTimer);
      if (socket) socket.close();
    };
  }, [localToken]);
}
