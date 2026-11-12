function observeInterfaceCycle(previous, capture) {
  const next = { ...previous };
  if (!capture.selected_iface || !(capture.ipc_accepted > 0)) return next;
  const identity = JSON.stringify(capture.selected_iface);
  if (!next.initial) next.initial = identity;
  else if (identity !== next.initial) next.left = true;
  else if (next.left && !next.returned) {
    next.returned = true;
    next.acknowledgedAtReturn = capture.journal_acknowledged_records;
  }
  if (next.returned && capture.journal_acknowledged_records > next.acknowledgedAtReturn) next.trafficAfterReturn = true;
  return next;
}
module.exports = { observeInterfaceCycle };
