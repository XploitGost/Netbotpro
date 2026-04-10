import { useEffect, useMemo, useState } from "react";

const OVERSCAN_ROWS = 5;

export function useWindowedRows(items, { enabled, rowHeight, containerHeight }) {
  const [scrollTop, setScrollTop] = useState(0);

  useEffect(() => {
    setScrollTop(0);
  }, [items]);

  const windowState = useMemo(() => {
    if (!enabled) {
      return {
        visibleItems: items,
        startIndex: 0,
        topSpacerHeight: 0,
        bottomSpacerHeight: 0,
      };
    }

    const visibleCount = Math.max(1, Math.ceil(containerHeight / rowHeight));
    const startIndex = Math.max(0, Math.floor(scrollTop / rowHeight) - OVERSCAN_ROWS);
    const endIndex = Math.min(items.length, startIndex + visibleCount + OVERSCAN_ROWS * 2);
    return {
      visibleItems: items.slice(startIndex, endIndex),
      startIndex,
      topSpacerHeight: startIndex * rowHeight,
      bottomSpacerHeight: Math.max(0, (items.length - endIndex) * rowHeight),
    };
  }, [containerHeight, enabled, items, rowHeight, scrollTop]);

  return {
    ...windowState,
    onScroll: enabled ? (event) => setScrollTop(event.currentTarget.scrollTop) : undefined,
    isWindowed: enabled,
  };
}
