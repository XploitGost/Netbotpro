import { useState } from "react";

export function AccordionPanel({ eyebrow, title, subtitle, badge, defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <section className={`accordion-panel ${open ? "is-open" : ""}`}>
      <button type="button" className="accordion-toggle" onClick={() => setOpen((current) => !current)} aria-expanded={open}>
        <div className="accordion-copy">
          <p className="eyebrow">{eyebrow}</p>
          <h3>{title}</h3>
          {subtitle ? <p className="accordion-subtitle">{subtitle}</p> : null}
        </div>
        <div className="accordion-meta">
          {badge ? <span className="panel-badge">{badge}</span> : null}
          <span className="accordion-chevron">{open ? "−" : "+"}</span>
        </div>
      </button>
      {open ? <div className="accordion-body">{children}</div> : null}
    </section>
  );
}
