# ADR 0011: Validated capture-route confirmation

Status: implemented; real VPN handover acceptance remains open.

## Reproduced Problems

The route state machine counted a changed profile name before examining the
binding error. A failed adapter lookup could therefore count toward the required
two observations and even return ready on its first failure. Two observations
with the same profile but different devices or filters also counted as stable.

PPP address inventory ordering/repetition changed the generated BPF text without
changing its meaning, creating unnecessary rebinds or unstable confirmation.

## Decision

Reject error, missing profile and empty target observations before counting a
candidate. Reset confirmation and expose the existing route warning. Confirm a
new profile only after two consecutive valid equal tuples of profile, physical
target(s) and capture filter. Copy list targets into the candidate tuple so later
list mutation cannot change the remembered observation.

Healthy old capture may continue during the first valid candidate observation.
After an unavailable-route warning, stay waiting until confirmation rather than
immediately reopening the old failed target. Drain/close the old binding before
updating selection, filter or metadata builder. Manual pinning and immediate filter
refresh of an already selected RAS profile retain their existing behavior.

Generate RAS filters from unique parsed IP addresses in deterministic address-family
and numeric order. Do not compare BPF strings using ad hoc semantic rewriting.
No discovery interval, retry loop, driver buffer or acknowledgement policy changes.

## Verification And Limits

Regression tests first reproduced invalid confirmation and unstable filter output.
They cover errors between valid observations, changing target/filter under one
profile, empty targets, builder/drain order, flapping, disconnect, manual pinning,
existing-profile filter updates and address-list reorder/deduplication.

These are controlled state-machine/loop tests, not a physical VPN toggle or proof
of zero packet loss. Live route-change timing, multi-adapter traffic coverage and
long UI soak still require an isolated runtime test. No VPN/OS settings or installed
desktop application were changed by this decision.
