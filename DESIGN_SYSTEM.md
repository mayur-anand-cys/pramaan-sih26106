# PRAMAAN SOC Design System

Issue #73 establishes a restrained, high-contrast visual language for PRAMAAN SOC interfaces. The system is designed for threat triage, digital forensics, evidence review, and security operations workflows.

## Design principles

The design system uses a dark operational surface, clear borders, strong typography, and a limited semantic color palette. Color communicates operational meaning; it is not decorative.

### Four non-negotiable rules

1. **No emojis** — Use text, labels, icons from the approved product icon set, or semantic indicators instead.

1. **No gradients** — Use solid surfaces and borders to preserve visual clarity and reduce noise.

1. **No shadows** — Use borders, spacing, and surface contrast to establish hierarchy.

1. **Color = meaning** — Apply colors only according to their semantic roles:
  - **Critical:** `#f85149`
  - **Medium:** `#d29922`
  - **Safe:** `#3fb950`
  - **Info:** `#58a6ff`
  - **Blockchain / evidence:** `#a371f7`

## Palette and typography

| Token | Value | Intended use |
| --- | --- | --- |
| Background | `#0a0e14` | Application background |
| Surface | `#0d1117` | Panels, cards, metrics |
| Raised surface | `#161b22` | Table headers, code blocks, hover states |
| Border | `#30363d` | Primary component borders |
| Muted border | `#21262d` | Dividers and low-emphasis boundaries |
| Text | `#e6edf3` | Primary text |
| Muted text | `#8b949e` | Supporting text and labels |
| Critical | `#f85149` | Confirmed or urgent risk |
| Medium | `#d29922` | Warnings and moderate risk |
| Safe | `#3fb950` | Passed checks and safe outcomes |
| Info | `#58a6ff` | Neutral information and actions |
| Blockchain | `#a371f7` | Cryptographic evidence and hashes |

Use **Inter** for interface text and **JetBrains Mono** for hashes, code, technical identifiers, keyboard shortcuts, and metric values.

## Importing the CSS in Streamlit

Place the stylesheet at `soc/static/css/pramaan-soc.css`. From `app.py`, load it with the following exact snippet:

```python
from pathlib import Path
import streamlit as st

css_path = Path(__file__).parent / "soc" / "static" / "css" / "pramaan-soc.css"
st.markdown(
    f"<style>{css_path.read_text(encoding='utf-8')}</style>",
    unsafe_allow_html=True,
)
```

The stylesheet can be loaded once near the top of the Streamlit app, after `st.set_page_config(...)` and before rendering the interface.

> The import snippet is presentation-only. It does not change application state, analysis logic, or backend behavior.

## Component usage

| Component | Class(es) | Use |
| --- | --- | --- |
| Panel | `.panel` | Wrap a logical section, investigation view, evidence block, or dashboard area. |
| Panel header | `.panel-header` | Add a title row and optional metadata inside a panel. |
| Panel title | `.panel-title` | Primary title inside `.panel-header`. |
| Panel subtitle | `.panel-subtitle` | Supporting context beneath a panel title. |
| Generic badge | `.badge` | Base status badge; combine with one semantic modifier. |
| Critical badge | `.badge .badge-critical` | Critical alerts, confirmed malicious findings, or urgent action. |
| Medium badge | `.badge .badge-medium` | Moderate risk, warnings, or review-needed findings. |
| Safe badge | `.badge .badge-safe` | Passed checks, clean results, or trusted outcomes. |
| Info badge | `.badge .badge-info` | Neutral status, metadata, or informational state. |
| Blockchain badge | `.badge .badge-blockchain` | Cryptographic proof, evidence anchoring, or blockchain state. |
| KPI metric | `.metric` | Wrap one KPI or summary value. |
| Metric label | `.metric-label` | Uppercase label for a metric. |
| Metric value | `.metric-value` | Monospace primary value for a metric. |
| Critical metric value | `.metric-value .metric-value-critical` | Critical metric value. |
| Medium metric value | `.metric-value .metric-value-medium` | Medium-risk metric value. |
| Safe metric value | `.metric-value .metric-value-safe` | Safe metric value. |
| Info metric value | `.metric-value .metric-value-info` | Informational metric value. |
| Blockchain metric value | `.metric-value .metric-value-blockchain` | Evidence or cryptographic metric value. |
| Status LED | `.led` | Small status indicator dot. |
| Critical LED | `.led .led-critical` | Critical state indicator. |
| Medium LED | `.led .led-medium` | Medium-risk state indicator. |
| Safe LED | `.led .led-safe` | Safe or healthy state indicator. |
| Off LED | `.led .led-off` | Inactive, unavailable, or unknown state indicator. |
| Data table | `.data-table` | Structured headers, extracted artifacts, findings, and audit records. |
| Button | `.btn` | Base action button. |
| Primary button | `.btn .btn-primary` | Main safe or informational action. |
| Danger button | `.btn .btn-danger` | Destructive, containment, or high-impact action. |
| Hash | `.hash` | SHA-256, Merkle roots, evidence IDs, and other long technical strings. |
| Keyboard shortcut | `kbd` | Display a keyboard key or shortcut. |
| Muted text | `.text-muted` | Secondary context that should not compete with findings. |
| Monospace utility | `.mono` | Apply technical monospace typography to an inline element. |

### Example markup

```html
<section class="panel">
  <header class="panel-header">
    <div>
      <h2 class="panel-title">Authentication Results</h2>
      <p class="panel-subtitle">Sender-domain verification</p>
    </div>
    <span class="badge badge-safe">Pass</span>
  </header>

  <div class="metric">
    <p class="metric-label">DMARC alignment</p>
    <p class="metric-value metric-value-safe">PASS</p>
  </div>

  <p>
    Evidence root:
    <span class="hash">9f86d081884c7d659a2feaa0c55ad015...</span>
  </p>
</section>
```

## Status and color guidance

- Use **critical** only when an item requires urgent analyst attention or represents confirmed/high-confidence risk.

- Use **medium** for warnings, suspicious indicators, partial failures, or items requiring review.

- Use **safe** for verified passes, healthy services, clean results, and completed controls.

- Use **info** for neutral metadata, navigation context, timestamps, and non-risk actions.

- Use **blockchain purple** only for cryptographic evidence, proof states, Merkle roots, or immutable evidence references.

Do not use semantic colors for decoration, branding flourishes, or ordinary headings. Neutral text and borders should carry the rest of the interface.

## Accessibility and interaction

- Keep text contrast high against `#0a0e14`, `#0d1117`, and `#161b22` surfaces.

- Do not communicate status by color alone; pair badges and LEDs with visible text.

- Preserve the visible focus ring on `.btn` controls.

- Keep labels concise and explicit for analysts scanning quickly.

- Allow long hashes and identifiers to wrap with `.hash` rather than overflow the viewport.

- Use `.data-table` for structured data and ensure column headings remain meaningful without color.

## File location

```
soc/
├── static/
│   └── css/
│       └── pramaan-soc.css
└── DESIGN_SYSTEM.md
```