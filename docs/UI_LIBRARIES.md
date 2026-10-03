# PRAMAAN — UI Library Research

Comparison of CDN-only UI libraries for the PRAMAAN SOC dashboard.
Constraint: **no npm, no bundler, no build step.** Every option must be
loadable via a single `<script>` or `<link>` tag.

---

## 1. Base UI / CSS Frameworks

| Library | Approach | Approx. weight | CDN |
|---|---|---|---|
| **Tailwind CSS (CDN)** | Utility-first | ~50 KB (JIT) | cdn.tailwindcss.com |
| **Pico.css** | Semantic, class-light | ~10 KB | cdn.jsdelivr.net/npm/@picocss/pico |
| **Water.css** | Drop-in minimal | ~2 KB | cdn.jsdelivr.net/gh/kognise/water.css |
| **DaisyUI** | Component classes on Tailwind | ~30 KB | cdn.jsdelivr.net/npm/daisyui |

**Recommendation: Pico.css.** Small (~10 KB), semantic (you style plain
HTML, not class soup), and adds professional polish with zero config.
Water.css is even smaller but less flexible. Tailwind CDN is heavy and
officially discouraged for production. DaisyUI requires committing to
the Tailwind ecosystem.

---

## 2. Charts

| Library | Use case | Approx. weight | CDN |
|---|---|---|---|
| **Plotly** | 3D + complex interactive | (already installed) | via Python |
| **Apache ECharts** | General-purpose 2D | ~1 MB (min) | cdn.jsdelivr.net/npm/echarts |
| **uPlot** | Time-series / line | ~45 KB | cdn.jsdelivr.net/npm/uplot |

**Recommendation: keep Plotly for 3D, add uPlot for 2D time-series.**
ECharts is powerful but ~1 MB — too heavy for a few charts. uPlot is
tiny, extremely fast, and perfect for relay timelines and traffic
sparklines.

---

## 3. Tables

| Library | Approach | Approx. weight |
|---|---|---|
| **Plain HTML + Pico.css** | Semantic `<table>` | 0 KB (uses base) |
| **AG Grid** | Full data grid | ~1 MB |
| **Streamlit `st.dataframe`** | Native | 0 KB |

**Recommendation: plain HTML tables styled by Pico.css** for custom
layouts, and **`st.dataframe`** for standard data views. AG Grid is
overkill unless editing or 100k+ row virtualization is required.

---

## 4. Icons

| Library | Approach | Approx. weight | CDN |
|---|---|---|---|
| **Tabler Icons (webfont)** | 5000+ SVG icons | ~100 KB | cdn.jsdelivr.net/npm/@tabler/icons-webfont |
| **Lucide** | SVG-only, no webfont | varies | inline SVG |
| **Font Awesome** | Well-known, large | ~70 KB | cdnjs.cloudflare.com |

**Recommendation: Tabler Icons.** Purpose-built for dashboards and
security contexts (shield, key, lock, alert variants). Webfont means no
per-icon SVG markup — just `<i class="ti ti-shield-check"></i>`.

---

## 5. Animation

| Library | Approach | Approx. weight | CDN |
|---|---|---|---|
| **AutoAnimate** | Zero-config DOM smoothing | ~3 KB | cdn.jsdelivr.net/npm/@formkit/auto-animate |
| **Animate.css** | Pre-built CSS keyframes | ~50 KB | cdnjs.cloudflare.com/ajax/libs/animate.css |

**Recommendation: AutoAnimate.** 3 KB, no config — add the library and
a `data-auto-animate` attribute to any container, and DOM updates
smooth themselves out. Makes the dashboard feel intentional rather than
janky. Animate.css is heavier and requires picking specific effects.

---

## Underrated picks worth considering

| Library | Category | Why |
|---|---|---|
| **Pico.css** | Base UI | Semantic styling, ~10 KB, zero config |
| **AutoAnimate** | Animation | 3 KB that makes the whole app feel polished |
| **uPlot** | Charts | Faster than libraries 20x its size |
| **Tabler Icons** | Icons | The most security-focused set with a webfont |
| **HTMX** | Interaction | AJAX-style behavior without writing JS |
| **Alpine.js** | Interaction | Lightweight Vue-like reactivity for HTML snippets |

---

## Do NOT use

Anything requiring **npm** or a **bundler**:

- React / Vue component libraries (MUI, Ant Design, Chakra)
- Tailwind CLI / PostCSS builds
- Any package without a pre-built CDN-hosted `.min.js` or `.min.css`

If it can't be loaded via a single `<script>` or `<link>` tag, it's out
of scope.

---

## Final recommendation

| Category | Choice | Weight |
|---|---|---|
| Base UI | Pico.css (CDN) | ~10 KB |
| Charts (2D) | uPlot (CDN) | ~45 KB |
| Charts (3D) | Plotly (existing) | 0 KB |
| Tables | Plain HTML + Pico.css | 0 KB |
| Icons | Tabler Icons (webfont) | ~100 KB |
| Animation | AutoAnimate (CDN) | ~3 KB |
| **Total** | | **~158 KB** |

Entirely CDN-based, no build step, minimal weight, significant polish
and performance gains.