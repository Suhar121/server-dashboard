# DESIGN.md --- VisActor Next Template

## 1. Purpose and Scope

This document describes the user interface and design requirements for
the VisActor Next Template dashboard, based on the publicly accessible
demo and its published repository documentation.

Reference: - Live demo: https://visactor-next-template.vercel.app/ -
Source repository: https://github.com/mengxi-ream/visactor-next-template

The application is a customer-support analytics dashboard. It presents
ticket volume, resolution performance, response time, channel
distribution, conversions, and customer satisfaction in a compact
dashboard layout.

**Evidence note:** The page content and documented stack are observable
from the public demo and repository. Exact CSS values, font family,
breakpoints, and some interaction details are not fully established by
the available page text. Design tokens and implementation values below
are therefore recommended specifications for a faithful, maintainable
implementation---not claims that every value is identical to the
original source.

## 2. Product and UX Goals

1.  Let an operator understand support performance quickly.
2.  Make high-level KPIs scannable before the user studies detailed
    charts.
3.  Present related metrics in a clear visual hierarchy.
4.  Support navigation between dashboard and ticket-related views.
5.  Support light and dark themes.
6.  Remain usable on desktop, tablet, and mobile.
7.  Keep chart components modular so data and chart types can evolve
    independently.

## 3. Application Shell

### 3.1 Global layout

Use a dashboard shell with three conceptual regions:

-   **Navigation sidebar:** brand/product navigation, primary
    destinations, and user identity.
-   **Main content area:** page title, page-level actions, KPI cards,
    and chart panels.
-   **Global controls:** theme toggle and account/profile area.

The public demo exposes navigation entries for **Dashboard** and
**Ticket**, a user area labelled **Agent Admin**, and a theme toggle.

### 3.2 Sidebar

Expected responsibilities: - Identify the application and provide
persistent navigation. - Show the active route with a visually distinct
state. - Provide accessible labels for all icons. - Collapse to a
compact icon rail on medium-sized screens if the available width is
constrained. - Become a drawer or off-canvas navigation on narrow mobile
screens.

Recommended behavior: - Desktop: persistent sidebar. - Tablet:
collapsible sidebar. - Mobile: menu button opens a drawer; selecting a
route closes it. - Active navigation must be indicated by more than
color alone.

### 3.3 Main content header

The dashboard header should include: - Page title: `Dashboard` -
Optional supporting description - Theme toggle - User/profile identity
where appropriate

Keep the header visually quiet. It should not compete with KPI values or
charts.

## 4. Dashboard Information Architecture

The dashboard content is arranged in two levels.

### Level 1 --- KPI overview

Four summary cards:

1.  **Created Tickets** --- total tickets created and month-over-month
    change.
2.  **Unsolved Tickets** --- current unresolved workload and change.
3.  **Resolved Tickets** --- completed tickets and change.
4.  **Average First Time Reply** --- average first-response time and
    change.

The reference page displays these example values: - Created Tickets:
`24,208`, change `-5%` - Unsolved Tickets: `4,564`, change `+2%` -
Resolved Tickets: `18,208`, change `+8%` - Average First Time Reply:
`12:01 min`, change `+8%`

These are reference/demo figures, not live business data.

Each KPI card should contain: - A concise label - A prominent value - A
comparison value or trend indicator - Supporting text such as
`Compare to last month` - Optional icon, used sparingly

Do not rely on green/red color alone to explain whether a change is good
or bad. For example, an increase in unsolved tickets may be undesirable
while an increase in resolved tickets may be positive.

### Level 2 --- Analytical panels

The public demo identifies the following panels:

-   **Average Tickets Created:** a date-based chart with a displayed
    period of `Dec 18, 2023 – Dec 24, 2023`; the documented template
    describes a bar chart.
-   **Conversions:** a visualization showing `17,220 Sales`; the
    repository documentation describes a circle-packing chart.
-   **Ticket By Channels:** a channel distribution visualization; the
    repository documentation describes a gauge chart.
-   **Customer Satisfication** (reference spelling): satisfaction
    summary with 156 responses:
    -   Positive: 80%
    -   Neutral: 15%
    -   Negative: 5%

The visible page also lists `Avg. Tickets Created: 3,817` and
`Avg. Tickets Resolved: 2,176` in the chart context. Preserve these as
sample data only if reproducing the demo.

## 5. Recommended Layout Grid

Use a responsive, 12-column desktop grid or an equivalent CSS grid.

### Desktop (approximately 1200 px and wider)

-   Persistent sidebar on the left.
-   Main content fills the remaining width.
-   Four KPI cards in one row where space permits.
-   Analytical panels arranged in two columns, with the most important
    or time-series panel given adequate width.
-   Consistent gaps between cards and chart panels.

### Tablet (approximately 768--1199 px)

-   Sidebar may collapse.
-   KPI cards in two columns.
-   Chart panels in one or two columns according to minimum readable
    chart width.
-   Keep card headings and chart legends from wrapping awkwardly.

### Mobile (below approximately 768 px)

-   Sidebar becomes a drawer.
-   KPI cards use one column on very narrow screens and two columns only
    when each card remains readable.
-   Charts stack vertically.
-   Chart tooltips must be touch-friendly.
-   Avoid horizontal page scrolling; allow contained horizontal
    scrolling only for dense tables or charts when necessary.
-   Reduce nonessential labels before reducing the legibility of data.

These breakpoints are implementation recommendations. Adjust them after
testing the actual component widths.

## 6. Visual Design Direction

### 6.1 Overall style

Use a modern, restrained SaaS dashboard aesthetic: - Clear hierarchy -
Neutral page background - Surface-based cards - Subtle borders and
restrained shadows - Consistent spacing - Compact but readable labels -
Data visualizations that carry the visual emphasis

Avoid decorative gradients, oversized marketing typography, excessive
icons, and strong shadows that make the dashboard feel like a landing
page.

### 6.2 Suggested design tokens

These are starter tokens to tune against a screenshot or the original
CSS.

  Token             Suggested light-theme value   Purpose
  ----------------- ----------------------------- -----------------------------------------
  Page background   `#F8FAFC`                     Main canvas
  Card/surface      `#FFFFFF`                     Cards and panels
  Primary text      `#0F172A`                     Headings and values
  Secondary text    `#64748B`                     Labels and supporting copy
  Border            `#E2E8F0`                     Card edges and dividers
  Primary accent    `#2563EB`                     Links, focus, selected states
  Positive          `#16A34A`                     Positive trend where semantically valid
  Warning           `#D97706`                     Caution states
  Negative          `#DC2626`                     Negative trend where semantically valid
  Muted surface     `#F1F5F9`                     Secondary panels

Dark theme should use a deep neutral page background, elevated neutral
surfaces, readable muted text, and adjusted chart colors that retain
contrast. Do not simply invert every color.

### 6.3 Typography

Use a modern sans-serif system stack unless the original repository
specifies a bundled font.

Recommended hierarchy: - Page title: 24--30 px, semibold - KPI value:
26--34 px, semibold - Panel title: 15--18 px, semibold - KPI label and
chart metadata: 12--14 px - Supporting text and axis labels: 12--13 px

Use tabular numerals for large metrics and time values where available.
Keep line height comfortable and avoid overly light weights for small
text.

### 6.4 Spacing and shape

Suggested starting scale: - 4 px: micro spacing - 8 px: compact
spacing - 12 px: label-to-value spacing - 16 px: standard internal card
spacing - 24 px: panel spacing - 32 px: major section spacing

Suggested card styling: - 8--12 px corner radius - 1 px subtle border -
Little or no shadow - Consistent padding, typically 16--24 px depending
on viewport

## 7. Component Specifications

### 7.1 KPI card

Structure: 1. Label 2. Primary value 3. Trend indicator 4. Comparison
helper text

States: - Default - Loading/skeleton - Empty or unavailable data -
Error - Updated value

Requirements: - Align values consistently across cards. - Format counts
with locale-aware separators. - Format durations as durations, not
generic numbers. - Explain the comparison period. - If a metric cannot
be calculated, show `—` with a helpful explanation rather than `0`.

### 7.2 Chart panel

Structure: - Panel title - Optional description or date range - Optional
legend or metric summary - Chart body - Optional footer/source note

Requirements: - Keep chart titles consistent. - Ensure chart content
resizes with its container. - Avoid clipping axis labels, legends, and
tooltips. - Provide an accessible text summary of the data. - Include
loading, empty, and error states. - Use real units and meaningful axis
labels. - Tooltips should show the exact value and relevant
date/category.

### 7.3 Average Tickets Created --- bar chart

Purpose: show ticket creation volume over time.

Requirements: - X-axis: date or day. - Y-axis: number of tickets. - Bars
should be visually consistent and distinguishable. - Show the selected
date range. - Tooltip should include the date and ticket count. - If
users can change the range, update the chart and summary values
together. - Avoid implying a trend from an incomplete date range.

### 7.4 Conversions --- circle-packing chart

Purpose: show a hierarchical or grouped sales/conversion breakdown.

Requirements: - Use circle packing only when the data has meaningful
group/parent-child structure. - Give each group a stable color. - Label
circles only when the label fits. - Show detailed labels and values in a
tooltip. - Include a fallback legend or tabular summary for
accessibility. - If the data is a single total with no hierarchy, use a
simpler visualization instead of inventing hierarchy.

The reference demo reports `17,220 Sales`; do not infer a breakdown that
is not provided.

### 7.5 Ticket By Channels --- gauge chart

Purpose: communicate a channel-related measure or distribution.

Requirements: - Clearly state what the gauge measures. - Include the
unit and target/range if applicable. - Do not use a gauge to imply a
percentage when the underlying data is a count. - Add a numeric label
and accessible summary. - If the intended meaning is channel share,
consider a bar chart or donut chart instead; a gauge is appropriate only
for a single measure against a range or target.

### 7.6 Customer satisfaction

Reference values: - 156 responses - Positive 80% - Neutral 15% -
Negative 5%

Requirements: - Display total responses and the three sentiment
categories. - Use clearly named labels alongside percentages. - Maintain
distinguishable colors and sufficient contrast. - Ensure percentages sum
to 100%, allowing for rounding if the underlying data requires it. -
Explain the collection period if the production product has one. - Do
not treat the demo figures as live values.

### 7.7 Theme toggle

Requirements: - Provide a clearly labelled accessible control. - Support
light and dark themes. - Keep text, borders, charts, tooltips, focus
rings, and icons legible in both themes. - Persist the user preference
if the app architecture supports it. - Respect system preference on
first visit where appropriate. - Avoid flashing the wrong theme during
initial render.

### 7.8 User identity

The demo shows `Agent Admin`.

Requirements: - Show the current user's display name and, if available,
avatar. - Use a menu for profile/settings actions if those actions
exist. - Do not expose account actions that are not implemented.

## 8. Color and Data Semantics

Use color consistently: - Positive/negative trends should be determined
by metric meaning, not sign alone. - Keep chart series colors stable
between views. - Ensure adjacent chart segments have enough contrast. -
Do not communicate categories by color alone; pair color with labels,
patterns, or symbols when useful. - Check text and interactive elements
against WCAG contrast guidance.

For the customer satisfaction chart, use three distinguishable semantic
colors and preserve labels in the legend.

## 9. Interaction and Behavior

### Navigation

-   Selecting Dashboard opens the dashboard view.
-   Selecting Ticket opens the ticket view.
-   The current route is visually indicated.
-   Browser back/forward navigation should work.

### Theme

-   Activating the theme control switches theme.
-   The selected theme applies consistently to the whole interface,
    including chart rendering.
-   The control has an accessible name and keyboard support.

### Chart interactions

-   Hover-capable devices may display tooltips on hover.
-   Touch devices must support tapping to inspect values.
-   Legends should clarify categories and series.
-   Any filter or date-range control must update all dependent metrics
    consistently.
-   If chart data is static, do not display controls that suggest it can
    be changed.

### Data refresh

If live data is added: - Provide a last-updated timestamp. - Handle slow
requests and failures. - Avoid showing a mixture of stale and fresh
values without indication. - Keep all KPI and chart values tied to the
same filter/date range where relevant.

## 10. Responsive and Accessibility Requirements

-   Semantic page headings and landmark regions.
-   Keyboard-accessible navigation and controls.
-   Visible focus states.
-   Descriptive accessible names for icon-only buttons.
-   Sufficient color contrast.
-   Charts must have an accessible textual summary or data alternative.
-   Do not depend on hover alone.
-   Respect reduced-motion preferences.
-   Prevent layout overflow at 320 px viewport width.
-   Keep target sizes comfortable for touch interaction.
-   Ensure chart legends and tooltips remain readable at browser zoom.

## 11. Recommended Frontend Architecture

The repository documentation identifies this stack: - Next.js 15 - React
/ TypeScript - VisActor visualization components - Tailwind CSS -
shadcn/ui components - Jotai for state management

The documented project structure includes: - `src/app/` --- application
routes - `src/components/chart-blocks/` --- chart components -
`src/components/nav/` --- navigation components - `src/components/ui/`
--- shared UI components - `src/config/` --- configuration - `src/data/`
--- sample data - `src/hooks/` --- custom hooks - `src/lib/` --- utility
functions - `src/style/` --- global styles - `src/types/` --- TypeScript
types

Recommended component boundaries: - `AppShell` - `SidebarNavigation` -
`DashboardHeader` - `ThemeToggle` - `KpiCard` - `ChartPanel` -
`TicketVolumeChart` - `ConversionChart` - `TicketChannelChart` -
`CustomerSatisfactionPanel`

Keep chart-specific configuration separate from layout components. Share
reusable card, typography, and spacing styles. Use typed data models for
each metric and chart.

## 12. Data Model Guidance

Use structured data rather than embedding values directly in UI markup.

Example conceptual models:

``` ts
type MetricSummary = {
  id: string;
  label: string;
  value: number | string;
  changePercent?: number;
  comparisonLabel?: string;
  direction?: "up" | "down" | "flat";
};

type TicketVolumePoint = {
  date: string;
  created: number;
  resolved?: number;
};

type SatisfactionSummary = {
  responses: number;
  positivePercent: number;
  neutralPercent: number;
  negativePercent: number;
};
```

The UI should distinguish missing data from legitimate zero values. Add
validation for totals and percentages before rendering.

## 13. Loading, Empty, and Error States

Every data panel should support: - **Loading:** skeletons with
dimensions close to the final content. - **Empty:** concise explanation
and, when appropriate, a next step. - **Error:** a nontechnical message
and retry action if retry is supported. - **Partial data:** display
available values while clearly marking unavailable sections. - **Stale
data:** show when the last successful update occurred.

Avoid flashing layout shifts when charts initialize. Reserve chart
height before rendering.

## 14. Performance Considerations

-   Keep the dashboard shell lightweight.
-   Avoid unnecessary rerenders of every chart when one card changes.
-   Load heavy visualization code only where it is needed.
-   Memoize expensive data transformations when profiling shows value.
-   Provide stable chart container dimensions.
-   Test chart rendering on low-powered mobile devices.
-   Avoid adding animation that slows interaction or obscures data.

## 15. Design Acceptance Checklist

### Visual

-   [ ] The dashboard has a clear sidebar/header/content hierarchy.
-   [ ] KPI cards use consistent sizing, spacing, and number alignment.
-   [ ] Chart panels use consistent titles, padding, borders, and
    backgrounds.
-   [ ] Light and dark themes are both legible.
-   [ ] No accidental horizontal page overflow occurs.

### Content

-   [ ] KPI labels and comparison periods are explicit.
-   [ ] Counts, percentages, currency, and durations use appropriate
    formatting.
-   [ ] The sample data is not presented as live production data.
-   [ ] Satisfaction percentages and response totals are validated.
-   [ ] Chart axes, units, legends, and tooltips are understandable.

### Behavior

-   [ ] Dashboard and Ticket navigation work.
-   [ ] Active navigation state follows the current route.
-   [ ] Theme switching updates the entire interface.
-   [ ] Charts display useful tooltips or touch interactions.
-   [ ] Loading, empty, and error states are implemented.

### Accessibility

-   [ ] All controls work with a keyboard.
-   [ ] Focus states are visible.
-   [ ] Icon-only controls have accessible names.
-   [ ] Charts have text alternatives.
-   [ ] Color is not the sole way to convey meaning.

### Responsive

-   [ ] The dashboard works at desktop, tablet, and mobile widths.
-   [ ] The sidebar becomes usable mobile navigation.
-   [ ] KPI cards and charts reflow without clipping.
-   [ ] Tooltips and legends work on touch screens.

## 16. Source Notes and Limitations

The public demo exposes the main dashboard labels and sample values. The
repository README documents the main features, visualization types,
technology stack, and source folder structure.

This file is a **design specification derived from those public
references**, not a pixel-perfect reverse-engineering report. Exact
spacing, font choices, CSS values, all routes, and all interaction
states should be confirmed by inspecting the live interface at multiple
viewport sizes and, for implementation-level accuracy, reviewing the
repository source.

### References

-   Live dashboard: https://visactor-next-template.vercel.app/
-   Source repository and README:
    https://github.com/mengxi-ream/visactor-next-template
-   Vercel template listing:
    https://examples.vercel.com/templates/next.js/visactor-nextjs-template
