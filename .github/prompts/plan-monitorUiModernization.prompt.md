# Modernization Plan: Monitor UI

This plan outlines the steps to modernize the user interface of the system monitor dashboard, focusing on a "Glassmorphism" aesthetic, improved typography, and smoother interactivity.

## 1. Visual Overhaul

**Goal**: Switch to a deep blue, glass-like aesthetic with modern typography.

-   **Font**: Import **Inter** from Google Fonts.
-   **Color Palette**:
    -   Background: Deep radial gradient (Dark Blue to Black).
    -   Cards: Semi-transparent white/blue with `backdrop-filter: blur()`.
    -   Text: High contrast white/grey.
    -   Accents: Neon Cyan, Orange, Green (brighter, glowing).
-   **CSS Variables Update**:
    ```css
    :root {
        --bg: #050505;
        --card-bg: rgba(20, 30, 45, 0.6);
        --card-border: rgba(255, 255, 255, 0.08);
        --text-main: #ffffff;
        --text-muted: #94a3b8;
        --accent-primary: #00f2ff; /* Neon Cyan */
        --accent-secondary: #ff8c00; /* Deep Orange */
        --glass-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.36);
    }
    ```
-   **Card Styling**:
    -   Apply `backdrop-filter: blur(12px)`.
    -   Add subtle white border glow.
    -   Rounded corners: `24px`.

## 2. Iconography

**Goal**: Replace inline SVGs with a consistent, lightweight icon library.

-   **Library**: **RemixIcon** (via CDN).
-   **Implementation**:
    -   Add `<link href="https://cdn.jsdelivr.net/npm/remixicon@3.5.0/fonts/remixicon.css" rel="stylesheet">` to `<head>`.
    -   Replace inline `<svg>` blocks with semantic icon tags (e.g., `<i class="ri-cpu-line"></i>`, `<i class="ri-drop-line"></i>`).

## 3. Layout Optimization

**Goal**: Improve spacing and responsiveness.

-   **Grid**: Increase gap to `24px` to allow the "glass" effect to breathe.
-   **Header**: Make the header floating/sticky with a stronger blur effect.
-   **Responsive**: Ensure single-column layout triggers smoothly on mobile (<768px).

## 4. Interactivity & Motion

**Goal**: Make the UI feel alive.

-   **Transitions**: Add `transition: all 0.3s ease` to cards and buttons.
-   **Hover Effects**:
    -   Cards: Slight lift (`transform: translateY(-4px)`) and increased border brightness on hover.
    -   Buttons: Glow effect.
-   **Loading State**:
    -   Create a simple CSS skeleton loader class (`.skeleton`) to apply to text elements before the first API response arrives.

## 5. Chart Styling (Canvas)

**Goal**: Make charts look like modern data visualizations.

-   **Gradient Fills**: Update the `Spark` class `draw()` method to use a vertical gradient fade (Solid color at top -> Transparent at bottom).
-   **Line Smoothing**: Increase line width to `3px` and use `lineJoin = 'round'`.
-   **Animation**: (Optional) Animate the new point entry if performance allows, otherwise focus on the visual quality of the static draw.

---

### Execution Steps

1.  **Edit `src/MonitorApp/wwwroot/index.html`**:
    -   Add Google Fonts and RemixIcon links in `<head>`.
    -   Rewrite the `<style>` block with the new CSS variables and classes.
    -   Update the HTML structure to use `<i class="ri-...">` tags.
    -   Update the `Spark` class in the `<script>` section.
2.  **Verify**: Open the file in a browser to check the visual changes.
