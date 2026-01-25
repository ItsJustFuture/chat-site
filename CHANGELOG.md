# Changelog

## Unreleased
- Added separate username and message text customization settings with migration into a unified customization blob.
- Redesigned the text customization modal into a two-column layout with richer previews and responsive stacking.
- Expanded gradient presets and improved gradient visibility with safer text contrast helpers.
- Legacy bubble preference cleanup now removes outdated bubble keys on settings load.
- Main vs. DM styling is scoped via explicit message context classes and chat roots.
- DM bubble appearance is driven by theme tokens with safe defaults.
- UI copy now references message layout, density, accent style, and contrast.
- Performance guardrails reduce unused bubble effects and heavy DM bubble styling.
