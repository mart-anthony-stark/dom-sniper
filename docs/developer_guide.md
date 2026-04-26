# Developer Guide: DOMSniper

## Architecture
The extension is built utilizing **Manifest V3** constraints, relying heavily on proper isolation world interactions:

1. **`tracer.js` (Main World Injection)**
   - Because standard content scripts execute in an `ISOLATED` world by default (where `window` modifications don't apply to the page), this script runs explicitly in the `MAIN` world (`world: "MAIN"` in `manifest.json`).
   - Replaces native objects with Proxy/Wrapper variants keeping the underlying function logic but analyzing the string inputs before passing them down.
   - Pushes findings down to the DOM layer via `window.dispatchEvent()`.

2. **`content.js` (Isolated World Content Script)**
   - Sits concurrently on the page listening for CustomEvents emitted by `tracer.js`. 
   - Uses Chrome's `runtime.sendMessage` API (only available in the isolated scope or background scripts) to ship findings securely to the Background Service Worker.

3. **`background.js` (Service Worker)**
   - Manages state. Caches arrays of vulnerability traces mapped to specific Tab IDs.
   - Updates the Extension badge (count + color red) dynamically.

## Adding new Sinks
If you aim to trace new API integrations:
1. Locate the native function reference in `tracer.js` (e.g. `const originalSink = window.Sink;`).
2. Implement your override passing through standard execution context utilizing `.apply(this, arguments)`.
3. Route the execution parameter to the `checkTaint('SinkName', argument)` validation logic.
