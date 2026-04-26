# DOM XSS Tracer

![DOM XSS Tracer Screenshot](docs/Screenshot%202026-04-26%20203035.png)

DOM XSS Tracer is a Chrome Extension designed for penetration testers to seamlessly trace DOM-based Cross-Site Scripting (XSS) vulnerabilities.

## Features
- **Sink Hooking**: Intercepts dangerous Javascript sinks like `eval()`, `setTimeout()`, `setInterval()`, `document.write()`, and `.innerHTML`.
- **Taint Tracking**: Automatically pulls URL query parameters and hashes, identifying if those raw string variables reach sinks without proper sanitization.
- **Trace Back**: Groups alerts with stack traces giving exact file lines of offending execution. 
- **Visual Alerting**: Injects a fixed UI badge on triggered sinks during active browsing.
- **Developer Popup**: Offers a centralized dashboard in the Extension's badge popup showcasing all active unmitigated DOM XSS triggers found during the session.

## Installation
1. Go to `chrome://extensions/` in Chrome.
2. Ensure **Developer mode** is enabled in the top right.
3. Click **Load unpacked** and select the `/extension` directory of this project.

## Developer Documentation
For details on modifying the underlying tracer hooks and background architecture, please refer to the [Developer Documentation](/docs/developer_guide.md).
