(function() {
  // Inject styles for highlights and tooltips
  const style = document.createElement('style');
  style.textContent = `
    @keyframes domsniper-pulse {
      0% { outline: 3px solid rgba(211, 47, 47, 0.9); outline-offset: 2px; }
      50% { outline: 3px solid rgba(211, 47, 47, 0.3); outline-offset: 4px; }
      100% { outline: 3px solid rgba(211, 47, 47, 0.9); outline-offset: 2px; }
    }
    .domsniper-vulnerable {
      animation: domsniper-pulse 1.5s infinite !important;
      cursor: help !important;
    }
    .domsniper-tooltip {
      position: fixed;
      background: #1a1a1a;
      color: #eeeeee;
      padding: 12px;
      border-radius: 8px;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      font-size: 13px;
      z-index: 2147483647;
      border: 1px solid #d32f2f;
      box-shadow: 0 8px 24px rgba(0,0,0,0.5);
      pointer-events: auto;
      max-width: 450px;
      line-height: 1.4;
      display: none;
    }
    .domsniper-tooltip b { color: #ff5252; }
    .domsniper-tooltip code { background: #333; padding: 2px 4px; border-radius: 3px; font-family: monospace; }
    .domsniper-tooltip.sticky { border-width: 2px; box-shadow: 0 12px 32px rgba(0,0,0,0.8); }
    .domsniper-close-btn { 
      cursor: pointer; 
      padding: 2px 8px; 
      background: #444; 
      border-radius: 4px; 
      font-size: 10px; 
      border: none; 
      color: white; 
      margin-left: 10px;
    }
    .domsniper-close-btn:hover { background: #d32f2f; }
  `;
  document.documentElement.appendChild(style);

  // Global tooltip element
  const globalTooltip = document.createElement('div');
  globalTooltip.className = 'domsniper-tooltip';
  document.documentElement.appendChild(globalTooltip);

  function closeGlobalTooltip() {
    globalTooltip.style.display = 'none';
    globalTooltip.classList.remove('sticky');
    // We can't easily reset isSticky here without a global state, 
    // but the individual element handlers will handle it.
    // Actually, let's use a custom property on the tooltip.
    globalTooltip._isSticky = false;
  }

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeGlobalTooltip();
    }
  });

  // Capture original sinks
  const originalEval = window.eval;
  const originalSetTimeout = window.setTimeout;
  const originalSetInterval = window.setInterval;
  const originalDocumentWrite = document.write;
  const originalDocumentWriteln = document.writeln;
  
  // Element.prototype.innerHTML & outerHTML
  const originalInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  const originalOuterHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');

  // URL parameters to track
  const urlParams = new URLSearchParams(window.location.search);
  const hash = window.location.hash;
  
  let taintedStrings = [];
  
  urlParams.forEach((value) => {
    if (value) taintedStrings.push(value);
  });
  if (hash) {
    taintedStrings.push(hash.substring(1)); // without #
  }

  // Filter out tiny strings to avoid false positives (e.g. tracking "1" or "a")
  taintedStrings = taintedStrings.filter(s => s.length > 2);

  function escapeHTML(str) {
    if (!str) return "";
    return String(str).replace(/[&<>"']/g, function(m) {
      return {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
      }[m];
    });
  }


  function getSettings() {
    if (!document.documentElement) return { enableVisuals: true, showBorders: true, popoverLeft: false };
    const attr = document.documentElement.getAttribute('data-domsniper-settings');
    if (attr) {
      try {
        return JSON.parse(attr);
      } catch (e) {}
    }
    return { enableVisuals: true, showBorders: true, popoverLeft: false };
  }

  function applySettings() {
    const settings = getSettings();
    if (!settings.enableVisuals) {
      // Hide all alert boxes
      document.querySelectorAll('.domsniper-alert-box').forEach(el => el.style.display = 'none');
      // Hide global tooltip
      globalTooltip.style.display = 'none';
      // Remove all highlights
      document.querySelectorAll('.domsniper-vulnerable').forEach(el => el.classList.remove('domsniper-vulnerable'));
    } else {
      // Restore alert boxes (optional, but good for real-time toggle)
      document.querySelectorAll('.domsniper-alert-box').forEach(el => el.style.display = 'block');
      if (!settings.showBorders) {
        document.querySelectorAll('.domsniper-vulnerable').forEach(el => el.classList.remove('domsniper-vulnerable'));
      }
    }
  }

  // Observe settings changes
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      if (mutation.type === 'attributes' && mutation.attributeName === 'data-domsniper-settings') {
        applySettings();
      }
    });
  });
  if (document.documentElement) {
    observer.observe(document.documentElement, { attributes: true });
  }

  function getReferenceUrl(sinkName) {
    if (sinkName.includes('eval') || sinkName.includes('setTimeout') || sinkName.includes('setInterval')) {
      return "https://portswigger.net/web-security/cross-site-scripting/dom-based#javascript-execution-sinks";
    } else if (sinkName.includes('innerHTML') || sinkName.includes('document.write') || sinkName.includes('document.writeln')) {
      return "https://owasp.org/www-community/attacks/DOM_Based_XSS";
    }
    return "https://portswigger.net/web-security/cross-site-scripting/dom-based";
  }

  function checkTaint(sinkName, payload, element = null) {
    if (typeof payload !== 'string') return;
    
    let isTainted = false;
    let foundTaint = "";
    
    for (let taint of taintedStrings) {
      if (payload.includes(taint)) {
        isTainted = true;
        foundTaint = taint;
        break;
      }
    }

    // Always extract caller info
    const stack = new Error().stack;
    const stackLines = stack.split('\n');
    // stackLines[0] is Error
    // stackLines[1] is checkTaint
    // stackLines[2] is the hook wrapper
    // stackLines[3] is usually the actual caller we want
    let callerLine = stackLines.length > 3 ? stackLines[3].trim() : (stackLines[2] ? stackLines[2].trim() : "Unknown source");
    
    if (isTainted) {
      const refUrl = getReferenceUrl(sinkName);
      console.warn(`%c[DOMSniper] 🚨 TAINTED SINK DETECTED!\nSink: ${sinkName}\nPayload: ${payload}\nTaint: ${foundTaint}\nSource: ${callerLine}\nReference: ${refUrl}`, 'background: red; color: white; display: block; padding: 5px;');
      visualAlert(sinkName, payload, foundTaint, callerLine, refUrl, element);
      
      // Dispatch event to be picked up by the Isolated World content.js and sent to the background script
      window.dispatchEvent(new CustomEvent('DOMSNIPER_ALERT', { 
        detail: { 
          sinkName: sinkName, 
          taint: foundTaint, 
          payload: payload, 
          caller: callerLine,
          reference: refUrl,
          timestamp: Date.now()
        } 
      }));
    } else {
      console.info(`[DOMSniper] Sink called: ${sinkName} \nPayload snippet: ${payload.substring(0,50)} \nSource: ${callerLine}`);
    }
  }

  function visualAlert(sinkName, payload, taint, caller, refUrl, element = null) {
    const settings = getSettings();
    
    if (!settings.enableVisuals) return;

    // 1. Highlight the element if provided and enabled
    if (element && element.classList && settings.showBorders) {
      element.classList.add('domsniper-vulnerable');
      
      // Set up tooltip events for this specific element
      let isSticky = false;

      function updateTooltipContent(sticky = false) {
        const escapedSink = escapeHTML(sinkName);
        const escapedTaint = escapeHTML(taint);
        const escapedCaller = escapeHTML(caller);
        const escapedPayload = escapeHTML(payload);

        globalTooltip.innerHTML = `
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
            <div style="display: flex; align-items: center;">
              <b style="font-size: 15px;">🚨 DOM XSS ${sticky ? '(Sticky)' : ''}</b>
              ${sticky ? '<button class="domsniper-close-btn" id="domsniper-close-tooltip">✕ Close</button>' : ''}
            </div>
            <span style="font-size: 10px; background: #d32f2f; padding: 2px 6px; border-radius: 4px; color: white;">HIGH</span>
          </div>
          <div style="margin-bottom: 8px;">
            <b>Sink:</b> <code>${escapedSink}</code><br/>
            <b>Taint Found:</b> <code style="color: #4fc3f7;">${escapedTaint}</code>
          </div>
          <div style="margin-bottom: 8px;">
            <b>Source Trace:</b><br/>
            <div style="background: #222; padding: 8px; border-radius: 4px; font-family: monospace; font-size: 11px; margin-top: 4px; border: 1px solid #444; max-height: 150px; overflow-y: auto;">
              ${escapedCaller}
            </div>
          </div>
          <div style="margin-bottom: 8px;">
            <b>Payload Preview:</b><br/>
            <div style="background: #222; padding: 8px; border-radius: 4px; font-family: monospace; font-size: 11px; margin-top: 4px; border: 1px solid #444; color: #ffab91; word-break: break-all; max-height: 80px; overflow-y: auto;">
              ${escapedPayload}
            </div>
          </div>
          <div style="margin-top: 10px; border-top: 1px solid #333; pt-10px; display: flex; justify-content: space-between; align-items: center; padding-top: 8px;">
            <a href="${refUrl}" target="_blank" style="color: #64b5f6; text-decoration: none; font-size: 11px;">📖 Documentation</a>
            <span style="font-size: 10px; color: #888;">${sticky ? 'Esc to close' : 'Ctrl+Click to Pin'}</span>
          </div>
        `;
        
        if (sticky) {
          globalTooltip.classList.add('sticky');
          const closeBtn = document.getElementById('domsniper-close-tooltip');
          if (closeBtn) {
            closeBtn.onclick = (e) => {
                e.stopPropagation();
                closeTooltip();
            };
          }
        } else {
          globalTooltip.classList.remove('sticky');
        }
      }

      function closeTooltip() {
        isSticky = false;
        globalTooltip._isSticky = false;
        globalTooltip.style.display = 'none';
        globalTooltip.classList.remove('sticky');
      }

      element.onmouseenter = (e) => {
        if (isSticky || globalTooltip._isSticky) return;
        updateTooltipContent(false);
        globalTooltip.style.display = 'block';
        
        const elementRect = element.getBoundingClientRect();
        const tooltipRect = globalTooltip.getBoundingClientRect();
        
        let left = elementRect.left;
        let top = elementRect.top - tooltipRect.height - 10;
        
        if (top < 10) top = elementRect.bottom + 10;
        if (left + tooltipRect.width > window.innerWidth) left = window.innerWidth - tooltipRect.width - 20;

        globalTooltip.style.left = Math.max(10, left) + 'px';
        globalTooltip.style.top = Math.max(10, top) + 'px';
      };
      
      element.onclick = (e) => {
        if (e.ctrlKey || e.metaKey) {
          e.preventDefault();
          e.stopPropagation();
          isSticky = true;
          globalTooltip._isSticky = true;
          updateTooltipContent(true);
          globalTooltip.style.display = 'block';
        }
      };

      let isOverTooltip = false;
      globalTooltip.onmouseenter = () => { isOverTooltip = true; };
      globalTooltip.onmouseleave = () => { 
        isOverTooltip = false; 
        if (!isSticky && !globalTooltip._isSticky) globalTooltip.style.display = 'none'; 
      };

      element.onmousemove = null;
      
      element.onmouseleave = () => {
        if (isSticky || globalTooltip._isSticky) return;
        setTimeout(() => {
          if (!isOverTooltip && !isSticky && !globalTooltip._isSticky) {
            globalTooltip.style.display = 'none';
          }
        }, 200);
      };

    }

    // 2. Original floating alert box logic
    // Prevent recursive innerHTML hooking by using standard DOM methods safely
    const div = document.createElement('div');
    div.className = 'domsniper-alert-box';
    div.style.position = 'fixed';
    div.style.bottom = '10px';
    if (settings.popoverLeft) {
      div.style.left = '10px';
      div.style.borderLeft = 'none';
      div.style.borderRight = '6px solid #d32f2f';
    } else {
      div.style.right = '10px';
      div.style.borderLeft = '6px solid #d32f2f';
    }
    div.style.backgroundColor = '#1a1a1a';
    div.style.color = '#eeeeee';
    div.style.padding = '15px';
    div.style.zIndex = '2147483647'; // Max z-index
    div.style.borderRadius = '6px';
    div.style.fontFamily = 'monospace';
    div.style.maxWidth = '450px';
    div.style.wordWrap = 'break-word';
    div.style.border = '1px solid #333';
    div.style.borderLeft = '6px solid #d32f2f';
    div.style.boxShadow = '0 4px 15px rgba(0,0,0,0.7)';
    
    div.textContent = '🚨 DOM XSS Alert';
    
    const details = document.createElement('div');
    details.style.marginTop = '10px';
    details.style.fontSize = '12px';
    
    // helper to inject text securely to avoid self-triggering
    function addDetail(label, text) {
      const p = document.createElement('p');
      p.style.margin = '5px 0';
      const b = document.createElement('b');
      b.textContent = label + ': ';
      p.appendChild(b);
      p.appendChild(document.createTextNode(text));
      details.appendChild(p);
    }

    addDetail('Sink', sinkName);
    addDetail('Taint Source', taint);
    addDetail('Payload', payload.substring(0, 100) + (payload.length > 100 ? '...' : ''));
    addDetail('Code Line', caller);

    // Add clickable reference link safely
    const refP = document.createElement('p');
    refP.style.margin = '5px 0';
    const refB = document.createElement('b');
    refB.textContent = 'Reference: ';
    refP.appendChild(refB);
    const refA = document.createElement('a');
    refA.href = refUrl;
    refA.target = '_blank';
    refA.style.color = '#64b5f6';
    refA.textContent = 'Learn more about this vulnerability';
    refP.appendChild(refA);
    details.appendChild(refP);

    div.appendChild(details);

    // Close button
    const closeBtn = document.createElement('button');
    closeBtn.textContent = 'Dismiss';
    closeBtn.style.marginTop = '10px';
    closeBtn.style.cursor = 'pointer';
    closeBtn.onclick = function() { div.remove(); };
    div.appendChild(closeBtn);

    document.documentElement.appendChild(div);
  }

  // ==== Hooks ====

  window.eval = function() {
    checkTaint('eval()', arguments[0]);
    return originalEval.apply(this, arguments);
  };

  window.setTimeout = function() {
    if (typeof arguments[0] === 'string') {
        checkTaint('setTimeout(string)', arguments[0]);
    }
    return originalSetTimeout.apply(this, arguments);
  };

  window.setInterval = function() {
    if (typeof arguments[0] === 'string') {
        checkTaint('setInterval(string)', arguments[0]);
    }
    return originalSetInterval.apply(this, arguments);
  };

  document.write = function() {
    const element = document.currentScript ? document.currentScript.parentElement : null;
    for (let i = 0; i < arguments.length; i++) {
      checkTaint('document.write', String(arguments[i]), element);
    }
    return originalDocumentWrite.apply(this, arguments);
  };

  document.writeln = function() {
    const element = document.currentScript ? document.currentScript.parentElement : null;
    for (let i = 0; i < arguments.length; i++) {
        checkTaint('document.writeln', String(arguments[i]), element);
      }
      return originalDocumentWriteln.apply(this, arguments);
  }

  try {
    Object.defineProperty(Element.prototype, 'innerHTML', {
      set: function(value) {
        checkTaint('innerHTML', String(value), this);
        originalInnerHTML.set.call(this, value);
      },
      get: function() {
        return originalInnerHTML.get.call(this);
      }
    });

    Object.defineProperty(Element.prototype, 'outerHTML', {
      set: function(value) {
        checkTaint('outerHTML', String(value), this.parentElement || this);
        originalOuterHTML.set.call(this, value);
      },
      get: function() {
        return originalOuterHTML.get.call(this);
      }
    });
  } catch (e) {
    console.error("[DOMSniper] Failed to hook properties", e);
  }

  console.log("[DOMSniper] Active. Tracking URL taints:", taintedStrings);

})();
