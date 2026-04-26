(function() {
  // Capture original sinks
  const originalEval = window.eval;
  const originalSetTimeout = window.setTimeout;
  const originalSetInterval = window.setInterval;
  const originalDocumentWrite = document.write;
  const originalDocumentWriteln = document.writeln;
  
  // Element.prototype.innerHTML
  const originalInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');

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

  function getReferenceUrl(sinkName) {
    if (sinkName.includes('eval') || sinkName.includes('setTimeout') || sinkName.includes('setInterval')) {
      return "https://portswigger.net/web-security/cross-site-scripting/dom-based#javascript-execution-sinks";
    } else if (sinkName.includes('innerHTML') || sinkName.includes('document.write') || sinkName.includes('document.writeln')) {
      return "https://owasp.org/www-community/attacks/DOM_Based_XSS";
    }
    return "https://portswigger.net/web-security/cross-site-scripting/dom-based";
  }

  function checkTaint(sinkName, payload) {
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
      visualAlert(sinkName, payload, foundTaint, callerLine, refUrl);
      
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

  function visualAlert(sinkName, payload, taint, caller, refUrl) {
    // Prevent recursive innerHTML hooking by using standard DOM methods safely
    const div = document.createElement('div');
    div.style.position = 'fixed';
    div.style.bottom = '10px';
    div.style.right = '10px';
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
    for (let i = 0; i < arguments.length; i++) {
      checkTaint('document.write', String(arguments[i]));
    }
    return originalDocumentWrite.apply(this, arguments);
  };

  document.writeln = function() {
    for (let i = 0; i < arguments.length; i++) {
        checkTaint('document.writeln', String(arguments[i]));
      }
      return originalDocumentWriteln.apply(this, arguments);
  }

  try {
    Object.defineProperty(Element.prototype, 'innerHTML', {
      set: function(value) {
        checkTaint('innerHTML', String(value));
        originalInnerHTML.set.call(this, value);
      },
      get: function() {
        return originalInnerHTML.get.call(this);
      }
    });
  } catch (e) {
    console.error("[DOMSniper] Failed to hook innerHTML", e);
  }

  console.log("[DOMSniper] Active. Tracking URL taints:", taintedStrings);

})();
