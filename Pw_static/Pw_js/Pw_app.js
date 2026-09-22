/**
 * Pw_app.js - Interactive Client Controller for Phishing Inspector Bento UI.
 * Handles mode switching, sample injection, async API queries, Donut score animations,
 * dynamic flag rendering, domain intelligence, and recent scans feed.
 */

document.addEventListener("DOMContentLoaded", () => {
  // DOM Elements
  const tabText = document.getElementById("tabText");
  const tabUrl = document.getElementById("tabUrl");
  const inputLabel = document.getElementById("inputLabel");
  const offerInput = document.getElementById("offerInput");
  const charCount = document.getElementById("charCount");
  const clearBtn = document.getElementById("clearBtn");
  const analyzeBtn = document.getElementById("analyzeBtn");
  const btnText = document.getElementById("btnText");
  const scanStepper = document.getElementById("scanStepper");
  const alertBanner = document.getElementById("alertBanner");
  const alertMessage = document.getElementById("alertMessage");

  // Sample Buttons
  const useSampleBtn = document.getElementById("useSampleBtn");
  const useUrlSampleBtn = document.getElementById("useUrlSampleBtn");

  // Results Elements
  const resultsCol = document.getElementById("resultsCol");
  const resultTag = document.getElementById("resultTag");
  const donutMeter = document.getElementById("donutMeter");
  const scoreNum = document.getElementById("scoreNum");
  const riskBadge = document.getElementById("riskBadge");
  const riskLabel = document.getElementById("riskLabel");
  const riskSummary = document.getElementById("riskSummary");
  const flagsContainer = document.getElementById("flagsContainer");
  const domainIntelBox = document.getElementById("domainIntelBox");
  const intelDomain = document.getElementById("intelDomain");
  const intelAge = document.getElementById("intelAge");
  const intelRegistrar = document.getElementById("intelRegistrar");
  const intelStatus = document.getElementById("intelStatus");
  const actionText = document.getElementById("actionText");
  const scansFeed = document.getElementById("scansFeed");

  let currentMode = "text"; // "text" | "url"

  // Preset Samples
  const SAMPLE_OFFER_TEXT =
    `Subject: Congratulations! You're Selected!

Hi,
We are pleased to inform you that you have been selected for a remote position at GlobalTech Solutions. To confirm your position, please pay a refundable security deposit of ₹4,999 for your laptop and training kit. This must be completed within 24 hours.

Contact recruiter on Telegram @hr_onboard_team.
Join our team and start your career!

Best regards,
HR Team
GlobalTech Solutions`;

  const SAMPLE_PHISHING_URL = "https://careers-amazon-security.xyz/apply?ref=102";

  // ==========================================
  // Mode Switching
  // ==========================================
  function setMode(mode) {
    currentMode = mode;
    hideAlert();

    if (mode === "text") {
      tabText.classList.add("active");
      tabText.setAttribute("aria-selected", "true");
      tabUrl.classList.remove("active");
      tabUrl.setAttribute("aria-selected", "false");
      inputLabel.textContent = "Paste job offer / email / message here";
      offerInput.placeholder = "Paste the job offer, email, or message you received...";
      offerInput.setAttribute("rows", "6");
      offerInput.setAttribute("maxlength", "5000");
    } else {
      tabUrl.classList.add("active");
      tabUrl.setAttribute("aria-selected", "true");
      tabText.classList.remove("active");
      tabText.setAttribute("aria-selected", "false");
      inputLabel.textContent = "Enter target offer or recruitment URL to inspect";
      offerInput.placeholder = "https://example-careers-verification.xyz/apply...";
      offerInput.setAttribute("rows", "3");
      offerInput.setAttribute("maxlength", "1000");
    }

    updateCharCount();
  }

  tabText.addEventListener("click", () => setMode("text"));
  tabUrl.addEventListener("click", () => setMode("url"));

  // ==========================================
  // Input Handling & Character Count
  // ==========================================
  function updateCharCount() {
    const len = offerInput.value.length;
    const max = currentMode === "text" ? 5000 : 1000;
    charCount.textContent = `${len}/${max} characters`;
    clearBtn.style.display = len > 0 ? "inline-block" : "none";
  }

  offerInput.addEventListener("input", () => {
    updateCharCount();
    hideAlert();
  });

  clearBtn.addEventListener("click", () => {
    offerInput.value = "";
    updateCharCount();
    hideAlert();
    offerInput.focus();
  });

  // ==========================================
  // Sample Presets (1-Click Judge Demo)
  // ==========================================
  useSampleBtn.addEventListener("click", () => {
    setMode("text");
    offerInput.value = SAMPLE_OFFER_TEXT;
    updateCharCount();
    hideAlert();
    offerInput.scrollIntoView({ behavior: "smooth", block: "center" });
    // Run immediate scan for instant responsiveness
    triggerAnalysis();
  });

  useUrlSampleBtn.addEventListener("click", () => {
    setMode("url");
    offerInput.value = SAMPLE_PHISHING_URL;
    updateCharCount();
    hideAlert();
    offerInput.scrollIntoView({ behavior: "smooth", block: "center" });
    // Run immediate scan for instant responsiveness
    triggerAnalysis();
  });

  // ==========================================
  // Alerts & Validation
  // ==========================================
  function showAlert(msg) {
    alertMessage.textContent = msg;
    alertBanner.style.display = "flex";
  }

  function hideAlert() {
    alertBanner.style.display = "none";
  }

  // ==========================================
  // Analysis Trigger & Fetch
  // ==========================================
  analyzeBtn.addEventListener("click", triggerAnalysis);

  async function triggerAnalysis() {
    const content = offerInput.value.trim();

    if (!content) {
      showAlert(currentMode === "text" ? "Please paste an offer letter to inspect." : "Please enter a URL to inspect.");
      offerInput.focus();
      return;
    }

    // Begin Loading State
    hideAlert();
    analyzeBtn.disabled = true;
    btnText.textContent = "Analyzing...";
    scanStepper.style.display = "flex";

    // Stepper Animation
    const s1 = document.getElementById("step1");
    const s2 = document.getElementById("step2");
    const s3 = document.getElementById("step3");

    s1.className = "step-indicator active";
    s2.className = "step-indicator";
    s3.className = "step-indicator";

    const stepTimer1 = setTimeout(() => {
      s1.className = "step-indicator done";
      s2.className = "step-indicator active";
    }, 600);

    const stepTimer2 = setTimeout(() => {
      s2.className = "step-indicator done";
      s3.className = "step-indicator active";
    }, 1200);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: currentMode, content: content })
      });

      const payload = await response.json();

      clearTimeout(stepTimer1);
      clearTimeout(stepTimer2);
      s3.className = "step-indicator done";

      if (!response.ok || payload.status !== "success") {
        const errorMsg = payload.message || "Threat inspection failed. Please try again.";
        showAlert(errorMsg);
        return;
      }

      // Render Dynamic Results
      renderAnalysisResults(payload.data);

      // Smooth scroll to results
      resultsCol.scrollIntoView({ behavior: "smooth", block: "start" });

    } catch (err) {
      showAlert("Network connection error. Is the Flask service running?");
      console.error("Analysis request failed:", err);
    } finally {
      analyzeBtn.disabled = false;
      btnText.textContent = "Analyze for Scam";
      setTimeout(() => {
        scanStepper.style.display = "none";
      }, 500);
    }
  }

  // ==========================================
  // Dynamic DOM Rendering
  // ==========================================
  function renderAnalysisResults(data) {
    resultTag.textContent = "LIVE SCAN RESULT";

    const score = Math.max(0, Math.min(100, data.threat_score || 0));
    const risk = (data.risk_level || "LOW").toUpperCase();

    // 1. Animate Donut Gauge
    animateDonutScore(score);

    // 2. Risk Badge & Threat Indicator Bar Styling
    riskBadge.className = "risk-pill";
    const threatBarFill = document.getElementById("threatBarFill");

    let circleColor = "#2ECC71"; // default safe green
    if (risk === "CRITICAL" || score >= 75) {
      riskBadge.classList.add("risk-critical");
      riskLabel.textContent = "Critical Risk";
      circleColor = "#E63946";
      if (threatBarFill) {
        threatBarFill.style.width = `${score}%`;
        threatBarFill.style.background = "linear-gradient(90deg, #F4A261, #E63946)";
        threatBarFill.style.boxShadow = "0 0 12px rgba(230, 57, 70, 0.7)";
      }
    } else if (risk === "HIGH" || score >= 50) {
      riskBadge.classList.add("risk-high");
      riskLabel.textContent = "High Risk";
      circleColor = "#FF6E42";
      if (threatBarFill) {
        threatBarFill.style.width = `${score}%`;
        threatBarFill.style.background = "linear-gradient(90deg, #F4A261, #FF6E42)";
        threatBarFill.style.boxShadow = "0 0 10px rgba(255, 110, 66, 0.6)";
      }
    } else if (risk === "MEDIUM" || score >= 25) {
      riskBadge.classList.add("risk-medium");
      riskLabel.textContent = "Medium Risk";
      circleColor = "#F4A261";
      if (threatBarFill) {
        threatBarFill.style.width = `${score}%`;
        threatBarFill.style.background = "linear-gradient(90deg, #2ECC71, #F4A261)";
        threatBarFill.style.boxShadow = "0 0 8px rgba(244, 162, 97, 0.5)";
      }
    } else {
      riskBadge.classList.add("risk-safe");
      riskLabel.textContent = "Low Risk / Safe";
      circleColor = "#2ECC71";
      if (threatBarFill) {
        threatBarFill.style.width = `${Math.max(5, score)}%`;
        threatBarFill.style.background = "#2ECC71";
        threatBarFill.style.boxShadow = "0 0 8px rgba(46, 204, 113, 0.6)";
      }
    }

    // Apply color to circle meter via both style and attribute for 100% browser compatibility
    donutMeter.style.stroke = circleColor;
    donutMeter.setAttribute("stroke", circleColor);

    // 3. Summary & Recommended Action
    riskSummary.textContent = data.summary || "Scan completed successfully.";
    actionText.textContent = data.recommended_action || "Verify company through authentic corporate domains.";

    // 4. Domain Intelligence (if URL scan)
    if (data.domain_intelligence && data.domain_intelligence.domain) {
      const intel = data.domain_intelligence;
      domainIntelBox.style.display = "block";
      intelDomain.textContent = intel.domain;

      if (intel.age_days !== null && intel.age_days !== undefined) {
        intelAge.textContent = `${intel.age_days} days old`;
        intelAge.className = intel.is_new_domain ? "highlight-warn" : "";
      } else {
        intelAge.textContent = "Unverified";
        intelAge.className = "";
      }

      intelRegistrar.textContent = intel.registrar || "Not Disclosed";
      intelStatus.textContent = intel.status === "success" ? "Verified" : intel.status;
    } else {
      domainIntelBox.style.display = "none";
    }

    // 5. Detected Red Flags
    renderFlagsList(data.flags || []);

    // 6. Update Recent Scans Feed
    prependRecentScan(data);
  }

  function animateDonutScore(targetScore) {
    const circumference = 251.2;
    const targetOffset = circumference - (circumference * targetScore) / 100;
    donutMeter.style.strokeDashoffset = targetOffset;

    // Numerical counter animation
    let currentScore = 0;
    const duration = 800; // ms
    const stepTime = 16;
    const steps = duration / stepTime;
    const increment = targetScore / steps;

    const counter = setInterval(() => {
      currentScore += increment;
      if (currentScore >= targetScore) {
        scoreNum.textContent = `${targetScore}%`;
        clearInterval(counter);
      } else {
        scoreNum.textContent = `${Math.round(currentScore)}%`;
      }
    }, stepTime);
  }

  function renderFlagsList(flags) {
    flagsContainer.innerHTML = "";

    if (!flags || flags.length === 0) {
      flagsContainer.innerHTML = `
        <div class="flag-item">
          <div class="flag-bullet bullet-green"></div>
          <div class="flag-body">
            <div class="flag-title">No Major Red Flags Detected</div>
            <div class="flag-quote">Standard phishing keywords and payment traps were not detected.</div>
          </div>
          <div class="flag-badge badge-safe">Safe</div>
        </div>
      `;
      return;
    }

    flags.forEach(flag => {
      const severity = (flag.severity || "medium").toLowerCase();
      let bulletClass = "bullet-orange";
      let badgeClass = "badge-medium";

      if (severity === "critical" || severity === "high") {
        bulletClass = "bullet-red";
        badgeClass = "badge-high";
      } else if (severity === "low") {
        bulletClass = "bullet-green";
        badgeClass = "badge-safe";
      }

      const item = document.createElement("div");
      item.className = "flag-item";
      item.innerHTML = `
        <div class="flag-bullet ${bulletClass}"></div>
        <div class="flag-body">
          <div class="flag-title">${escapeHtml(flag.title || "Suspicious Signal")}</div>
          <div class="flag-quote">"${escapeHtml(flag.evidence || flag.explanation || "Identified pattern")}"</div>
        </div>
        <div class="flag-badge ${badgeClass}">${capitalize(severity)}</div>
      `;
      flagsContainer.appendChild(item);
    });
  }

  // ==========================================
  // Recent Scans (Session-Isolated Storage)
  // Wiped when website is closed or restarted
  // ==========================================
  const STORAGE_KEY = "trueoffer_session_scans";

  // Purge any residual permanent localStorage from older builds
  try {
    localStorage.removeItem("trueoffer_recent_scans");
    localStorage.removeItem("trueoffer_session_scans");
  } catch (e) { }

  function getSavedScans() {
    try {
      const raw = sessionStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch (e) {
      return [];
    }
  }

  function saveScanToStorage(item) {
    try {
      const list = getSavedScans();
      list.unshift(item);
      if (list.length > 10) list.pop();
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(list));
    } catch (e) {
      console.warn("Could not save to sessionStorage", e);
    }
  }

  function createScanEntryElement(item) {
    const score = item.threat_score || 0;
    let chipClass = "chip-green";
    let badgeClass = "badge-safe";
    let badgeLabel = "Safe";

    if (score >= 70) {
      chipClass = "chip-red";
      badgeClass = "badge-high";
      badgeLabel = "High";
    } else if (score >= 35) {
      chipClass = "chip-orange";
      badgeClass = "badge-medium";
      badgeLabel = "Medium";
    }

    const entry = document.createElement("div");
    entry.className = "scan-entry";
    entry.innerHTML = `
      <div class="scan-score-chip ${chipClass}">${score}%</div>
      <div class="scan-info">
        <strong>${escapeHtml(item.title || "Custom Offer Inspection")}</strong>
        <small>${escapeHtml(item.timestamp || "Just now")} &bull; ${capitalize(item.scan_type || "Text")}</small>
      </div>
      <span class="scan-badge ${badgeClass}">${badgeLabel}</span>
    `;
    return entry;
  }

  function loadRecentScans() {
    const saved = getSavedScans();
    if (!saved || saved.length === 0) {
      scansFeed.innerHTML = `
        <div class="scans-empty" id="scansEmpty">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#8CAAB9" stroke-width="1.8">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="8" x2="12" y2="12"></line>
            <line x1="12" y1="16" x2="12.01" y2="16"></line>
          </svg>
          <span>No recent scans yet.<br><small>Your analyzed offers and URLs will appear here.</small></span>
        </div>
      `;
      return;
    }

    scansFeed.innerHTML = "";
    saved.slice(0, 5).forEach(item => {
      scansFeed.appendChild(createScanEntryElement(item));
    });
  }

  function prependRecentScan(data) {
    const score = data.threat_score || 0;
    const title = data.domain_intelligence && data.domain_intelligence.domain
      ? data.domain_intelligence.domain
      : "Custom Offer Inspection";

    const scanRecord = {
      threat_score: score,
      title: title,
      scan_type: data.scan_type || "Text",
      timestamp: "Just now",
      risk_level: data.risk_level || "LOW"
    };

    // Save to localStorage
    saveScanToStorage(scanRecord);

    // Remove empty placeholder if present
    const scansEmpty = document.getElementById("scansEmpty");
    if (scansEmpty) {
      scansEmpty.remove();
    }

    const entry = createScanEntryElement(scanRecord);
    scansFeed.insertBefore(entry, scansFeed.firstChild);

    // Keep max 5 visible in sidebar
    while (scansFeed.children.length > 5) {
      scansFeed.removeChild(scansFeed.lastChild);
    }
  }

  // Load any previously saved scans on initialization
  loadRecentScans();

  // Helpers
  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  function capitalize(str) {
    if (!str) return "";
    return str.charAt(0).toUpperCase() + str.slice(1);
  }
});
