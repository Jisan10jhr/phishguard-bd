
/*
 * PhishGuard BD
 * Educational URL analysis tool
 *
 * This tool uses simple rules to identify potential warning signs.
 * Scores are illustrative, not probabilities of maliciousness.
 * It does not perform live reputation or website-content checks.
 */

const form = document.getElementById("url-form");
const input = document.getElementById("url-input");
const results = document.getElementById("results");
// ========================================
// URL Analysis History
// ========================================

const historyList = document.getElementById("history-list");
const clearHistoryButton = document.getElementById("clear-history");

const HISTORY_KEY = "phishguard-history";
const HISTORY_LIMIT = 20;

// Load saved history from this browser.
function getHistory() {
  try {
    const saved = localStorage.getItem(HISTORY_KEY);
    const history = saved ? JSON.parse(saved) : [];

    return Array.isArray(history) ? history : [];
  } catch (error) {
    console.error("Could not load analysis history:", error);
    return [];
  }
}

// Display saved history.
function renderHistory() {
  if (!historyList) return;

  historyList.replaceChildren();

  const history = getHistory();

  if (history.length === 0) {
    const emptyMessage = document.createElement("p");
    emptyMessage.classList.add("history-empty");
    emptyMessage.textContent = "No analysis history yet.";
    historyList.appendChild(emptyMessage);
    return;
  }

  history.forEach(function (entry) {
    const item = document.createElement("article");
    item.classList.add("history-item");

    const urlText = document.createElement("p");
    urlText.textContent = entry.url;

    const levelText = document.createElement("p");
    levelText.textContent =
      `Risk level: ${entry.riskLevel} | Score: ${entry.score}/100`;

    const dateText = document.createElement("p");
    dateText.textContent = new Date(entry.date).toLocaleString();

    item.append(urlText, levelText, dateText);
    historyList.appendChild(item);
  });
}

// Save a successful URL analysis.
function saveHistory(raw, analysis) {
  try {
    const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw)
      ? raw
      : `https://${raw}`;

    const parsedURL = new URL(candidate);

    // Exclude query parameters and fragments for privacy.
    const savedURL = parsedURL.origin + parsedURL.pathname;

    const history = getHistory();

    history.unshift({
      url: savedURL,
      riskLevel: analysis.riskLevel,
      score: analysis.score,
      date: new Date().toISOString()
    });

    localStorage.setItem(
      HISTORY_KEY,
      JSON.stringify(history.slice(0, HISTORY_LIMIT))
    );

    renderHistory();
  } catch (error) {
    console.error("Could not save analysis history:", error);
  }
}

// Clear saved history.
if (clearHistoryButton) {
  clearHistoryButton.addEventListener("click", function () {
    try {
      localStorage.removeItem(HISTORY_KEY);
      renderHistory();
    } catch (error) {
      console.error("Could not clear analysis history:", error);
    }
  });
}

// Display history when the page opens.
renderHistory();
if (!form || !input || !results) {
  console.error(
    "PhishGuard BD: Missing url-form, url-input, or results element. Check index.html."
  );
} else {
  form.addEventListener("submit", function (event) {
    event.preventDefault();

    
const raw = input.value.trim();
results.replaceChildren();

const analysis = analyzeURL(raw);

if (!analysis.valid) {
  results.textContent = analysis.error;
  return;
}
saveHistory(raw, analysis);
const warnings = analysis.warnings;
const score = analysis.score;
const riskLevel = analysis.riskLevel;


    // Results heading.
    const heading = document.createElement("h3");
    heading.textContent = "URL Analysis Results";

    // Colored risk badge.
    const riskBadge = document.createElement("span");
    riskBadge.classList.add("risk-badge");

    if (riskLevel === "High") {
      riskBadge.classList.add("risk-high");
    } else if (riskLevel === "Medium") {
      riskBadge.classList.add("risk-medium");
    } else {
      riskBadge.classList.add("risk-low");
    }

    riskBadge.textContent = `Heuristic level: ${riskLevel}`;

    // Score display.
    const scoreText = document.createElement("p");
    scoreText.textContent = `Warning score: ${score}/100`;

    // Warning summary.
    const summary = document.createElement("p");

    if (warnings.length === 0) {
      summary.textContent =
        "No warning signs covered by this tool were detected. This does not mean the URL is safe.";
    } else {
      summary.textContent =
        `Detected ${warnings.length} potential warning sign(s):`;
    }

  // Detailed warning report.
const list = document.createElement("ul");

warnings.forEach(function (warning) {
  const item = document.createElement("li");

  const message = document.createElement("strong");
  message.textContent = warning.message;

  const points = document.createElement("p");
  points.textContent = `Illustrative points: ${warning.points}`;

  const explanation = document.createElement("p");
  explanation.textContent = `Why it matters: ${warning.explanation}`;

  const action = document.createElement("p");
  action.textContent = `Recommended action: ${warning.action}`;

  item.append(message, points, explanation, action);
  list.appendChild(item);
});

    // Practical advice.
    const advice = document.createElement("p");
    advice.classList.add("result-advice");

    if (riskLevel === "High") {
      advice.textContent =
        "Safety advice: Multiple warning signs were detected. Do not enter passwords or payment information. Verify the destination using an independently obtained official website or contact method.";
    } else if (riskLevel === "Medium") {
      advice.textContent =
        "Safety advice: Review the warning signs carefully. Verify the domain through an official source before entering information.";
    } else {
      advice.textContent =
        "Safety advice: Few warning signs were detected by this tool, but the website may still be malicious. Verify the sender and destination independently.";
    }

    // Limitations.
    const note = document.createElement("p");
    note.classList.add("result-limitations");
    note.textContent =
      "Limitations: This rule-based score is not a probability that a URL is malicious. Legitimate URLs may trigger warnings, and malicious URLs may go undetected. No live reputation, redirect, or website-content checks are performed.";

    // Privacy reminder.
    const privacyTip = document.createElement("p");
    privacyTip.textContent =
      "Privacy tip: Never enter passwords or other personal information into a link to test it.";

    results.append(
      heading,
      riskBadge,
      scoreText,
      summary,
      list,
      advice,
      note,
      privacyTip
    );
  });
}

// ========================================
// Mobile Navigation Menu
// ========================================

const menuToggle = document.querySelector(".menu-toggle");
const navLinks = document.querySelector(".nav-links");

if (menuToggle && navLinks) {
  menuToggle.addEventListener("click", function () {
    const isOpen = navLinks.classList.toggle("is-open");

    menuToggle.setAttribute("aria-expanded", isOpen);
    menuToggle.setAttribute(
      "aria-label",
      isOpen ? "Close navigation" : "Open navigation"
    );

    menuToggle.textContent = isOpen ? "✕" : "☰";
  });

  // Close the menu after selecting a navigation link.
  navLinks.querySelectorAll("a").forEach(function (link) {
    link.addEventListener("click", function () {
      navLinks.classList.remove("is-open");
      menuToggle.setAttribute("aria-expanded", "false");
      menuToggle.setAttribute("aria-label", "Open navigation");
      menuToggle.textContent = "☰";
    });
  });
}
