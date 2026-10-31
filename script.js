
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
