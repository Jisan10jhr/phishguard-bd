
/*
 * PhishGuard BD
 * Educational URL analysis tool
 *
 * This is a rule-based educational checker.
 * It is not a malware scanner or live reputation service.
 */

const form = document.getElementById("url-form");
const input = document.getElementById("url-input");
const results = document.getElementById("results");

// Confirm that the required HTML elements exist.
if (!form || !input || !results) {
  console.error(
    "PhishGuard BD: Missing url-form, url-input, or results element. Check index.html."
  );
} else {
  form.addEventListener("submit", function (event) {
    event.preventDefault();

    const raw = input.value.trim();
    results.replaceChildren();

    if (!raw) {
      results.textContent = "Please enter a URL to analyze.";
      return;
    }

    let url;

    // Add HTTPS if the user did not enter a protocol.
    try {
      const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw)
        ? raw
        : `https://${raw}`;

      url = new URL(candidate);

      if (!["http:", "https:"].includes(url.protocol)) {
        throw new Error("Unsupported protocol");
      }

      if (
        !url.hostname.includes(".") ||
        url.hostname.startsWith(".") ||
        url.hostname.endsWith(".")
      ) {
        throw new Error("Invalid hostname");
      }
    } catch {
      results.textContent =
        "Invalid URL format. Enter a web address such as https://example.com.";
      return;
    }

    const warnings = [];
    let score = 0;
    const hostname = url.hostname.toLowerCase();
    const parts = hostname.split(".");

    // Record a warning and its illustrative points.
    function addWarning(message, points) {
      warnings.push(message);
      score += points;
    }

    // 1. HTTP instead of HTTPS.
    if (url.protocol !== "https:") {
      addWarning(
        "Uses HTTP rather than HTTPS. The connection may not be encrypted.",
        15
      );
    }

    // 2. Embedded username or password.
    if (url.username || url.password) {
      addWarning(
        "Contains embedded user information before the hostname. Verify the actual destination.",
        25
      );
    }

    // 3. IPv4 address as the hostname.
    const isIPv4 =
      /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) &&
      hostname.split(".").every(
        part => Number(part) >= 0 && Number(part) <= 255
      );

    if (isIPv4) {
      addWarning(
        "Uses an IPv4 address instead of a conventional domain name.",
        20
      );
    }

    // 4. Encoded hostname labels.
    if (parts.some(part => part.startsWith("xn--"))) {
      addWarning(
        "Contains an encoded domain label. Check carefully for lookalike characters.",
        20
      );
    }

    // 5. Multiple hostname levels.
    if (parts.length >= 5) {
      addWarning(
        "Has several hostname levels. Verify the actual registered domain.",
        10
      );
    }

    // 6. Hyphens can be worth checking, but are not proof of fraud.
    if (hostname.includes("-")) {
      addWarning(
        "The hostname contains a hyphen. This is not malicious by itself.",
        5
      );
    }

    // 7. Unusually long URL.
    if (raw.length > 100) {
      addWarning(
        "The URL is unusually long. Long URLs are not necessarily malicious, so inspect the destination carefully.",
        5
      );
    }

    // Limit the illustrative score to 100.
    score = Math.min(score, 100);

    const riskLevel =
      score >= 50 ? "High" :
      score >= 20 ? "Medium" :
      "Low";

    // Build results using safe DOM methods.
    const heading = document.createElement("h3");
    heading.textContent = "URL Analysis Results";

    // Color-coded risk badge.
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

    // Display the score separately.
    const scoreText = document.createElement("p");
    scoreText.textContent = `Warning score: ${score}/100`;

    // Summarize the analysis.
    const summary = document.createElement("p");

    if (warnings.length === 0) {
      summary.textContent =
        "No warning signs covered by this tool were detected. This does not mean the URL is safe.";
    } else {
      summary.textContent =
        `Detected ${warnings.length} potential warning sign(s):`;
    }

    // List each detected warning.
    const list = document.createElement("ul");

    warnings.forEach(function (warning) {
      const item = document.createElement("li");
      item.textContent = warning;
      list.appendChild(item);
    });

    // Practical advice based on the heuristic level.
    const advice = document.createElement("p");
    advice.classList.add("result-advice");

    if (riskLevel === "High") {
      advice.textContent =
        "Safety advice: Several warning signs were detected. Avoid opening this link until you independently verify its destination.";
    } else if (riskLevel === "Medium") {
      advice.textContent =
        "Safety advice: Review the warning signs carefully. Verify the domain through an official source before entering information.";
    } else {
      advice.textContent =
        "Safety advice: Few warning signs were detected by this tool, but that does not mean the website is trustworthy. Verify the sender and destination.";
    }

    // Explain the limitations.
    const note = document.createElement("p");
    note.classList.add("result-limitations");
    note.textContent =
      "Limitations: This rule-based score is not a probability that a URL is malicious. Checks can produce false positives and miss threats. No live reputation, redirect, or website-content checks are performed.";

    // Privacy reminder.
    const privacyTip = document.createElement("p");
    privacyTip.textContent =
      "Privacy tip: Never enter passwords or other personal information into a link to test it.";

    // Display all results in the correct order.
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
