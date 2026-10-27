
/*
 * PhishGuard BD
 * Educational URL analysis tool
 *
 * Scores are heuristic warning points, not probabilities.
 * This tool cannot determine whether a website is safe.
 */

const form = document.getElementById("url-form");
const input = document.getElementById("url-input");
const results = document.getElementById("results");

form.addEventListener("submit", function (event) {
  event.preventDefault();

  const raw = input.value.trim();
  results.replaceChildren();

  const heading = document.createElement("h3");
  const summary = document.createElement("p");
  const scoreText = document.createElement("p");
  const list = document.createElement("ul");
  const note = document.createElement("p");

  results.append(heading, summary, scoreText, list, note);

  function showInvalid(message) {
    heading.textContent = "Invalid URL format";
    summary.textContent = message;
    scoreText.remove();
    list.remove();
    note.remove();
  }

  if (!raw) {
    showInvalid("Please enter a website URL to analyze.");
    return;
  }

  let url;

  try {
    const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw)
      ? raw
      : `https://${raw}`;

    url = new URL(candidate);

    if (!["http:", "https:"].includes(url.protocol)) {
      throw new Error("Unsupported protocol");
    }

    if (
      !url.hostname ||
      !url.hostname.includes(".") ||
      /\s/.test(url.hostname)
    ) {
      throw new Error("Invalid hostname");
    }
  } catch {
    showInvalid(
      "Enter a valid web address, such as https://example.com."
    );
    return;
  }

  const warnings = [];
  let score = 0;
  const hostname = url.hostname.toLowerCase();

  function addWarning(message, points) {
    warnings.push(message);
    score += points;
  }

  if (url.protocol !== "https:") {
    addWarning(
      "Uses HTTP instead of HTTPS. The connection may not be encrypted.",
      15
    );
  }

  if (url.username || url.password) {
    addWarning(
      "Contains embedded user information before the hostname. Check which host the URL actually targets.",
      25
    );
  }

  const ipv4Pattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const ipv4Parts = hostname.split(".").map(Number);
  const isIPv4 =
    ipv4Pattern.test(hostname) &&
    ipv4Parts.every(part => part >= 0 && part <= 255);

  if (isIPv4) {
    addWarning(
      "Uses an IPv4 address instead of a conventional domain name.",
      20
    );
  }

  if (hostname.split(".").some(part => part.startsWith("xn--"))) {
    addWarning(
      "Contains an encoded domain label. Check for lookalike characters.",
      20
    );
  }

  if (hostname.split(".").length >= 5) {
    addWarning(
      "Has several hostname levels. Check the actual domain carefully.",
      10
    );
  }

  if (hostname.includes("-")) {
    addWarning(
      "The hostname contains a hyphen. This is common on legitimate sites too, so context matters.",
      5
    );
  }

  // Keep the score within the range 0–100.
  score = Math.min(score, 100);

  let riskLevel;
  if (score >= 50) {
    riskLevel = "High";
  } else if (score >= 20) {
    riskLevel = "Medium";
  } else {
    riskLevel = "Low";
  }

  heading.textContent = "URL Analysis Results";
  scoreText.textContent =
    `Warning score: ${score}/100 | Heuristic level: ${riskLevel}`;

  if (warnings.length === 0) {
    summary.textContent =
      "No warning signs covered by this tool were detected. " +
      "This does not establish that the URL is safe.";
  } else {
    summary.textContent =
      `Detected ${warnings.length} potential warning sign(s):`;
  }

  warnings.forEach(function (warning) {
    const item = document.createElement("li");
    item.textContent = warning;
    list.appendChild(item);
  });

  note.textContent =
    "Limitations: This score is based only on simple URL patterns. " +
    "It is not a probability of maliciousness. False positives and " +
    "missed threats are possible. No live reputation, redirects, " +
    "or website-content checks are performed. Do not enter passwords " +
    "or personal information to test a link.";
});


  results.appendChild(note);
});
