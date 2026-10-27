
/*
 * PhishGuard BD
 * Educational URL analysis tool
 *
 * Rule-based warnings are not a probability of maliciousness.
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

    if (!raw) {
      results.textContent = "Please enter a URL to analyze.";
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

      if (!url.hostname.includes(".")) {
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

    function addWarning(message, points) {
      warnings.push(message);
      score += points;
    }

    if (url.protocol !== "https:") {
      addWarning(
        "Uses HTTP rather than HTTPS. The connection may not be encrypted.",
        15
      );
    }

    if (url.username || url.password) {
      addWarning(
        "Contains embedded user information before the hostname. Verify the actual destination.",
        25
      );
    }

    const parts = hostname.split(".");
    const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) &&
      hostname.split(".").every(part => Number(part) >= 0 && Number(part) <= 255);

    if (ipv4) {
      addWarning(
        "Uses an IPv4 address instead of a conventional domain name.",
        20
      );
    }

    if (parts.some(part => part.startsWith("xn--"))) {
      addWarning(
        "Contains an encoded domain label. Check carefully for lookalike characters.",
        20
      );
    }

    if (parts.length >= 5) {
      addWarning(
        "Has several hostname levels. Check the actual domain carefully.",
        10
      );
    }

    if (hostname.includes("-")) {
      addWarning(
        "The hostname contains a hyphen. This is not malicious by itself.",
        5
      );
    }

    score = Math.min(score, 100);

    const level =
      score >= 50 ? "High" :
      score >= 20 ? "Medium" : "Low";

    const heading = document.createElement("h3");
    heading.textContent = "URL Analysis Results";

    const scoreText = document.createElement("p");
    scoreText.textContent =
      `Warning score: ${score}/100 | Heuristic level: ${level}`;

    const summary = document.createElement("p");
    summary.textContent = warnings.length
      ? `Detected ${warnings.length} potential warning sign(s):`
      : "No warning signs covered by this tool were detected. This does not establish that the URL is safe.";

    const list = document.createElement("ul");

    warnings.forEach(message => {
      const item = document.createElement("li");
      item.textContent = message;
      list.appendChild(item);
    });

    const note = document.createElement("p");
    note.textContent =
      "This rule-based score is not a probability of maliciousness. " +
      "Checks can produce false positives and miss threats. No live " +
      "reputation, redirect, or website-content checks are performed.";

    results.append(heading, scoreText, summary, list, note);
  });
}
