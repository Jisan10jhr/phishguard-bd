
/*
 * PhishGuard BD
 * Educational URL analysis tool
 *
 * Important:
 * This is a rule-based educational checker, not a
 * malware scanner or a live website reputation service.
 */

const form = document.getElementById("url-form");
const input = document.getElementById("url-input");
const results = document.getElementById("results");

// Check that the required HTML elements exist.
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

    // Add HTTPS when the user omits the protocol.
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

    // Add a warning and its illustrative score.
    function addWarning(message, points) {
      warnings.push(message);
      score += points;
    }

    // 1. Check the connection protocol.
    if (url.protocol !== "https:") {
      addWarning(
        "The URL uses HTTP instead of HTTPS. The connection may not be encrypted.",
        15
      );
    }

    // 2. Check for credentials embedded in the URL.
    if (url.username || url.password) {
      addWarning(
        "The URL contains embedded user information before the hostname. Verify the actual destination.",
        25
      );
    }

    // 3. Check for an IPv4 address used as the hostname.
    const isIPv4 =
      /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) &&
      hostname.split(".").every(
        part => Number(part) >= 0 && Number(part) <= 255
      );

    if (isIPv4) {
      addWarning(
        "The hostname is an IPv4 address rather than a conventional domain name.",
        20
      );
    }

    // 4. Check for encoded domain labels.
    if (parts.some(part => part.startsWith("xn--"))) {
      addWarning(
        "The domain contains an encoded hostname label. Check carefully for lookalike characters.",
        20
      );
    }

    // 5. Check for many subdomain levels.
    if (parts.length >= 5) {
      addWarning(
        "The hostname has several subdomain levels. Verify the actual registered domain.",
        10
      );
    }

    // 6. A hyphen is only a contextual warning sign.
    if (hostname.includes("-")) {
      addWarning(
        "The hostname contains a hyphen. This is not malicious by itself.",
        5
      );
    }

    // 7. Check for unusually long URLs.
    if (raw.length > 100) {
      addWarning(
        "The URL is unusually long. Long URLs are not necessarily malicious, so inspect the destination carefully.",
        5
      );
    }

    // Keep the illustrative score between 0 and 100.
    score = Math.min(score, 100);

    const riskLevel =
      score >= 50 ? "High" :
      score >= 20 ? "Medium" :
      "Low";

    // Build the result safely using textContent.
    const heading = document.createElement("h3");
    heading.textContent = "URL Analysis Results";

    const scoreText = document.createElement("p");
    scoreText.textContent =
      `Warning score: ${score}/100 | Heuristic level: ${riskLevel}`;

    const summary = document.createElement("p");

    if (warnings.length === 0) {
      summary.textContent =
        "No warning signs covered by this tool were detected. This does not mean the URL is safe.";
    } else {
      summary.textContent =
        `Found ${warnings.length} potential warning sign(s):`;
    }

    const list = document.createElement("ul");

    warnings.forEach(function (warning) {
      const item = document.createElement("li");
      item.textContent = warning;
      list.appendChild(item);
    });

    const note = document.createElement("p");
    note.textContent =
      "Limitations: This rule-based score is not a probability that a URL is malicious. " +
      "These checks can produce false positives and miss threats. " +
      "No live reputation, redirect, or website-content checks are performed.";

    const privacyTip = document.createElement("p");
    privacyTip.textContent =
      "Privacy tip: Never enter passwords or other personal information into a link to test it.";

    results.append(
      heading,
      scoreText,
      summary,
      list,
      note,
      privacyTip
    );
  });
}

