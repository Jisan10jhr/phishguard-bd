
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
    const fullURL = `${url.hostname}${url.pathname}${url.search}`.toLowerCase();

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

    // 2. Credentials embedded before the hostname.
    if (url.username || url.password) {
      addWarning(
        "Contains user information before the hostname. This can disguise the destination; inspect the actual hostname carefully.",
        25
      );
    }

    // 3. IPv4 hostname.
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
        "Contains an encoded domain label. Check for lookalike characters.",
        20
      );
    }

    // 5. Many hostname levels.
    if (parts.length >= 5) {
      addWarning(
        "Has several hostname levels. Verify the actual registered domain.",
        10
      );
    }

    // 6. Hyphens are contextual clues, not proof of maliciousness.
    if (hostname.includes("-")) {
      addWarning(
        "The hostname contains a hyphen. This is not malicious by itself.",
        5
      );
    }

    // 7. Unusually long URL.
    if (raw.length > 100) {
      addWarning(
        "The URL is unusually long. Inspect the destination and parameters carefully.",
        5
      );
    }

    // 8. @ symbol in the raw URL can make the destination confusing.
    if (raw.includes("@")) {
      addWarning(
        "Contains an @ symbol. In a URL, text before @ may be interpreted as user information, while the hostname comes after it.",
        15
      );
    }

    // 9. Suspicious terms in the hostname.
    // These terms can occur on legitimate websites too.
    const suspiciousTerms = [
      "login",
      "verify",
      "secure",
      "account",
      "signin",
      "update",
      "password",
      "wallet"
    ];

    const matchedTerms = suspiciousTerms.filter(term =>
      hostname.split(/[.-]/).includes(term)
    );

    if (matchedTerms.length > 0) {
      addWarning(
        `The hostname contains login or account-related term(s): ${matchedTerms.join(", ")}. These words are not proof of phishing; verify the domain owner.`,
        10
      );
    }

   
    // 10. Brand-name clues and misleading subdomains.
    // This is a heuristic check, not proof of impersonation.

    const brandDomains = {
      paypal: ["paypal.com"],
      google: ["google.com"],
      microsoft: ["microsoft.com", "live.com"],
      apple: ["apple.com"],
      facebook: ["facebook.com"],
      instagram: ["instagram.com"],
      amazon: ["amazon.com"],
      netflix: ["netflix.com"],
      binance: ["binance.com"]
    };

    const hostnameLabels = hostname.split(".");
    const detectedBrands = [];

    for (const [brand, officialDomains] of Object.entries(brandDomains)) {
      const containsBrand = hostnameLabels.some(label =>
        label === brand || label.includes(brand)
      );

      if (!containsBrand) {
        continue;
      }

      const isKnownDomain = officialDomains.some(domain =>
        hostname === domain || hostname.endsWith(`.${domain}`)
      );

      if (!isKnownDomain) {
        detectedBrands.push(brand);
      }
    }

    if (detectedBrands.length > 0) {
      addWarning(
        `The hostname contains a familiar brand name (${detectedBrands.join(", ")}) but does not match the limited list of recognized official domains. It may be impersonating a brand. Verify the exact domain using the brand's official website.`,
        20
      );
    }

    // 11. URL shortener detection.
    // Shortened links hide their final destination.
    // This does not mean the link is malicious.

    const shortenerDomains = [
      "bit.ly",
      "tinyurl.com",
      "t.co",
      "is.gd",
      "ow.ly",
      "buff.ly",
      "rebrand.ly",
      "shorturl.at",
      "cutt.ly",
      "rb.gy"
    ];

    const isShortenedURL = shortenerDomains.some(domain =>
      hostname === domain || hostname.endsWith(`.${domain}`)
    );

    if (isShortenedURL) {
      addWarning(
        "Uses a URL shortening service. Shortened links hide their final destination. Check the destination through a trusted link-expansion service or an independently obtained official website before visiting.",
        15
      );
    }


    // 12. Encoded characters in the URL path or query.
    if (/%[0-9a-f]{2}/i.test(fullURL)) {
      addWarning(
        "Contains percent-encoded characters. This is common on legitimate websites too, but inspect unfamiliar links carefully.",
        5
      );
    }

    score = Math.min(score, 100);

    const riskLevel =
      score >= 50 ? "High" :
      score >= 20 ? "Medium" :
      "Low";

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

    // Warning list.
    const list = document.createElement("ul");

    warnings.forEach(function (warning) {
      const item = document.createElement("li");
      item.textContent = warning;
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
