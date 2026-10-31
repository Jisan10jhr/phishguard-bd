
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

     
const hostname = url.hostname;
const isIPv6Literal =
  hostname.startsWith("[") && hostname.endsWith("]");

if (
  (!hostname.includes(".") && !isIPv6Literal) ||
  hostname.startsWith(".") ||
  hostname.endsWith(".")
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

    // Store warnings as structured information.
    function addWarning(
      message,
      points,
      explanation = "This pattern may deserve attention, but it does not prove that a URL is malicious.",
      action = "Verify the destination independently before sharing personal or sensitive information."
    ) {
      warnings.push({
        message: message,
        points: points,
        explanation: explanation,
        action: action
      });

      score += points;
    }


   // 1. HTTP instead of HTTPS.
if (url.protocol !== "https:") {
  addWarning(
    "Uses HTTP rather than HTTPS. The connection may not be encrypted.",
    15,
    "HTTPS helps protect data exchanged between your browser and a website through encryption. An HTTP connection does not provide this protection, so information may be exposed or modified in transit.",
    "Avoid entering passwords, payment details, or personal information on HTTP pages. If the organization offers an official HTTPS website, use that address instead."
  );
}

    // 2. Credentials embedded before the hostname.
if (url.username || url.password) {
  addWarning(
    "Contains user information before the hostname. This can disguise the destination; inspect the actual hostname carefully.",
    25,
    "URLs can contain user information before the @ symbol, while the actual hostname appears after it. Attackers may exploit this format to make a link look as though it belongs to a familiar website when it leads somewhere else.",
    "Identify the actual hostname after the @ symbol. Do not trust familiar-looking words before it. If the destination is unfamiliar, avoid the link and visit the organization's official website directly."
  );
}

   
   // 3. IPv4 and IPv6 hostname detection.

const isIPv4 =
  /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) &&
  hostname.split(".").every(
    part => Number(part) >= 0 && Number(part) <= 255
  );

// URL.hostname returns IPv6 addresses inside square brackets.
// The URL parser validates the IPv6 address syntax.
const isIPv6 = hostname.startsWith("[") && hostname.endsWith("]");

if (isIPv4 || isIPv6) {
  addWarning(
    `Uses an ${isIPv4 ? "IPv4" : "IPv6"} address instead of a conventional domain name. Verify the destination carefully.`,
    20,
    "Websites normally use domain names that help visitors recognize their destinations. An IP address in a URL is not automatically malicious, but it can make the website's operator and identity less obvious.",
    "Verify the IP address through an independent, trusted source before visiting or entering information. Avoid assuming that an IP-based URL belongs to a familiar organization."
  );
}


    // 4. Encoded hostname labels.
if (parts.some(part => part.startsWith("xn--"))) {
  addWarning(
    "Contains an encoded domain label. Check for lookalike characters.",
    20,
    "Internationalized domain names can use Punycode labels beginning with xn-- to represent non-English characters. Some attackers may use visually similar characters from different writing systems to imitate familiar domain names.",
    "Check the domain carefully in your browser's address bar. If it claims to belong to a familiar organization, visit that organization's official website directly instead of following the unfamiliar link."
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
    5,
    "Hyphens are common in legitimate websites. However, deceptive domains may use hyphens to imitate familiar brands or make misleading names.",
    "Check the complete domain carefully, including its spelling and the domain ending, before entering personal information."
  );
}

   // 7. Unusually long URL.
if (raw.length > 100) {
  addWarning(
    "The URL is unusually long. Inspect the destination and parameters carefully.",
    5,
    "Long URLs can contain many parameters, redirects, or encoded information. Some legitimate websites also use long URLs, but excessive length can make it harder to recognize the actual destination and notice suspicious details.",
    "Check the hostname carefully and look for unexpected redirects or unfamiliar parameters. If the link claims to belong to a familiar organization, visit its official website directly."
  );
}

   // 8. Detect @ in the URL authority section.
const hasAtInAuthority = url.host !== url.hostname;

if (hasAtInAuthority) {
  addWarning(
    "Contains user information before the hostname. Inspect the actual destination carefully.",
    25,
    "An @ symbol in the URL authority section can separate user information from the actual hostname. Deceptive links may place familiar-looking text before @ to disguise the real destination.",
    "Identify the actual hostname shown after the @ symbol. Do not trust familiar-looking text before it. If the destination is unfamiliar, visit the organization's official website directly."
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
    10,
    "Words such as secure, login, verify, and account can appear on legitimate websites. However, scammers may use them to make deceptive links look trustworthy or encourage users to sign in.",
    "Do not sign in through an unfamiliar link. Visit the organization's official website directly and check whether the domain is genuine."
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
    label === brand || label.split("-").includes(brand)
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
    20,
    "Scammers may include a well-known company or brand name in an unrelated domain to make a deceptive website appear trustworthy. A brand name alone does not establish who owns or operates the website.",
    "Do not use the link to sign in or make payments. Visit the brand's official website by typing its known address yourself, and compare the exact domain."
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
    "Uses a URL shortening service. Shortened links hide their final destination. Check the destination before visiting.",
    15,
    "URL shortening services redirect visitors to another address. Although many are legitimate, the shortened URL does not reveal the final destination, making it harder to recognize an unfamiliar or deceptive website.",
    "If you don't recognize the sender, avoid opening the shortened link. Verify the destination using a reputable link-expansion service or visit the organization's official website directly."
  );
}


    // 12. Encoded characters in the URL path or query.
if (/%[0-9a-f]{2}/i.test(fullURL)) {
  addWarning(
    "Contains percent-encoded characters. This is common on legitimate websites too, but inspect unfamiliar links carefully.",
    5,
    "Percent-encoding represents certain characters using a percent sign followed by two hexadecimal digits, such as %20 for a space. It is widely used by legitimate websites, but unfamiliar or heavily encoded URLs can make parts of a link harder to read.",
    "Check the hostname and the surrounding URL carefully. Do not assume encoded characters indicate phishing. If the link is unfamiliar or unexpected, visit the organization's official website directly."
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
