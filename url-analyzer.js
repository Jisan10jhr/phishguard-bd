
/*
 * PhishGuard BD
 * URL Analysis Engine
 *
 * Educational heuristic analysis.
 * Scores are illustrative, not probabilities.
 * No live reputation, redirect, or website-content checks.
 */

function analyzeURL(rawInput) {
  const raw = String(rawInput || "").trim();

  if (!raw) {
    return {
      valid: false,
      error: "Please enter a URL to analyze."
    };
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

    if (!url.hostname || /[%\s]/.test(url.hostname)) {
  throw new Error("Invalid hostname");
}
  } catch {
    return {
      valid: false,
      error: "Invalid URL format. Enter a web address such as https://example.com."
    };
  }

  const warnings = [];
  let score = 0;

  const hostname = url.hostname.toLowerCase();
  const parts = hostname.split(".");
  const fullURL =
    `${url.hostname}${url.pathname}${url.search}`.toLowerCase();

  function addWarning(
    message,
    points,
    explanation = "This pattern may deserve attention, but it does not prove that a URL is malicious.",
    action = "Verify the destination independently before sharing personal or sensitive information."
  ) {
    warnings.push({
      message,
      points,
      explanation,
      action
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

  const isIPv6 =
    hostname.startsWith("[") && hostname.endsWith("]");

  if (isIPv4 || isIPv6) {
    addWarning(
      `Uses an ${isIPv4 ? "IPv4" : "IPv6"} address instead of a conventional domain name. Verify the destination carefully.`,
      20,
      "Websites normally use domain names that help visitors recognize their destinations. An IP address in a URL is not automatically malicious, but it can make the website's operator and identity less obvious.",
      "Verify the IP address through an independent, trusted source before visiting or entering information. Avoid assuming that an IP-based URL belongs to a familiar organization."
    );
  }

  // 4. Punycode hostname labels.
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

  // 6. Hyphens in hostname.
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

  // 8. Suspicious terms in the hostname.
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

  // 9. Brand-name clues.
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

  // 10. URL shortener detection.
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

  // 11. Percent-encoded characters.
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

  return {
    valid: true,
    hostname,
    warnings,
    score,
    riskLevel
  };
}
