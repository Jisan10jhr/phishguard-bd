
/*
 * PhishGuard BD
 * Educational URL analysis tool
 *
 * This tool checks for common warning signs.
 * It does not determine whether a website is safe.
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
  const list = document.createElement("ul");

  results.append(heading, summary, list);

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
    heading.textContent = "Invalid URL format";
    summary.textContent =
      "Enter a valid web address, such as https://example.com.";
    return;
  }

  const warnings = [];
  const hostname = url.hostname.toLowerCase();

  if (url.protocol !== "https:") {
    warnings.push(
      "The URL uses HTTP instead of HTTPS. The connection may not be encrypted."
    );
  }

  if (url.username || url.password) {
    warnings.push(
      "The URL contains embedded user information. Check carefully which host it points to."
    );
  }

  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    warnings.push(
      "The hostname resembles an IPv4 address instead of a conventional domain name."
    );
  }

  if (hostname.split(".").some(part => part.startsWith("xn--"))) {
    warnings.push(
      "The domain contains an encoded hostname label. Inspect it carefully for lookalike characters."
    );
  }

  if (hostname.split(".").length >= 5) {
    warnings.push(
      "The hostname has several subdomain levels. Verify the actual registered domain."
    );
  }

  if (hostname.includes("-")) {
    warnings.push(
      "The hostname contains a hyphen. This is not malicious by itself, but deserves context."
    );
  }

  heading.textContent = "URL Analysis Results";

  if (warnings.length === 0) {
    summary.textContent =
      "No warning signs covered by this tool were detected. " +
      "This does not establish that the URL is safe.";
  } else {
    summary.textContent =
      `Found ${warnings.length} potential warning sign(s):`;
  }

  warnings.forEach(function (warning) {
    const item = document.createElement("li");
    item.textContent = warning;
    list.appendChild(item);
  });

  const note = document.createElement("p");
  note.textContent =
    "Limitations: These basic checks can produce false positives " +
    "and miss malicious URLs. No live reputation or website-content " +
    "checks are performed.";

  results.appendChild(note);
});
