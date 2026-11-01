# PhishGuard BD 🛡️

**An educational cybersecurity project for analyzing suspicious URL patterns and promoting phishing awareness.**

🌐 **Live Demo:** https://jisan10jhr.github.io/phishguard-bd/

## About the Project

PhishGuard BD is a web-based educational tool designed to help users recognize common warning signs in suspicious URLs and develop safer online habits.

It uses rule-based URL analysis to identify potentially suspicious patterns and provides educational resources about phishing, link safety, account security, and safe browsing.

**Important:** PhishGuard BD is an educational tool, not a definitive security scanner. Its results do not guarantee that a URL is safe or malicious.

## Features

- **URL Analysis:** Examines submitted URLs for common suspicious patterns.
- **Risk Assessment:** Displays Low, Medium, or High risk levels with a score from 0 to 100.
- **Warning Indicators:** Explains detected URL warning signs.
- **Analysis History:** Saves up to 20 recent analyses in the user's browser.
- **Automated Tests:** Includes a test page for checking URL analyzer behavior.
- **Cybersecurity Learning:** Provides educational pages covering:
  - Recognizing phishing
  - Checking suspicious links
  - Protecting online accounts
  - Staying safe online

## Risk Levels

| Risk Level | Score |
|---|---:|
| Low | 0–19 |
| Medium | 20–49 |
| High | 50–100 |

These scores are illustrative heuristic results, not probabilities of malicious activity.

## Technologies Used

- HTML5
- CSS3
- JavaScript
- Browser Local Storage
- GitHub Pages

## Project Pages

- [Homepage and URL Scanner](https://jisan10jhr.github.io/phishguard-bd/)
- [About PhishGuard BD](https://jisan10jhr.github.io/phishguard-bd/about.html)
- [Phishing Awareness](https://jisan10jhr.github.io/phishguard-bd/phishing.html)
- [Suspicious Link Safety](https://jisan10jhr.github.io/phishguard-bd/link-safety.html)
- [Account Security](https://jisan10jhr.github.io/phishguard-bd/account-security.html)
- [Online Safety](https://jisan10jhr.github.io/phishguard-bd/online-safety.html)
- [Automated Tests](https://jisan10jhr.github.io/phishguard-bd/tests.html)

## Testing

The URL analyzer has an automated test suite covering 16 scenarios, including:

- Normal HTTPS URLs
- HTTP URLs
- URL shorteners
- IPv4 and IPv6 addresses
- Punycode domains
- Encoded URLs
- Credentials in URLs
- Malformed hostnames
- Suspicious hostname keywords
- Brand impersonation patterns
- Multiple warning signs

**Last recorded result: 16/16 tests passed.**

## Limitations

PhishGuard BD currently uses URL pattern analysis. It does not:

- Check live domain reputation or threat-intelligence databases.
- Verify website ownership or legitimacy.
- Follow redirects to inspect the final destination.
- Analyze website content or downloaded files.
- Guarantee protection against phishing or malware.

A low-risk result does not mean a website is guaranteed to be safe. Always use caution when opening unfamiliar links.

## Future Improvements

- Expand URL analysis rules and edge-case testing.
- Improve detection of deceptive domains and URL structures.
- Explore trusted threat-intelligence integrations.
- Improve accessibility and mobile usability.
- Add more cybersecurity learning resources.

## Author

**MD JISAN HOSSAN RIMON**

Created as an educational cybersecurity project to promote safer digital practices.

---

*PhishGuard BD — Learn to recognize suspicious links. Think before you click.*
