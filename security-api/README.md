# SENTINEL SECURITY – External link reputation API

The Cloudflare Worker at `security-api/worker.js` checks submitted domains with the public PhishDestroy / DestroyList API. It requires no account, API key, or payment details.

## Free setup

1. Keep the existing Cloudflare Worker named `sentinel-link-check`.
2. Deploy the latest repository version of `security-api/worker.js` (Cloudflare Git integration should detect the commit and deploy automatically; otherwise trigger a deployment).
3. No VirusTotal secret is required.
4. Google Safe Browsing is optional. If you already have a suitable key, you may add it as the Worker Secret `GOOGLE_SAFE_BROWSING_API_KEY`; do not create a billing account or enter payment details just for this project.
5. Copy the Worker HTTPS address and paste it in SENTINEL SECURITY → Link.

## How it works

- PhishDestroy checks the submitted hostname against its public threat-intelligence service: `https://api.destroy.tools/v1/check?domain=`.
- Google Safe Browsing is queried only if `GOOGLE_SAFE_BROWSING_API_KEY` is configured.
- An unavailable provider is reported as unavailable, not as a clean result.
- The app does not automatically open the submitted URL.

## Privacy and limitations

The hostname is sent to PhishDestroy; the full URL is sent to Google only if its optional key is configured. Do not submit links containing password-reset tokens, session identifiers, or other secrets.

This is a reputation check, not a guarantee of safety. Newly created, private, targeted, or unreported phishing domains may not be detected. A low score or absence from a blocklist is not proof that a site is safe. Public free services may change availability, limits, or terms. The Worker should not be exposed as an unrestricted public scanning service without rate limiting or an authenticated access layer.
