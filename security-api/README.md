# SENTINEL SECURITY – External link reputation API

This repository includes an optional Cloudflare Worker proxy at `security-api/worker.js`.
The iOS app sends a URL to this endpoint only after the user taps **Verifica con i database esterni**.

## Free-tier setup (personal, non-commercial use)

To avoid enabling Google Cloud billing, you can use **VirusTotal Public API only** with the Cloudflare Workers Free plan.

1. Create a Cloudflare account and a Worker named `sentinel-link-check`.
2. Deploy `security-api/worker.js` as the Worker entry point.
3. In Worker settings, add one **Secret** environment variable:
   - `VIRUSTOTAL_API_KEY`
4. Obtain the key from your VirusTotal account's API key page. Do not purchase a plan.
5. Deploy the Worker and copy its HTTPS address (for example, `https://sentinel-link-check.<account>.workers.dev`).
6. Paste that address in SENTINEL SECURITY → Link. The Worker accepts POST requests at its root URL.

**Google Safe Browsing is optional.** The Worker supports it if a suitable key is available, but it is not needed for the free-only setup. Do not create a Google Cloud billing account or enter payment details just for this project.

VirusTotal's Public API has strict quotas and is restricted to permitted non-commercial use. Do not use it for a commercial service or distribute it as a public scanning service. Check the current provider terms and quotas before use. The Cloudflare Free plan also has usage limits; exceeding them may require reducing usage or choosing a different setup, not automatically upgrading.

Never put provider API keys in the iOS app, this repository, screenshots, or public configuration. If a key is exposed, revoke and rotate it.

## How it works

- VirusTotal receives the submitted URL for analysis and returns available analysis statistics.
- Google Safe Browsing is queried only if `GOOGLE_SAFE_BROWSING_API_KEY` is configured.
- The Worker returns each provider's status separately. A pending or unavailable result is not a clean result.
- The app does not automatically open the submitted URL.

## Privacy and limitations

When the user requests a check, the full URL is transmitted to this Worker and then to the configured providers. Query strings can contain session identifiers or personal tokens; do not submit such links. Provider policies may retain submitted URLs and analysis data. Review their terms before enabling the service.

This is reputation checking, not a guarantee. New, private, targeted or unreported phishing pages may not be detected. Results can be delayed, incomplete or produce false positives. The free/public API tiers have strict rate limits and usage restrictions. Do not use this endpoint as a public unrestricted service; configure Cloudflare rate limiting or an authenticated access layer before wider distribution.
