=== Coozmoo Dashboard Connector ===
Contributors: nareshwaghela
Tags: dashboard, auto-login, rest-api, management, ssl
Requires at least: 5.8
Tested up to: 7.0
Stable tag: 1.5.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Connects your WordPress site to the Coozmoo central management dashboard with secure auto-login and REST API support.

== Description ==

Coozmoo Dashboard Connector links your WordPress site to the Coozmoo central management dashboard at coozmoo.webvault.me.

**Features:**
* Secure token-based auto-login for administrators and assigned users
* REST API endpoints for site status, authentication, and token retrieval
* SSL bypass support for HTTP-only environments
* Granular user access control
* Clean, modern admin interface using system fonts — no external requests

**REST API Endpoints:**
* `POST /wp-json/WP/v1/ping` — Returns site status (extended data requires token)
* `POST /wp-json/WP/v1/auth` — Validates an access token
* `GET  /wp-json/WP/v1/get-token` — Returns the stored token (requires Secret header)

== Installation ==

1. Upload the `coozmoo-dashboard-connector` folder to `/wp-content/plugins/`.
2. Activate the plugin through the **Plugins** screen in WordPress.
3. Go to **Settings → Coozmoo Connector** to find your access token.
4. Enter the token in your Coozmoo central dashboard.

== Changelog ==

= 1.5.0 =
* Removed Google Fonts — now uses system font stack (no external requests)
* Removed assets folder from plugin ZIP
* Fixed Plugin URI
* Moved /get-token secret validation to permission_callback
* Removed sensitive data (admin_email, plugins list) from public /ping endpoint
* Used rest_url() instead of hardcoded /wp-json/ path
* Moved inline CSS to wp_enqueue API via wp_add_inline_style
* Added phpcs:ignore comments for intentional nonce-free GET handler

= 1.4.0 =
* Complete UI redesign with sidebar navigation
* Added Access Users tab
* Token regeneration with confirmation
* hash_equals() for timing-safe token validation

= 1.3.0 =
* Added assigned users feature
* SSL bypass for HTTP-only environments
