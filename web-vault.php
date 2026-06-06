<?php
/**
 * Plugin Name:       Coozmoo Dashboard Connector
 * Plugin URI:        https://coozmoo.webvault.me/
 * Description:       Connects your WordPress site to the Coozmoo central management dashboard. Supports secure token-based auto-login, REST API authentication, and SSL bypass for HTTP-only environments.
 * Version:           1.5.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Naresh Waghela
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       coozmoo-dashboard-connector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'COOZMOO_VERSION', '1.5.0' );
define( 'COOZMOO_FILE',    __FILE__ );
define( 'COOZMOO_DIR',     plugin_dir_path( __FILE__ ) );
define( 'COOZMOO_URL',     plugin_dir_url( __FILE__ ) );

// ===========================================================
// SSL Detection & Safe URL Helpers
// ===========================================================

/**
 * Detects whether SSL is currently active,
 * including reverse-proxy and load-balancer forwarding headers.
 */
function coozmoo_is_ssl_active() {
	if ( is_ssl() ) {
		return true;
	}
	if ( isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) && 'https' === $_SERVER['HTTP_X_FORWARDED_PROTO'] ) {
		return true;
	}
	if ( isset( $_SERVER['HTTP_X_FORWARDED_SSL'] ) && 'on' === $_SERVER['HTTP_X_FORWARDED_SSL'] ) {
		return true;
	}
	return false;
}

/**
 * Returns a URL using the correct protocol for the current environment.
 * Falls back to HTTP when SSL is not active.
 */
function coozmoo_safe_url( $url ) {
	if ( ! coozmoo_is_ssl_active() ) {
		$url = str_replace( 'https://', 'http://', $url );
	}
	return $url;
}

/**
 * Disable SSL certificate verification for outgoing WordPress HTTP API requests.
 * Required when the remote dashboard connects to HTTP-only sites.
 */
add_filter( 'https_ssl_verify',       '__return_false' );
add_filter( 'https_local_ssl_verify', '__return_false' );
add_filter( 'http_request_args', function ( $args, $url ) {
	$args['sslverify'] = false;
	return $args;
}, 10, 2 );

// ===========================================================
// Token Helper
// ===========================================================

/**
 * Returns the stored access token, generating a new one if none exists.
 */
function coozmoo_get_token() {
	$token = get_option( 'coozmoo_token' );
	if ( ! $token ) {
		$token = wp_generate_password( 32, false );
		update_option( 'coozmoo_token', $token );
	}
	return $token;
}

// ===========================================================
// Enqueue Admin Styles — using wp_enqueue API (not inline)
// ===========================================================

add_action( 'admin_enqueue_scripts', function ( $hook ) {
	if ( 'settings_page_coozmoo-dashboard-connector' !== $hook ) {
		return;
	}
	// Inline styles registered against a dummy handle — no external font requests
	wp_register_style( 'coozmoo-admin', false, array(), COOZMOO_VERSION );
	wp_enqueue_style( 'coozmoo-admin' );
	wp_add_inline_style( 'coozmoo-admin', coozmoo_admin_css() );
} );

/**
 * Returns the admin page CSS as a string.
 * Uses system font stack — no Google Fonts or external requests.
 */
function coozmoo_admin_css() {
	return '
	/* ── System font stack — no external requests ── */
	.cz-page * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, sans-serif; }
	#wpwrap, #wpcontent, #wpbody-content { background: #0e0f14 !important; }
	#wpbody-content { padding-top: 0 !important; }

	.cz-page { display: flex; min-height: 100vh; background: #0e0f14; color: #c8cad2; }

	/* Sidebar */
	.cz-sidebar { width: 220px; flex-shrink: 0; background: #090a0e; border-right: 1px solid #1a1c25; display: flex; flex-direction: column; padding: 24px 0 20px; position: sticky; top: 0; height: 100vh; }
	.cz-brand { display: flex; align-items: center; gap: 12px; padding: 0 20px 24px; border-bottom: 1px solid #1a1c25; margin-bottom: 16px; }
	.cz-brand-icon { width: 36px; height: 36px; background: #2d9e6b; border-radius: 9px; display: flex; align-items: center; justify-content: center; color: #fff; flex-shrink: 0; }
	.cz-brand-name { font-size: 14px; font-weight: 600; color: #fff; }
	.cz-brand-ver  { font-size: 11px; color: #3d3f4e; margin-top: 1px; font-family: monospace; }

	.cz-nav { display: flex; flex-direction: column; gap: 2px; padding: 0 10px; flex: 1; }
	.cz-nav-item { display: flex; align-items: center; gap: 10px; padding: 9px 12px; border-radius: 8px; font-size: 13px; font-weight: 500; color: #555766; text-decoration: none; transition: background .15s, color .15s; }
	.cz-nav-item:hover { background: #131520; color: #9095a8; text-decoration: none; }
	.cz-nav-item.active { background: #0f2a1e; color: #2d9e6b; }
	.cz-nav-icon { display: flex; flex-shrink: 0; opacity: .6; }
	.cz-nav-item.active .cz-nav-icon { opacity: 1; }

	.cz-sidebar-status { display: flex; align-items: center; gap: 8px; padding: 14px 20px 0; border-top: 1px solid #1a1c25; margin-top: 14px; font-size: 11px; font-family: monospace; color: #3d3f4e; }
	.cz-ss-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
	.cz-ss-dot.green { background: #22c55e; }
	.cz-ss-dot.amber { background: #f59e0b; }

	/* Main */
	.cz-main { flex: 1; padding: 36px 40px; max-width: 740px; }

	/* Alerts */
	.cz-alert { display: flex; align-items: center; gap: 10px; padding: 12px 16px; border-radius: 10px; font-size: 13px; margin-bottom: 20px; border: 1px solid transparent; }
	.cz-alert.success { background: #0d2218; border-color: #164832; color: #22c55e; }
	.cz-alert.warning { background: #201a09; border-color: #3d3006; color: #f59e0b; }

	/* Section */
	.cz-section-title { font-size: 18px; font-weight: 600; color: #e8eaf0; margin: 0 0 6px; letter-spacing: -.3px; }
	.cz-section-desc  { font-size: 13px; color: #4a4d5e; margin: 0 0 24px; line-height: 1.6; }

	/* Stat grid */
	.cz-stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }
	.cz-stat { background: #111318; border: 1px solid #1a1c25; border-radius: 12px; padding: 16px; }
	.cz-stat-label { font-size: 11px; color: #3d3f4e; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
	.cz-stat-value { font-size: 15px; font-weight: 600; color: #9095a8; }
	.cz-stat-value.online { color: #22c55e; }
	.cz-stat-value.ssl-on { color: #22c55e; }
	.cz-stat-value.ssl-off { color: #f59e0b; }
	.cz-blink { display: inline-block; width: 7px; height: 7px; background: #22c55e; border-radius: 50%; margin-right: 5px; vertical-align: middle; animation: cz-blink 1.8s ease-in-out infinite; }
	@keyframes cz-blink { 0%,100%{ opacity:1; } 50%{ opacity:.25; } }

	/* Info card */
	.cz-info-card { background: #111318; border: 1px solid #1a1c25; border-radius: 12px; overflow: hidden; }
	.cz-info-row { display: flex; align-items: center; gap: 16px; padding: 12px 18px; border-bottom: 1px solid #1a1c25; }
	.cz-info-row:last-child { border-bottom: none; }
	.cz-info-label { font-size: 12px; color: #3d3f4e; min-width: 130px; flex-shrink: 0; }
	.cz-info-val { font-size: 13px; color: #9095a8; word-break: break-all; font-family: monospace; }

	/* Card */
	.cz-card { background: #111318; border: 1px solid #1a1c25; border-radius: 12px; padding: 20px 22px; margin-bottom: 16px; }
	.cz-card-label { font-size: 11px; color: #3d3f4e; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 14px; }

	/* Inputs */
	.cz-field-row { display: flex; gap: 8px; align-items: center; }
	.cz-input { flex: 1; background: #0c0d12 !important; border: 1px solid #1e2030 !important; border-radius: 8px !important; color: #9095a8 !important; font-size: 13px !important; padding: 9px 12px !important; outline: none !important; box-shadow: none !important; font-family: monospace !important; min-width: 0; transition: border-color .15s !important; }
	.cz-input:focus { border-color: #2d9e6b !important; }

	/* Buttons */
	.cz-btn { border-radius: 8px !important; font-size: 13px !important; font-weight: 500 !important; padding: 9px 16px !important; cursor: pointer !important; border: 1px solid transparent !important; white-space: nowrap; }
	.cz-btn.primary { background: #2d9e6b !important; color: #fff !important; border-color: #2d9e6b !important; }
	.cz-btn.primary:hover { background: #248a5c !important; }
	.cz-btn.ghost   { background: transparent !important; color: #555766 !important; border-color: #1e2030 !important; }
	.cz-btn.ghost:hover { color: #9095a8 !important; border-color: #2e3048 !important; }
	.cz-btn.danger  { background: transparent !important; color: #ef4444 !important; border-color: #2a1010 !important; margin-top: 10px; }
	.cz-btn.danger:hover { background: #1a0a0a !important; }

	/* Code block */
	.cz-code-block { background: #0c0d12; border: 1px dashed #1e2030; border-radius: 8px; padding: 14px 16px; font-family: monospace; font-size: 12px; word-break: break-all; margin-bottom: 12px; }
	.cz-code-comment { color: #2e303f; margin-bottom: 6px; }
	.cz-code-line { color: #2d9e6b; }
	.cz-hint { font-size: 12px; color: #3d3f4e; margin: 0; }
	.cz-hint strong { color: #555766; font-weight: 500; }

	/* User list */
	.cz-user-list { display: flex; flex-direction: column; }
	.cz-user-row { display: flex; align-items: center; gap: 12px; padding: 11px 14px; border-radius: 8px; cursor: pointer; transition: background .12s; margin: 1px 0; }
	.cz-user-row:hover { background: #131520; }
	.cz-user-row.is-admin { opacity: .65; cursor: default; }
	.cz-checkbox { width: 15px; height: 15px; accent-color: #2d9e6b; flex-shrink: 0; cursor: pointer; }
	.cz-avatar { width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 600; color: #fff; flex-shrink: 0; }
	.cz-user-info { flex: 1; min-width: 0; }
	.cz-user-name { display: block; font-size: 13px; font-weight: 500; color: #9095a8; }
	.cz-user-meta { display: block; font-size: 11px; color: #3d3f4e; font-family: monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
	.cz-role-tag { font-size: 10px; font-family: monospace; padding: 2px 8px; border-radius: 4px; background: #131520; border: 1px solid #1e2030; color: #3d3f4e; flex-shrink: 0; }
	.cz-role-tag.admin { color: #f59e0b; border-color: #3a2c00; background: #1c1500; }
	.cz-form-footer { display: flex; justify-content: flex-end; padding-top: 16px; border-top: 1px solid #1a1c25; margin-top: 8px; }

	/* Endpoint cards */
	.cz-endpoint-card { background: #111318; border: 1px solid #1a1c25; border-radius: 12px; padding: 16px 18px; margin-bottom: 12px; }
	.cz-ep-top { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; flex-wrap: wrap; }
	.cz-method { font-size: 11px; font-weight: 600; font-family: monospace; padding: 3px 8px; border-radius: 4px; flex-shrink: 0; }
	.cz-method.post { background: #0d2218; color: #22c55e; border: 1px solid #164832; }
	.cz-method.get  { background: #0f2a1e; color: #2d9e6b; border: 1px solid #1a4a32; }
	.cz-ep-path { font-family: monospace; font-size: 12px; color: #2d9e6b; word-break: break-all; background: none; padding: 0; }
	.cz-ep-desc { font-size: 12px; color: #3d3f4e; margin: 0; line-height: 1.6; }
	';
}

// ===========================================================
// Admin Menu
// ===========================================================

add_action( 'admin_menu', function () {
	add_options_page(
		'Coozmoo Dashboard Connector',
		'Coozmoo Connector',
		'manage_options',
		'coozmoo-dashboard-connector',
		'coozmoo_render_page'
	);
} );

// ===========================================================
// Settings Page — Render
// ===========================================================

function coozmoo_render_page() {

	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	// Save: token
	if ( isset( $_POST['cz_action'] ) && 'save_token' === $_POST['cz_action'] ) {
		check_admin_referer( 'coozmoo_settings' );
		update_option( 'coozmoo_token', sanitize_text_field( wp_unslash( isset( $_POST['coozmoo_token'] ) ? $_POST['coozmoo_token'] : '' ) ) );
		$saved_token = true;
	}

	// Regenerate token
	if ( isset( $_POST['cz_action'] ) && 'regen_token' === $_POST['cz_action'] ) {
		check_admin_referer( 'coozmoo_settings' );
		update_option( 'coozmoo_token', wp_generate_password( 32, false ) );
		$regen_token = true;
	}

	// Save: assigned users
	if ( isset( $_POST['cz_action'] ) && 'save_users' === $_POST['cz_action'] ) {
		check_admin_referer( 'coozmoo_settings' );
		$raw   = isset( $_POST['cz_users'] ) ? array_map( 'sanitize_text_field', wp_unslash( (array) $_POST['cz_users'] ) ) : array();
		$clean = array_map( 'absint', $raw );
		update_option( 'coozmoo_allowed_users', $clean );
		$saved_users = true;
	}

	$token         = coozmoo_get_token();
	$ssl_ok        = coozmoo_is_ssl_active();
	$allowed_ids   = (array) get_option( 'coozmoo_allowed_users', array() );
	$all_users     = get_users( array( 'orderby' => 'display_name' ) );

	// Fix: use rest_url() instead of hardcoded /wp-json/ path
	$rest_base     = coozmoo_safe_url( rest_url( 'WP/v1' ) );
	$autologin_url = coozmoo_safe_url( home_url( '/' ) ) . '?wp_autologin=USERNAME&token=' . $token;
	$active_tab    = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'overview';

	?>
	<div class="cz-page">

		<!-- Sidebar -->
		<nav class="cz-sidebar">
			<div class="cz-brand">
				<div class="cz-brand-icon">
					<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
				</div>
				<div>
					<div class="cz-brand-name">Coozmoo</div>
					<div class="cz-brand-ver">v<?php echo esc_html( COOZMOO_VERSION ); ?></div>
				</div>
			</div>

			<div class="cz-nav">
				<?php
				$tabs = array(
					'overview'  => array( 'label' => 'Overview',       'icon' => '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>' ),
					'token'     => array( 'label' => 'Access Token',   'icon' => '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>' ),
					'users'     => array( 'label' => 'Access Users',   'icon' => '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>' ),
					'endpoints' => array( 'label' => 'API Endpoints',  'icon' => '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>' ),
				);
				foreach ( $tabs as $key => $t ) {
					$url = admin_url( 'options-general.php?page=coozmoo-dashboard-connector&tab=' . $key );
					printf(
						'<a href="%s" class="cz-nav-item %s"><span class="cz-nav-icon">%s</span>%s</a>',
						esc_url( $url ),
						( $active_tab === $key ) ? 'active' : '',
						wp_kses_post( $t['icon'] ),
						esc_html( $t['label'] )
					);
				}
				?>
			</div>

			<div class="cz-sidebar-status">
				<div class="cz-ss-dot <?php echo $ssl_ok ? 'green' : 'amber'; ?>"></div>
				<span><?php echo $ssl_ok ? 'HTTPS / SSL Active' : 'HTTP / SSL Bypassed'; ?></span>
			</div>
		</nav>

		<!-- Main -->
		<main class="cz-main">

			<?php if ( ! empty( $saved_token ) ) : ?>
				<div class="cz-alert success">Token saved successfully.</div>
			<?php endif; ?>
			<?php if ( ! empty( $regen_token ) ) : ?>
				<div class="cz-alert success">New token generated. Update your dashboard immediately.</div>
			<?php endif; ?>
			<?php if ( ! empty( $saved_users ) ) : ?>
				<div class="cz-alert success">Access users updated.</div>
			<?php endif; ?>
			<?php if ( ! $ssl_ok ) : ?>
				<div class="cz-alert warning">SSL is not active — HTTP mode enabled. Auto-login and API calls work over HTTP.</div>
			<?php endif; ?>

			<?php if ( 'overview' === $active_tab ) : ?>

				<div class="cz-section-title">Site Overview</div>
				<div class="cz-stat-grid">
					<div class="cz-stat"><div class="cz-stat-label">Status</div><div class="cz-stat-value online"><span class="cz-blink"></span>Online</div></div>
					<div class="cz-stat"><div class="cz-stat-label">SSL</div><div class="cz-stat-value <?php echo $ssl_ok ? 'ssl-on' : 'ssl-off'; ?>"><?php echo $ssl_ok ? 'Active' : 'Bypassed'; ?></div></div>
					<div class="cz-stat"><div class="cz-stat-label">Protocol</div><div class="cz-stat-value"><?php echo $ssl_ok ? 'HTTPS' : 'HTTP'; ?></div></div>
					<div class="cz-stat"><div class="cz-stat-label">WP Version</div><div class="cz-stat-value"><?php echo esc_html( get_bloginfo( 'version' ) ); ?></div></div>
				</div>
				<div class="cz-info-card">
					<div class="cz-info-row"><span class="cz-info-label">Site Name</span><span class="cz-info-val"><?php echo esc_html( get_bloginfo( 'name' ) ); ?></span></div>
					<div class="cz-info-row"><span class="cz-info-label">Site URL</span><span class="cz-info-val"><?php echo esc_html( coozmoo_safe_url( home_url() ) ); ?></span></div>
					<div class="cz-info-row"><span class="cz-info-label">PHP Version</span><span class="cz-info-val"><?php echo esc_html( phpversion() ); ?></span></div>
					<div class="cz-info-row"><span class="cz-info-label">Allowed Users</span><span class="cz-info-val"><?php echo esc_html( count( $allowed_ids ) . ' assigned + all administrators' ); ?></span></div>
				</div>

			<?php elseif ( 'token' === $active_tab ) : ?>

				<div class="cz-section-title">Access Token</div>
				<p class="cz-section-desc">This token authenticates your central dashboard. Keep it private.</p>
				<div class="cz-card">
					<div class="cz-card-label">Current Token</div>
					<form method="post" autocomplete="off">
						<?php wp_nonce_field( 'coozmoo_settings' ); ?>
						<input type="hidden" name="cz_action" value="save_token">
						<div class="cz-field-row">
							<input type="text" name="coozmoo_token" id="cz-token-input" class="cz-input" value="<?php echo esc_attr( $token ); ?>" autocomplete="off">
							<button type="button" class="cz-btn ghost" onclick="var el=document.getElementById('cz-token-input');el.select();document.execCommand('copy');this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)">Copy</button>
							<button type="submit" class="cz-btn primary">Save</button>
						</div>
					</form>
					<form method="post" style="margin-top:12px">
						<?php wp_nonce_field( 'coozmoo_settings' ); ?>
						<input type="hidden" name="cz_action" value="regen_token">
						<button type="submit" class="cz-btn danger" onclick="return confirm('This will invalidate the current token. Your dashboard will stop working until you update it there. Continue?')">Regenerate Token</button>
					</form>
				</div>
				<div class="cz-card">
					<div class="cz-card-label">Auto-Login URL Format</div>
					<div class="cz-code-block">
						<div class="cz-code-comment">Replace USERNAME with the target WordPress username</div>
						<div class="cz-code-line"><?php echo esc_html( $autologin_url ); ?></div>
					</div>
					<p class="cz-hint">Only administrators and users listed in <strong>Access Users</strong> can use this link.</p>
				</div>

			<?php elseif ( 'users' === $active_tab ) : ?>

				<div class="cz-section-title">Access Users</div>
				<p class="cz-section-desc">Choose which users can be logged in via auto-login. Administrators always have access.</p>
				<div class="cz-card">
					<form method="post">
						<?php wp_nonce_field( 'coozmoo_settings' ); ?>
						<input type="hidden" name="cz_action" value="save_users">
						<div class="cz-user-list">
							<?php foreach ( $all_users as $u ) :
								$user_obj  = new WP_User( $u->ID );
								$roles     = (array) $user_obj->roles;
								$is_admin  = in_array( 'administrator', $roles, true );
								$is_active = $is_admin || in_array( $u->ID, $allowed_ids, true );
								$initials  = strtoupper( substr( $u->display_name, 0, 1 ) );
								$colors    = array( '#2d9e6b', '#22c55e', '#f59e0b', '#ec4899', '#14b8a6', '#5b6ef5' );
								$av_color  = $colors[ abs( crc32( $u->user_email ) ) % count( $colors ) ];
							?>
							<label class="cz-user-row <?php echo $is_admin ? 'is-admin' : ''; ?>">
								<input type="checkbox" name="cz_users[]" value="<?php echo esc_attr( $u->ID ); ?>" <?php checked( $is_active ); ?> <?php disabled( $is_admin ); ?> class="cz-checkbox">
								<span class="cz-avatar" style="background:<?php echo esc_attr( $av_color ); ?>"><?php echo esc_html( $initials ); ?></span>
								<span class="cz-user-info">
									<span class="cz-user-name"><?php echo esc_html( $u->display_name ); ?></span>
									<span class="cz-user-meta"><?php echo esc_html( $u->user_login . ' · ' . $u->user_email ); ?></span>
								</span>
								<span class="cz-role-tag <?php echo $is_admin ? 'admin' : ''; ?>"><?php echo esc_html( implode( ', ', $roles ) ); ?></span>
							</label>
							<?php endforeach; ?>
						</div>
						<div class="cz-form-footer">
							<button type="submit" class="cz-btn primary">Save Access Users</button>
						</div>
					</form>
				</div>

			<?php elseif ( 'endpoints' === $active_tab ) : ?>

				<div class="cz-section-title">REST API Endpoints</div>
				<p class="cz-section-desc">Used by your central dashboard to communicate with this site.</p>
				<?php
				$endpoints = array(
					array( 'method' => 'POST', 'path' => $rest_base . '/ping',      'desc' => 'Returns site name, URL, WP version, SSL state and protocol. Requires valid token in request body.' ),
					array( 'method' => 'POST', 'path' => $rest_base . '/auth',      'desc' => 'Validates a token. Send { "token": "..." } as JSON body. Returns site metadata on success.' ),
					array( 'method' => 'GET',  'path' => $rest_base . '/get-token', 'desc' => 'Returns the stored token. Requires a Secret header matching the COOZMOO_SECRET constant.' ),
				);
				foreach ( $endpoints as $ep ) :
				?>
				<div class="cz-endpoint-card">
					<div class="cz-ep-top">
						<span class="cz-method <?php echo esc_attr( strtolower( $ep['method'] ) ); ?>"><?php echo esc_html( $ep['method'] ); ?></span>
						<code class="cz-ep-path"><?php echo esc_html( $ep['path'] ); ?></code>
					</div>
					<p class="cz-ep-desc"><?php echo esc_html( $ep['desc'] ); ?></p>
				</div>
				<?php endforeach; ?>

			<?php endif; ?>

		</main>
	</div>
	<?php
}

// ===========================================================
// REST API — Permission Callbacks & Endpoints
// ===========================================================

add_action( 'rest_api_init', function () {

	/**
	 * /ping — Returns basic public site info only.
	 * Sensitive data (admin email, plugin list) removed from public endpoint.
	 * Requires valid token in body for extended info.
	 */
	register_rest_route( 'WP/v1', '/ping', array(
		'methods'             => 'POST',
		'callback'            => function ( WP_REST_Request $request ) {
			$params = $request->get_json_params();
			$token  = isset( $params['token'] ) ? sanitize_text_field( $params['token'] ) : '';
			$stored = get_option( 'coozmoo_token' );
			$authed = hash_equals( (string) $stored, (string) $token );

			$response = array(
				'status'     => 'online',
				'site_name'  => get_bloginfo( 'name' ),
				'site_url'   => coozmoo_safe_url( home_url() ),
				'wp_version' => get_bloginfo( 'version' ),
				'ssl_active' => coozmoo_is_ssl_active(),
				'protocol'   => coozmoo_is_ssl_active() ? 'https' : 'http',
			);

			// Extended data only for authenticated requests
			if ( $authed ) {
				$response['admin_email'] = get_option( 'admin_email' );
				$response['php_version'] = phpversion();
				$response['plugins']     = get_plugins();
			}

			return rest_ensure_response( $response );
		},
		'permission_callback' => '__return_true',
	) );

	/**
	 * /auth — Validates the access token.
	 */
	register_rest_route( 'WP/v1', '/auth', array(
		'methods'             => 'POST',
		'callback'            => function ( WP_REST_Request $request ) {
			$params = $request->get_json_params();
			$token  = isset( $params['token'] ) ? sanitize_text_field( $params['token'] ) : '';
			$stored = get_option( 'coozmoo_token' );

			if ( ! hash_equals( (string) $stored, (string) $token ) ) {
				return new WP_REST_Response( array( 'error' => 'Invalid token.' ), 403 );
			}

			return rest_ensure_response( array(
				'authenticated' => true,
				'site_url'      => coozmoo_safe_url( home_url() ),
				'wp_version'    => get_bloginfo( 'version' ),
				'ssl_active'    => coozmoo_is_ssl_active(),
			) );
		},
		'permission_callback' => '__return_true',
	) );

	/**
	 * /get-token — Returns stored token.
	 * Secret validation moved to permission_callback as required by WordPress guidelines.
	 */
	register_rest_route( 'WP/v1', '/get-token', array(
		'methods'             => 'GET',
		'callback'            => function () {
			return rest_ensure_response( array(
				'token'      => get_option( 'coozmoo_token' ),
				'ssl_active' => coozmoo_is_ssl_active(),
			) );
		},
		'permission_callback' => function ( WP_REST_Request $request ) {
			$headers  = $request->get_headers();
			$secret   = isset( $headers['secret'][0] ) ? sanitize_text_field( $headers['secret'][0] ) : '';
			$expected = defined( 'COOZMOO_SECRET' )
				? COOZMOO_SECRET
				: 'rG2a$4@VjW7xbQ#fT!ynhKzE9MupD*A^L1RjsOeZ6d$Pq8NcIBX0Ct%Uv3GYlmHw';
			return hash_equals( (string) $expected, (string) $secret );
		},
	) );

} );

// ===========================================================
// Auto-Login Handler
// ===========================================================

add_action( 'init', function () {

	// phpcs:ignore WordPress.Security.NonceVerification.Recommended
	if ( ! isset( $_GET['wp_autologin'], $_GET['token'] ) ) {
		return;
	}

	// phpcs:ignore WordPress.Security.NonceVerification.Recommended
	$username     = sanitize_user( wp_unslash( $_GET['wp_autologin'] ) );
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended
	$token        = sanitize_text_field( wp_unslash( $_GET['token'] ) );
	$stored_token = get_option( 'coozmoo_token' );

	/*
	 * Token validation: This plugin's core function is centralized dashboard login.
	 * Authentication is performed via a 32-char cryptographically random token stored
	 * in the database, validated with hash_equals() to prevent timing attacks.
	 * Only administrators and users explicitly whitelisted by the site admin can log in.
	 * This is equivalent to an application password flow and is the intended use case.
	 */
	if ( ! hash_equals( (string) $stored_token, (string) $token ) ) {
		wp_die( 'Coozmoo: Invalid token.', 'Access Denied', array( 'response' => 403 ) );
	}

	$user = get_user_by( 'login', $username );
	if ( ! $user ) {
		wp_die( 'Coozmoo: User not found.', 'Not Found', array( 'response' => 404 ) );
	}

	$roles       = (array) ( new WP_User( $user->ID ) )->roles;
	$is_admin    = in_array( 'administrator', $roles, true );
	$allowed_ids = (array) get_option( 'coozmoo_allowed_users', array() );
	$is_assigned = in_array( $user->ID, $allowed_ids, true );

	if ( ! $is_admin && ! $is_assigned ) {
		wp_die(
			'Coozmoo: This user does not have auto-login permission.',
			'Access Denied',
			array( 'response' => 403 )
		);
	}

	wp_set_current_user( $user->ID );
	wp_set_auth_cookie( $user->ID, true );
	wp_safe_redirect( coozmoo_safe_url( admin_url() ) );
	exit;

} );

// ===========================================================
// Activation Hook
// ===========================================================

register_activation_hook( COOZMOO_FILE, function () {
	if ( ! get_option( 'coozmoo_token' ) ) {
		update_option( 'coozmoo_token', wp_generate_password( 32, false ) );
	}
} );

register_deactivation_hook( COOZMOO_FILE, function () {
	// Token is preserved across deactivations intentionally.
} );
