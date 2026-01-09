<?php
/**
 * Author:              Christopher Ross
 * Author URI:          https://thisismyurl.com/?source=vault-support-thisismyurl
 * Plugin Name:         Vault Support
 * Plugin URI:          https://thisismyurl.com/vault-support-thisismyurl/?source=vault-support-thisismyurl
 * Donate link:         https://thisismyurl.com/vault-support-thisismyurl/#register?source=vault-support-thisismyurl
 * * Description:         Vault System for the thisismyurl.com Shared Code Suite. Secure original storage, encryption, journaling, rollback engine, and cloud offload for media files.
 * Tags:                vault, backup, encryption, security, media, storage, journaling, rollback, cloud
 * * Version:             1.2601.0819
 * Requires at least:   6.4
 * Requires PHP:        8.2
 * Requires Plugins:    media-support-thisismyurl
 * * Update URI:          https://github.com/thisismyurl/vault-support-thisismyurl
 * GitHub Plugin URI:   https://github.com/thisismyurl/vault-support-thisismyurl
 * Primary Branch:      main
 * Text Domain:         vault-support-thisismyurl
 * * License:             GPL2
 * License URI:         https://www.gnu.org/licenses/gpl-2.0.html
 * * @package TIMU_VAULT_SUPPORT
 * */

namespace TIMU\VaultSupport;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Plugin constants.
 */
define( 'TIMU_VAULT_VERSION', '1.2601.0819' );
define( 'TIMU_VAULT_PATH', plugin_dir_path( __FILE__ ) );
define( 'TIMU_VAULT_URL', plugin_dir_url( __FILE__ ) );
define( 'TIMU_VAULT_BASENAME', plugin_basename( __FILE__ ) );

/**
 * Note: The Vault class is loaded from includes/class-timu-vault.php and aliased for legacy Core namespace compatibility.
 */

/**
 * Check dependencies before activation.
 *
 * @return void
 */
function check_dependencies(): void {
	if ( ! class_exists( 'TIMU\\MediaSupport\\Media_Processor' ) ) {
		deactivate_plugins( TIMU_VAULT_BASENAME );
		wp_die(
			esc_html__( 'Vault Support requires Media Support to be installed and activated.', 'vault-support-thisismyurl' ),
			esc_html__( 'Plugin Dependency Error', 'vault-support-thisismyurl' ),
			array( 'back_link' => true )
		);
	}
}
register_activation_hook( __FILE__, __NAMESPACE__ . '\\check_dependencies' );

/**
 * Initialize Vault Support plugin.
 *
 * @return void
 */
function init(): void {
	// Bail if Media Support is not active.
	if ( ! class_exists( 'TIMU\\MediaSupport\\Media_Processor' ) ) {
		add_action( 'admin_notices', __NAMESPACE__ . '\\dependency_notice' );
		return;
	}

	// Register this plugin as a Hub with Core Support.
	do_action(
		'timu_register_module',
		array(
			'slug'         => 'vault-support-thisismyurl',
			'name'         => __( 'Vault Support', 'vault-support-thisismyurl' ),
			'type'         => 'hub',
			'suite'        => 'media',
			'version'      => TIMU_VAULT_VERSION,
			'description'  => __( 'Secure original storage with encryption, journaling, rollback engine, and cloud offload.', 'vault-support-thisismyurl' ),
			'capabilities' => array( 'vault', 'encryption', 'journaling', 'rollback', 'cloud_offload' ),
			'path'         => TIMU_VAULT_PATH,
			'url'          => TIMU_VAULT_URL,
			'basename'     => TIMU_VAULT_BASENAME,
		)
	);

	// Load Vault class from this plugin and initialize.
	if ( ! class_exists( '\\TIMU\\VaultSupport\\TIMU_Vault' ) && file_exists( TIMU_VAULT_PATH . 'includes/class-timu-vault.php' ) ) {
		require_once TIMU_VAULT_PATH . 'includes/class-timu-vault.php';
	}

	if ( class_exists( '\\TIMU\\VaultSupport\\TIMU_Vault' ) ) {
		\TIMU\VaultSupport\TIMU_Vault::init();
	}

	// Add admin menu.
	add_action( 'admin_menu', __NAMESPACE__ . '\\register_admin_menu' );
	add_action( 'network_admin_menu', __NAMESPACE__ . '\\register_network_admin_menu' );
}
add_action( 'plugins_loaded', __NAMESPACE__ . '\\init', 5 );

/**
 * Display dependency notice if Media Support is missing.
 *
 * @return void
 */
function dependency_notice(): void {
	?>
	<div class="notice notice-error">
		<p>
			<?php
			echo wp_kses_post(
				sprintf(
					/* translators: 1: Plugin name, 2: Required plugin name with link */
					__( '<strong>%1$s</strong> requires %2$s to be installed and activated.', 'vault-support-thisismyurl' ),
					'Vault Support',
					'<a href="https://github.com/thisismyurl/media-support-thisismyurl">Media Support</a>'
				)
			);
			?>
		</p>
	</div>
	<?php
}

/**
 * Register admin menu for Vault settings.
 *
 * @return void
 */
function register_admin_menu(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	add_submenu_page(
		'timu-core-dashboard',
		__( 'Vault Settings', 'vault-support-thisismyurl' ),
		__( 'Vault', 'vault-support-thisismyurl' ),
		'manage_options',
		'timu-vault-settings',
		__NAMESPACE__ . '\\render_settings_page'
	);
}

/**
 * Register network admin menu for Vault settings.
 *
 * @return void
 */
function register_network_admin_menu(): void {
	if ( ! current_user_can( 'manage_network_options' ) ) {
		return;
	}

	add_submenu_page(
		'timu-core-dashboard',
		__( 'Vault Settings', 'vault-support-thisismyurl' ),
		__( 'Vault', 'vault-support-thisismyurl' ),
		'manage_network_options',
		'timu-vault-settings',
		__NAMESPACE__ . '\\render_settings_page'
	);
}

/**
 * Render Vault settings page.
 *
 * @return void
 */
function render_settings_page(): void {
	// Settings view will be copied from core-support/includes/views/settings.php
	echo '<div class="wrap"><h1>' . esc_html__( 'Vault Settings', 'vault-support-thisismyurl' ) . '</h1>';
	echo '<p>' . esc_html__( 'Vault settings UI will be implemented here.', 'vault-support-thisismyurl' ) . '</p>';
	echo '</div>';
}

/**
 * Load text domain for translations.
 *
 * @return void
 */
function load_textdomain(): void {
	load_plugin_textdomain( 'vault-support-thisismyurl', false, dirname( TIMU_VAULT_BASENAME ) . '/languages' );
}
add_action( 'init', __NAMESPACE__ . '\\load_textdomain' );
