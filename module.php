<?php
/**
 * Vault Spoke Module
 *
 * This module is loaded by the TIMU Core Module Loader.
 * It is NOT a WordPress plugin, but an extension of Core.
 * Depends on: Media Hub (provided by plugin-media-support-thisismyurl)
 *
 * @package TIMU_CORE
 * @subpackage TIMU_VAULT_SPOKE
 * @requires plugin-media-support-thisismyurl
 */

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
 * Initialize Vault Support plugin.
 *
 * @return void
 */
function init(): void {
	// Check if Media Support plugin (plugin-media-support-thisismyurl) is loaded.
	// This plugin provides the media_hub feature that Vault Support depends on.
	$has_media_support = function_exists( '\TIMU\MediaSupport\init' );
	$has_media_hub_feature = function_exists( '\TIMU\CoreSupport\has_timu_feature' ) && \TIMU\CoreSupport\has_timu_feature( 'media_hub' );
	
	if ( ! $has_media_support && ! $has_media_hub_feature ) {
		add_action( 'admin_notices', __NAMESPACE__ . '\\dependency_notice' );
		return;
	}

	// Register this plugin as a Spoke (not Hub) with Core Support.
	do_action(
		'timu_register_module',
		array(
			'slug'         => 'vault-support-thisismyurl',
			'name'         => __( 'Vault Support', 'vault-support-thisismyurl' ),
			'type'         => 'spoke',
			'suite'        => 'media',
			'version'      => TIMU_VAULT_VERSION,
			'description'  => __( 'Secure original storage with encryption, journaling, rollback engine, and cloud offload.', 'vault-support-thisismyurl' ),
			'capabilities' => array( 'vault', 'encryption', 'journaling', 'rollback', 'cloud_offload' ),
			'path'         => TIMU_VAULT_PATH,
			'url'          => TIMU_VAULT_URL,
			'basename'     => TIMU_VAULT_BASENAME,
		)
	);

	// Load Vault class from vault-support namespace.
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
add_action( 'plugins_loaded', __NAMESPACE__ . '\\init', 15 );

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
					'<a href="https://github.com/thisismyurl/plugin-media-support-thisismyurl">Media Support (plugin-media-support-thisismyurl)</a>'
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
