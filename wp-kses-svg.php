<?php
/**
 * Plugin Name:       Wp Kses Svg
 * Plugin URI:        PLUGIN SITE HERE
 * Description:       PLUGIN DESCRIPTION HERE
 * Version:           0.1.0
 * Requires at least: 6.4
 * Requires PHP:      8.1
 * Tested up to:      7.0
 * Author:            YOUR NAME HERE
 * Author URI:        YOUR SITE HERE
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-kses-svg
 * Domain Path:       /languages
 *
 * @package           WpKsesSvg
 */

defined( 'ABSPATH' ) || exit;

define( 'WP_KSES_SVG_VERSION', '0.1.0' );
define( 'WP_KSES_SVG_PATH', plugin_dir_path( __FILE__ ) );
define( 'WP_KSES_SVG_URL', plugin_dir_url( __FILE__ ) );

require_once WP_KSES_SVG_PATH . 'lib/selfdirectory/class-selfdirectory.php';
require_once WP_KSES_SVG_PATH . 'src/Autoloader.php';
require_once WP_KSES_SVG_PATH . 'src/Packages.php';

if ( ! \WpKsesSvg\Autoloader::init() ) {
	return;
}
\WpKsesSvg\Packages::init();

add_action(
	'init',
	function () {
		load_plugin_textdomain( 'wp-kses-svg', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
	}
);

add_action(
	'selfd_register',
	function () {
		selfd( __FILE__ );
	}
);
