<?php
/**
 * Package bootstrap.
 *
 * @package WpKsesSvg
 * @since   0.1.0
 */

namespace WpKsesSvg;

use WpKsesSvg\Upload\UploadFilter;

defined( 'ABSPATH' ) || exit;

/**
 * Initialises all first-party packages.
 *
 * @since 0.1.0
 */
class Packages {

	/**
	 * Constructor — private, use ::init().
	 *
	 * @since 0.1.0
	 */
	private function __construct() {}

	/**
	 * Boot all packages.
	 *
	 * @since  0.1.0
	 * @return void
	 */
	public static function init(): void {
		// Load the public wp_kses_svg() function.
		require_once WP_KSES_SVG_PATH . 'src/functions.php';

		// Register upload hooks (MIME allowance + on-upload sanitization).
		UploadFilter::register();
	}
}
