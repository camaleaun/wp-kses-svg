<?php
/**
 * PSR-4 autoloader bootstrap.
 *
 * @package WpKsesSvg
 * @since   0.1.0
 */

namespace WpKsesSvg;

defined( 'ABSPATH' ) || exit;

/**
 * Bootstraps Composer's PSR-4 autoloader.
 *
 * @since 0.1.0
 */
class Autoloader {

	/**
	 * Constructor — private, use ::init().
	 *
	 * @since 0.1.0
	 */
	private function __construct() {}

	/**
	 * Require vendor/autoload.php and return the result.
	 *
	 * @since  0.1.0
	 * @return bool|mixed False when the autoloader file is missing or returns falsy.
	 */
	public static function init(): mixed {
		$autoloader = dirname( __DIR__ ) . '/vendor/autoload.php';

		if ( ! is_readable( $autoloader ) ) {
			self::missing_autoloader();
			return false;
		}

		$result = require $autoloader;
		return $result ? $result : false;
	}

	/**
	 * Display an admin notice when vendor/autoload.php is missing.
	 *
	 * @since  0.1.0
	 * @return void
	 */
	private static function missing_autoloader(): void {
		if ( ! is_admin() ) {
			return;
		}
		add_action(
			'admin_notices',
			function () {
				echo '<div class="notice notice-error"><p>' .
					esc_html__(
						'Wp Kses Svg: Composer autoloader not found. Run "composer install".',
						'wp-kses-svg'
					) .
					'</p></div>';
			}
		);
	}
}
