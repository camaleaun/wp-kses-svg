<?php
/**
 * Plugin-wide constants and path helpers.
 *
 * @package WpKsesSvg
 * @since   0.1.0
 */

namespace WpKsesSvg;

defined( 'ABSPATH' ) || exit;

/**
 * Centralises plugin paths and URLs.
 *
 * @since 0.1.0
 */
class Constants {

	/**
	 * Absolute path to the plugin root directory (with trailing slash).
	 *
	 * @since  0.1.0
	 * @return string
	 */
	public static function plugin_path(): string {
		return WP_KSES_SVG_PATH;
	}

	/**
	 * URL to the plugin root directory (with trailing slash).
	 *
	 * @since  0.1.0
	 * @return string
	 */
	public static function plugin_url(): string {
		return WP_KSES_SVG_URL;
	}

	/**
	 * Plugin version string.
	 *
	 * @since  0.1.0
	 * @return string
	 */
	public static function version(): string {
		return WP_KSES_SVG_VERSION;
	}
}
