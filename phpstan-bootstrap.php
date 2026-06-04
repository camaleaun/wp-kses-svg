<?php
/**
 * PHPStan bootstrap — defines constants required for static analysis.
 */

define( 'ABSPATH', '/tmp/wordpress/' );
define( 'WPINC', 'wp-includes' );
define( 'WP_KSES_SVG_VERSION', '0.1.0' );
define( 'WP_KSES_SVG_PATH', __DIR__ . '/' );
define( 'WP_KSES_SVG_URL', 'https://example.com/wp-content/plugins/wp-kses-svg/' );

if ( ! function_exists( 'selfd' ) ) {
	function selfd( string $file ): void {} // phpcs:ignore
}
