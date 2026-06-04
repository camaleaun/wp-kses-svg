<?php
/**
 * Loads the WordPress HTML API classes directly from wp-includes.
 *
 * This avoids a full WordPress bootstrap while still exercising the real
 * WP_HTML_Processor implementation in unit tests.
 *
 * Load order mirrors wp-settings.php lines 265-278.
 *
 * @package WpKsesSvg\Tests
 */

declare( strict_types=1 );

// WP_INCLUDES_PATH env var lets CI point to an installed WordPress without
// requiring the repo to be nested inside a WP install tree.
// Falls back to dirname(__DIR__, 5) which resolves correctly when the plugin
// lives at wp-content/plugins/wp-kses-svg/ inside a WordPress root.
$wp_includes = getenv( 'WP_INCLUDES_PATH' ) ?: dirname( __DIR__, 5 ) . '/wp-includes';

// kses.php provides wp_kses() and wp_kses_uri_attributes() used by the HTML API.
require_once $wp_includes . '/kses.php';

require_once $wp_includes . '/class-wp-token-map.php';
require_once $wp_includes . '/html-api/html5-named-character-references.php';
require_once $wp_includes . '/html-api/class-wp-html-attribute-token.php';
require_once $wp_includes . '/html-api/class-wp-html-span.php';
require_once $wp_includes . '/html-api/class-wp-html-doctype-info.php';
require_once $wp_includes . '/html-api/class-wp-html-text-replacement.php';
require_once $wp_includes . '/html-api/class-wp-html-decoder.php';
require_once $wp_includes . '/html-api/class-wp-html-tag-processor.php';
require_once $wp_includes . '/html-api/class-wp-html-unsupported-exception.php';
require_once $wp_includes . '/html-api/class-wp-html-active-formatting-elements.php';
require_once $wp_includes . '/html-api/class-wp-html-open-elements.php';
require_once $wp_includes . '/html-api/class-wp-html-token.php';
require_once $wp_includes . '/html-api/class-wp-html-stack-event.php';
require_once $wp_includes . '/html-api/class-wp-html-processor-state.php';
require_once $wp_includes . '/html-api/class-wp-html-processor.php';
