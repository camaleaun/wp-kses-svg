<?php
/**
 * PHPUnit bootstrap — loads Brain\Monkey and minimal WP stubs, then loads
 * plugin source files under test.
 *
 * @package WpKsesSvg
 * @license GPL-2.0-or-later
 */

declare( strict_types=1 );

require_once dirname( __DIR__ ) . '/vendor/autoload.php';

// Activate Patchwork stream wrapper BEFORE defining stub functions so that
// Brain\Monkey can mock them per test. Must come before stubs are required.
require_once dirname( __DIR__ ) . '/vendor/antecedent/patchwork/Patchwork.php';

// WordPress HTML API + kses — real WP classes loaded directly from wp-includes.
// Must come BEFORE stubs/functions.php to avoid redeclaration of wp_kses* functions.
require_once __DIR__ . '/stubs/wp-html-api.php';

// Remaining WordPress function stubs (everything not covered by wp-html-api.php).
require_once __DIR__ . '/stubs/functions.php';

// WordPress constants.
defined( 'ABSPATH' ) || define( 'ABSPATH', sys_get_temp_dir() . '/wordpress/' );
define( 'WP_KSES_SVG_VERSION', '0.1.0' );
define( 'WP_KSES_SVG_PATH', dirname( __DIR__ ) . '/' );
define( 'WP_KSES_SVG_URL', 'http://example.com/wp-content/plugins/wp-kses-svg/' );

// Plugin source files under test.
// Allowlist first (consumed by the stages), then the pipeline stages, then the
// Sanitizer orchestrator that wires them together.
require_once WP_KSES_SVG_PATH . 'src/Sanitizer/Allowlist.php';
require_once WP_KSES_SVG_PATH . 'src/Sanitizer/XmlValidator.php';
require_once WP_KSES_SVG_PATH . 'src/Sanitizer/ThreatScanner.php';
require_once WP_KSES_SVG_PATH . 'src/Sanitizer/ReferenceGuard.php';
require_once WP_KSES_SVG_PATH . 'src/Sanitizer/StyleSanitizer.php';
require_once WP_KSES_SVG_PATH . 'src/Sanitizer/CaseBridge.php';
require_once WP_KSES_SVG_PATH . 'src/Sanitizer/Sanitizer.php';
require_once WP_KSES_SVG_PATH . 'src/Upload/UploadFilter.php';
require_once WP_KSES_SVG_PATH . 'src/functions.php';
