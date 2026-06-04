<?php
/**
 * Inline style="..." attribute sanitisation.
 *
 * This stage decomposes every inline style attribute into individual CSS
 * declarations and keeps only those whose property is on an explicit allowlist
 * and whose value contains no dangerous pattern (url(), expression(),
 * behaviour(), -moz-binding, javascript:, vbscript:, data:).
 *
 * Declarations that fail either test are dropped silently; a style attribute
 * left with no safe declarations is emitted empty so wp_kses() can remove it.
 *
 * @package WpKsesSvg\Sanitizer
 * @since   0.1.0
 */

namespace WpKsesSvg\Sanitizer;

defined( 'ABSPATH' ) || exit;

/**
 * Filters inline CSS declarations against a property and value allowlist.
 *
 * @since 0.1.0
 */
final class StyleSanitizer {

	/**
	 * CSS properties permitted inside an inline style attribute.
	 *
	 * Stored as a value => true lookup map for O(1) membership tests on the
	 * hot path.  Only visual / layout properties with no code-execution vector
	 * are included.
	 *
	 * @since 0.1.0
	 * @var array<string, true>
	 */
	private const SAFE_PROPERTIES = array(
		'fill'                => true,
		'fill-opacity'        => true,
		'fill-rule'           => true,
		'stroke'              => true,
		'stroke-width'        => true,
		'stroke-linecap'      => true,
		'stroke-linejoin'     => true,
		'stroke-dasharray'    => true,
		'stroke-dashoffset'   => true,
		'stroke-opacity'      => true,
		'opacity'             => true,
		'visibility'          => true,
		'display'             => true,
		'overflow'            => true,
		'clip-path'           => true,
		'clip-rule'           => true,
		'mask'                => true,
		'filter'              => true,
		'color'               => true,
		'stop-color'          => true,
		'stop-opacity'        => true,
		'flood-color'         => true,
		'flood-opacity'       => true,
		'color-interpolation' => true,
		'color-rendering'     => true,
		'shape-rendering'     => true,
		'image-rendering'     => true,
		'text-rendering'      => true,
		'vector-effect'       => true,
		'paint-order'         => true,
		'font-family'         => true,
		'font-size'           => true,
		'font-style'          => true,
		'font-weight'         => true,
		'text-anchor'         => true,
		'dominant-baseline'   => true,
		'letter-spacing'      => true,
		'word-spacing'        => true,
		'text-decoration'     => true,
		'writing-mode'        => true,
		'transform'           => true,
		'transform-origin'    => true,
		'transform-box'       => true,
		'isolation'           => true,
		'mix-blend-mode'      => true,
	);

	/**
	 * Substrings that are never safe inside a CSS value, regardless of property.
	 *
	 * @since 0.1.0
	 * @var string[]
	 */
	private const BLOCKED_VALUE_PATTERNS = array(
		'url(',
		'expression(',
		'behaviour(',
		'behavior(',
		'-moz-binding',
		'javascript:',
		'vbscript:',
		'data:',
	);

	/**
	 * Sanitise every inline style attribute in the markup.
	 *
	 * @since  0.1.0
	 *
	 * @param  string $svg SVG markup.
	 * @return string      SVG markup with sanitised style attributes.
	 */
	public static function sanitize( string $svg ): string {
		return (string) preg_replace_callback(
			'/style\s*=\s*(["\'])(.*?)\1/is',
			static function ( array $matches ): string {
				$quote = $matches[1];
				$safe  = self::filter_declarations( $matches[2] );

				return 'style=' . $quote . $safe . $quote;
			},
			$svg
		);
	}

	/**
	 * Filter a raw CSS declaration block down to its safe declarations.
	 *
	 * @since  0.1.0
	 *
	 * @param  string $css Raw value of a style attribute (without quotes).
	 * @return string      Semicolon-joined safe declarations, or '' if none.
	 */
	private static function filter_declarations( string $css ): string {
		$safe = array();

		foreach ( explode( ';', $css ) as $declaration ) {
			$declaration = trim( $declaration );

			if ( '' === $declaration ) {
				continue;
			}

			[ $property, $value ] = self::split_declaration( $declaration );

			if ( ! isset( self::SAFE_PROPERTIES[ $property ] ) ) {
				continue;
			}

			if ( self::value_has_blocked_pattern( $value ) ) {
				continue;
			}

			$safe[] = $property . ':' . $value;
		}

		return implode( ';', $safe );
	}

	/**
	 * Split a "property: value" declaration into a normalised pair.
	 *
	 * The property is lowercased; the value is returned verbatim (trimmed).
	 *
	 * @since  0.1.0
	 *
	 * @param  string $declaration A single CSS declaration.
	 * @return array{0: string, 1: string} [ property, value ].
	 */
	private static function split_declaration( string $declaration ): array {
		$parts    = explode( ':', $declaration, 2 );
		$property = strtolower( trim( $parts[0] ) );
		$value    = isset( $parts[1] ) ? trim( $parts[1] ) : '';

		return array( $property, $value );
	}

	/**
	 * Whether a CSS value contains any blocked substring.
	 *
	 * @since  0.1.0
	 *
	 * @param  string $value A CSS declaration value.
	 * @return bool          True when a blocked pattern is present.
	 */
	private static function value_has_blocked_pattern( string $value ): bool {
		$value = strtolower( $value );

		foreach ( self::BLOCKED_VALUE_PATTERNS as $pattern ) {
			if ( str_contains( $value, $pattern ) ) {
				return true;
			}
		}

		return false;
	}
}
