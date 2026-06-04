<?php
/**
 * Deny-first threat detection.
 *
 * This stage performs the hard-reject pass: a single boolean question —
 * "does this markup contain anything that makes the whole file unsafe?".
 * When the answer is yes, the Sanitizer discards the entire file rather than
 * attempting to strip the offending construct (deny-first, not sanitise-and-
 * salvage).
 *
 * The scanner runs on the raw string before wp_kses().  It is intentionally
 * conservative: every check here is a reason to reject the file outright.
 *
 * Threats detected:
 *   - Explicitly blocked tags (script, foreignObject, handler, image, feImage).
 *   - Static on* event-handler attributes.
 *   - javascript: / data: / vbscript: URI schemes anywhere in the markup.
 *   - Unknown or namespace-prefixed tags (text-node defacement vector).
 *   - SMIL animate/set whose attributeName targets an on* handler or style.
 *
 * @package WpKsesSvg\Sanitizer
 * @since   0.1.0
 */

namespace WpKsesSvg\Sanitizer;

defined( 'ABSPATH' ) || exit;

/**
 * Scans SVG markup for fatal threats that warrant rejecting the whole file.
 *
 * @since 0.1.0
 */
final class ThreatScanner {

	/**
	 * Matches any static on* event-handler attribute (onload, onclick, …).
	 *
	 * @since 0.1.0
	 * @var string
	 */
	private const RE_EVENT_HANDLER = '/\bon\w+\s*=/i';

	/**
	 * Matches a dangerous URI scheme anywhere in the markup.
	 *
	 * @since 0.1.0
	 * @var string
	 */
	private const RE_DANGEROUS_SCHEME = '/\b(?:javascript|data|vbscript)\s*:/i';

	/**
	 * Matches a SMIL attributeName that targets an on* handler or the style attr.
	 *
	 * SMIL <animate>/<set> can mutate any attribute on a target element at
	 * runtime.  attributeName="onload" injects an event handler; attributeName=
	 * "style" injects an unsanitised style value.  Both bypass the static
	 * checks above, so they are caught here.
	 *
	 * @since 0.1.0
	 * @var string
	 */
	private const RE_SMIL_ATTRIBUTE = '/\battributeName\s*=\s*["\']\s*(?:on\w+|style)\s*["\']/i';

	/**
	 * Matches every opening / self-closing tag name in the markup.
	 *
	 * Capture group 1 is the tag name (including any namespace prefix).
	 *
	 * @since 0.1.0
	 * @var string
	 */
	private const RE_TAG_NAME = '/<([a-zA-Z][a-zA-Z0-9:._-]*)(?:[\s\/>])/';

	/**
	 * Determine whether the markup contains any fatal threat.
	 *
	 * Checks are ordered cheapest-first and short-circuit on the first hit, so
	 * obviously malicious input is rejected with minimal work.
	 *
	 * @since  0.1.0
	 *
	 * @param  string $svg SVG markup (post preamble-strip, pre wp_kses).
	 * @return bool        True when the file must be rejected.
	 */
	public static function has_threat( string $svg ): bool {
		return self::has_blocked_tag( $svg )
			|| self::has_event_handler( $svg )
			|| self::has_dangerous_scheme( $svg )
			|| self::has_smil_attribute_injection( $svg )
			|| self::has_unknown_tag( $svg );
	}

	/**
	 * Whether the markup contains an explicitly blocked tag.
	 *
	 * @since  0.1.0
	 *
	 * @param  string $svg SVG markup.
	 * @return bool        True when a blocked tag is present.
	 */
	private static function has_blocked_tag( string $svg ): bool {
		foreach ( Allowlist::blocked_tags() as $tag ) {
			if ( 1 === preg_match( '/<' . preg_quote( $tag, '/' ) . '[\s\/>]/i', $svg ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether the markup contains a static on* event-handler attribute.
	 *
	 * @since  0.1.0
	 *
	 * @param  string $svg SVG markup.
	 * @return bool        True when an on* attribute is present.
	 */
	private static function has_event_handler( string $svg ): bool {
		return 1 === preg_match( self::RE_EVENT_HANDLER, $svg );
	}

	/**
	 * Whether the markup contains a dangerous URI scheme.
	 *
	 * @since  0.1.0
	 *
	 * @param  string $svg SVG markup.
	 * @return bool        True when javascript:/data:/vbscript: is present.
	 */
	private static function has_dangerous_scheme( string $svg ): bool {
		return 1 === preg_match( self::RE_DANGEROUS_SCHEME, $svg );
	}

	/**
	 * Whether a SMIL attributeName targets an event handler or the style attr.
	 *
	 * @since  0.1.0
	 *
	 * @param  string $svg SVG markup.
	 * @return bool        True when a SMIL runtime-injection vector is present.
	 */
	private static function has_smil_attribute_injection( string $svg ): bool {
		return 1 === preg_match( self::RE_SMIL_ATTRIBUTE, $svg );
	}

	/**
	 * Whether the markup contains any unknown or namespace-prefixed tag.
	 *
	 * The wp_kses() function strips unknown tags but preserves their text content, so
	 * <evil:div>injected text</evil:div> would surface as visible plain text
	 * (defacement).  Detecting unknown tags here lets the file be rejected
	 * outright.
	 *
	 * The xml: and xlink: prefixes are tolerated because they appear as
	 * attribute prefixes in valid SVG, never as tag prefixes; the guard simply
	 * avoids a false positive should the tag-name regex ever catch one.
	 *
	 * @since  0.1.0
	 *
	 * @param  string $svg SVG markup.
	 * @return bool        True when an unknown or prefixed tag is present.
	 */
	private static function has_unknown_tag( string $svg ): bool {
		if ( ! preg_match_all( self::RE_TAG_NAME, $svg, $matches ) ) {
			return false;
		}

		$allowed = Allowlist::tag_lookup();

		foreach ( $matches[1] as $tag ) {
			$lower = strtolower( $tag );

			if ( str_starts_with( $lower, 'xml:' ) || str_starts_with( $lower, 'xlink:' ) ) {
				continue;
			}

			// Any namespace-prefixed tag is invalid SVG markup.
			if ( str_contains( $tag, ':' ) ) {
				return true;
			}

			if ( ! isset( $allowed[ $lower ] ) ) {
				return true;
			}
		}

		return false;
	}
}
