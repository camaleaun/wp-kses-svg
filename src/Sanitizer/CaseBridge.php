<?php
/**
 * CamelCase round-trip across the wp_kses() boundary.
 *
 * The wp_kses() function lowercases attribute names both when matching the allowlist and
 * when emitting output.  SVG, however, is case-sensitive: viewBox,
 * gradientUnits, preserveAspectRatio and friends must keep their canonical
 * camelCase or the markup is invalid.
 *
 * This stage bridges the gap by renaming attributes around the wp_kses() call:
 *
 *   - normalize() lowercases every camelCase attribute name so wp_kses() can
 *     match it against the (lowercase) allowlist keys.
 *   - restore() renames each attribute back to its canonical camelCase form
 *     after wp_kses() has run.
 *
 * The canonical mapping is the static Allowlist::case_map() table.  That table
 * is verified, entry by entry, against WP_HTML_Processor::
 * get_qualified_attribute_name() (the authoritative HTML-spec mapping) by
 * CaseBridgeTest, so the hand-maintained table can never silently drift from
 * the spec mapping without a test failing.
 *
 * Why a string rewrite is safe here (it never touches attribute *values*):
 *
 *   1. The rewrite operates only inside tag-open regions ("<tag ...>"); text
 *      content between tags is never matched.
 *   2. Within a tag, every quoted value is masked with an unprintable
 *      placeholder *before* the name lookup runs, then restored afterwards, so
 *      a value such as fill="viewBox" or font-family="a viewBox=b" can never be
 *      mistaken for an attribute name.
 *   3. The input is validated as well-formed XML upstream (XmlValidator), which
 *      guarantees every attribute value is quoted — the precondition the
 *      masking step relies on.
 *
 * This replaces the earlier WP_HTML_Processor-based walk: it is ~24x faster on
 * camelCase markup (≈24 µs vs ≈575 µs per round trip) while producing output
 * that is byte-for-byte identical to the processor on the full adversarial
 * corpus (see CaseBridgeTest).
 *
 * @package WpKsesSvg\Sanitizer
 * @since   0.1.0
 */

namespace WpKsesSvg\Sanitizer;

defined( 'ABSPATH' ) || exit;

/**
 * Normalises and restores SVG attribute-name case around wp_kses().
 *
 * @since 0.1.0
 */
final class CaseBridge {

	/**
	 * Matches any attribute-name token inside a masked tag region.
	 *
	 * Capture groups: (1) the leading whitespace, (2) the bare attribute name,
	 * (3) optional whitespace plus the "=" sign.  Only the name in group 2 is a
	 * rewrite candidate; the surrounding capture groups are re-emitted verbatim.
	 *
	 * @since 0.1.0
	 * @var string
	 */
	private const RE_ATTR_NAME = '/(\s)([a-zA-Z][a-zA-Z0-9]*)(\s*=)/';

	/**
	 * Matches a complete tag-open region, "<tag ... >".
	 *
	 * @since 0.1.0
	 * @var string
	 */
	private const RE_TAG_OPEN = '/<[a-zA-Z][^>]*>/s';

	/**
	 * Matches a quoted attribute value (double- or single-quoted).
	 *
	 * @since 0.1.0
	 * @var string
	 */
	private const RE_QUOTED_VALUE = '/"[^"]*"|\'[^\']*\'/';

	/**
	 * Cheap pre-check: does the markup contain any camelCase attribute name?
	 *
	 * The round-trip is the costliest part of the pipeline.  The vast majority
	 * of real-world SVGs (icons, simple shapes) use only lowercase attribute
	 * names and never need the round-trip at all.
	 *
	 * This regex looks for an attribute-name token (word boundary, letters,
	 * then "=") that contains an uppercase letter.  When none is present, the
	 * normalize/restore passes are provably no-ops and can be skipped.
	 *
	 * It is intentionally over-inclusive: a false positive merely runs the
	 * (correct) rewrite unnecessarily; it can never cause a real camelCase
	 * attribute to be missed, because any such attribute matches this pattern.
	 *
	 * @since 0.1.0
	 * @var string
	 */
	private const RE_HAS_CAMELCASE_ATTR = '/\s[a-zA-Z:-]*[A-Z][a-zA-Z:-]*\s*=/';

	/**
	 * Whether the markup contains at least one camelCase attribute name.
	 *
	 * When this returns false, normalize() and restore() are guaranteed no-ops
	 * and the caller may skip them entirely.
	 *
	 * @since  0.1.0
	 *
	 * @param  string $svg SVG markup.
	 * @return bool        True when a camelCase attribute name may be present.
	 */
	public static function needs_rewrite( string $svg ): bool {
		return 1 === preg_match( self::RE_HAS_CAMELCASE_ATTR, $svg );
	}

	/**
	 * Lowercase every camelCase attribute name in the markup.
	 *
	 * Uses the camelCase => lowercase direction of Allowlist::case_map() so
	 * wp_kses() can match the (lowercase) allowlist keys.  Attribute values and
	 * element text content are never altered.
	 *
	 * @since  0.1.0
	 *
	 * @param  string $svg Well-formed SVG markup.
	 * @return string      Markup with all attribute names lowercased.
	 */
	public static function normalize( string $svg ): string {
		return self::rewrite_attribute_case( $svg, array_flip( Allowlist::case_map() ) );
	}

	/**
	 * Restore canonical camelCase attribute names after wp_kses() has run.
	 *
	 * Uses the lowercase => camelCase direction of Allowlist::case_map().
	 *
	 * @since  0.1.0
	 *
	 * @param  string $svg SVG markup (post wp_kses).
	 * @return string      Markup with canonical camelCase attribute names.
	 */
	public static function restore( string $svg ): string {
		return self::rewrite_attribute_case( $svg, Allowlist::case_map() );
	}

	/**
	 * Rewrite attribute-name case using a name => name lookup table.
	 *
	 * The same routine serves both directions; the caller supplies the lookup
	 * table mapping each source name to its target name.  Names not present in
	 * the table are left untouched.
	 *
	 * Safety: only tag-open regions are processed, and within each region every
	 * quoted value is masked before the name lookup runs (see the class-level
	 * doc for the full rationale), so values and text content are never mutated.
	 *
	 * @since  0.1.0
	 *
	 * @param  string                $svg    SVG markup to rewrite.
	 * @param  array<string, string> $lookup Source-name => target-name map.
	 * @return string                        Rewritten markup.
	 */
	private static function rewrite_attribute_case( string $svg, array $lookup ): string {
		if ( '' === $svg || empty( $lookup ) ) {
			return $svg;
		}

		return (string) preg_replace_callback(
			self::RE_TAG_OPEN,
			static function ( array $tag ) use ( $lookup ): string {
				return self::rewrite_tag( $tag[0], $lookup );
			},
			$svg
		);
	}

	/**
	 * Rewrite attribute names within a single tag-open region.
	 *
	 * Masks quoted values, applies the name lookup, then restores the values.
	 *
	 * @since  0.1.0
	 *
	 * @param  string                $tag    A complete "<tag ...>" region.
	 * @param  array<string, string> $lookup Source-name => target-name map.
	 * @return string                        The rewritten tag region.
	 */
	private static function rewrite_tag( string $tag, array $lookup ): string {
		$masks  = array();
		$masked = (string) preg_replace_callback(
			self::RE_QUOTED_VALUE,
			static function ( array $value ) use ( &$masks ): string {
				// NUL-delimited placeholder: NUL bytes cannot appear in
				// well-formed XML, so the placeholder is collision-free.
				$key           = "\x00" . count( $masks ) . "\x00";
				$masks[ $key ] = $value[0];
				return $key;
			},
			$tag
		);

		$rewritten = (string) preg_replace_callback(
			self::RE_ATTR_NAME,
			static function ( array $m ) use ( $lookup ): string {
				$name = $m[2];
				return isset( $lookup[ $name ] )
					? $m[1] . $lookup[ $name ] . $m[3]
					: $m[0];
			},
			$masked
		);

		return strtr( $rewritten, $masks );
	}
}
