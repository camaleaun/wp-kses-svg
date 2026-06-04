<?php
/**
 * XML well-formedness validation and preamble normalisation.
 *
 * This stage owns every interaction with libxml.  It answers a single
 * question — "is this string well-formed XML, parsed with all dangerous
 * features disabled?" — and provides the preamble-stripping helper that
 * removes constructs (XML declaration, DOCTYPE, comments, whitespace-encoded
 * control characters) which are either unnecessary for inline SVG or actively
 * dangerous.
 *
 * Security rationale:
 *   - LIBXML_NONET disables all network access during parsing, defeating
 *     SSRF via external DTDs and entities.
 *   - LIBXML_NOENT disables entity substitution, defeating XXE.
 *   - The DOCTYPE is stripped unconditionally, so even a well-formed file
 *     carrying an entity declaration loses it before any further processing.
 *
 * @package WpKsesSvg\Sanitizer
 * @since   0.1.0
 */

namespace WpKsesSvg\Sanitizer;

defined( 'ABSPATH' ) || exit;

/**
 * Validates XML well-formedness and normalises the document preamble.
 *
 * @since 0.1.0
 */
final class XmlValidator {

	/**
	 * Libxml flags applied to every parse: no network, no entity expansion.
	 *
	 * @since 0.1.0
	 * @var int
	 */
	private const LIBXML_FLAGS = LIBXML_NONET | LIBXML_NOENT;

	/**
	 * Wrapper element used to parse fragments without an XML declaration.
	 *
	 * Declares the xlink namespace so that xlink:href attributes do not cause
	 * "undefined namespace prefix" parse errors during validation.
	 *
	 * @since 0.1.0
	 * @var string
	 */
	private const WRAP_OPEN  = '<root xmlns:xlink="http://www.w3.org/1999/xlink">';
	private const WRAP_CLOSE = '</root>';

	/**
	 * Determine whether a string is well-formed XML.
	 *
	 * Parses the string (wrapped in a namespaced root element) with all
	 * external-entity and network features disabled.  Any libxml error means
	 * the document is rejected.
	 *
	 * @since  0.1.0
	 *
	 * @param  string $xml XML/SVG string to validate.
	 * @return bool        True when the string is well-formed XML.
	 */
	public static function is_well_formed( string $xml ): bool {
		$previous = libxml_use_internal_errors( true );
		libxml_clear_errors();

		$document = new \DOMDocument();
		$parsed   = $document->loadXML( self::WRAP_OPEN . $xml . self::WRAP_CLOSE, self::LIBXML_FLAGS );

		$errors = libxml_get_errors();
		libxml_clear_errors();
		libxml_use_internal_errors( $previous );

		return $parsed && empty( $errors );
	}

	/**
	 * Remove the XML preamble and normalise whitespace escapes.
	 *
	 * Strips, in order:
	 *   1. The XML processing instruction (<?xml ... ?>).
	 *   2. Any DOCTYPE declaration (the primary XXE vector).
	 *   3. HTML comments (which can hide payloads from naive parsers).
	 *   4. Numeric character references for the C0 whitespace bytes
	 *      (tab &#9;/&#x9;, LF &#10;/&#xA;, CR &#13;/&#xD;).
	 *
	 * Step 4 matters because browsers strip ASCII whitespace from URL values
	 * before parsing the scheme, so "java&#9;script:" is read as "javascript:"
	 * at render time.  Collapsing those references here lets the downstream
	 * threat scanner detect the reconstituted scheme.  All other numeric
	 * references (e.g. &#169; for the copyright sign) are preserved.
	 *
	 * @since  0.1.0
	 *
	 * @param  string $svg Raw SVG string.
	 * @return string      SVG string without preamble or whitespace escapes.
	 */
	public static function strip_preamble( string $svg ): string {
		$svg = preg_replace( '/<\?xml[^>]*\?>/i', '', $svg ) ?? $svg;
		$svg = preg_replace( '/<!DOCTYPE[^>]*>/is', '', $svg ) ?? $svg;
		$svg = preg_replace( '/<!--[\s\S]*?-->/', '', $svg ) ?? $svg;
		$svg = preg_replace( '/&#(?:[xX][09aAdD]|9|10|13);/', '', $svg ) ?? $svg;

		return trim( $svg );
	}
}
