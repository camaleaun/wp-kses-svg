<?php
/**
 * Reference-safety enforcement for href, xlink:href and url() values.
 *
 * SVG can reference other resources in three ways that this stage governs:
 *
 *   1. href / xlink:href on *reference* elements (<use>, <mpath>, <textPath>,
 *      SMIL animation elements).  These must point only to internal fragments
 *      (#id); an external URL would enable SSRF or resource inclusion.  The
 *      <a> element is deliberately excluded — it is a navigation element and
 *      legitimately carries https:// and mailto: URLs, which wp_kses()
 *      validates via wp_allowed_protocols().
 *
 *   2. url() inside filter primitive in / in2 attributes.  An external url()
 *      causes the browser to fetch a remote resource at render time.
 *
 *   3. url() inside presentation attributes (fill, stroke, filter, clip-path,
 *      mask, marker-*).  Same external-fetch concern as (2).
 *
 * Case (1) is *stripped* (the bad reference is removed, the element kept).
 * Cases (2) and (3) are *detected* and reported so the Sanitizer can
 * hard-reject the whole file (deny-first).
 *
 * Note on recursive <use> (billion-laughs DoS): <use href="#a"> nesting is
 * structurally valid SVG with no code-execution vector — at worst it stresses
 * the renderer, which is a browser concern, not a file-upload-gate concern.
 * It is intentionally allowed through.
 *
 * @package WpKsesSvg\Sanitizer
 * @since   0.1.0
 */

namespace WpKsesSvg\Sanitizer;

defined( 'ABSPATH' ) || exit;

/**
 * Enforces internal-only references and rejects external url() resources.
 *
 * @since 0.1.0
 */
final class ReferenceGuard {

	/**
	 * Reference elements whose href/xlink:href must be an internal #fragment.
	 *
	 * Listed in both lowercase and canonical camelCase so the regex alternation
	 * matches regardless of how the author cased the tag in the source markup.
	 *
	 * @since 0.1.0
	 * @var string[]
	 */
	private const FRAGMENT_REF_TAGS = array(
		'use',
		'mpath',
		'textpath',
		'textPath',
		'set',
		'animate',
		'animatetransform',
		'animateTransform',
		'animatemotion',
		'animateMotion',
	);

	/**
	 * Presentation attributes that accept url() and that a browser will fetch.
	 *
	 * @since 0.1.0
	 * @var string
	 */
	private const PRESENTATION_URL_ATTRS = 'fill|stroke|filter|clip-path|mask|marker-start|marker-mid|marker-end';

	/**
	 * Strip non-fragment href / xlink:href from reference elements.
	 *
	 * Only the elements in FRAGMENT_REF_TAGS are touched.  On those, any
	 * href / xlink:href whose value does not start with "#" is removed; the
	 * element itself is preserved.  The <a> element is never matched here.
	 *
	 * @since  0.1.0
	 *
	 * @param  string $svg SVG markup.
	 * @return string      SVG markup with unsafe references removed.
	 */
	public static function strip_external_references( string $svg ): string {
		$tags = implode( '|', array_map( 'preg_quote', self::FRAGMENT_REF_TAGS ) );

		return (string) preg_replace_callback(
			'/<(' . $tags . ')\b([^>]*?)>/is',
			static function ( array $matches ): string {
				$inner = preg_replace(
					'/(?:xlink:)?href\s*=\s*(["\'])(?!#).*?\1/i',
					'',
					$matches[2]
				);

				return '<' . $matches[1] . $inner . '>';
			},
			$svg
		) ?? $svg;
	}

	/**
	 * Whether any filter in / in2 attribute carries an external url() value.
	 *
	 * Named sources (SourceGraphic, SourceAlpha, …) never contain url(), and
	 * internal url(#id) references are explicitly permitted; only external
	 * url() values trigger a match.
	 *
	 * @since  0.1.0
	 *
	 * @param  string $svg SVG markup.
	 * @return bool        True when an external filter url() reference is found.
	 */
	public static function has_external_filter_reference( string $svg ): bool {
		return 1 === preg_match( '/\b(in2?)\s*=\s*(["\'])url\((?!#)[^)]*\)\2/i', $svg );
	}

	/**
	 * Whether any presentation attribute carries an external url() value.
	 *
	 * Internal url(#id) references are explicitly permitted; only external
	 * url(http(s)://…) values trigger a match.
	 *
	 * @since  0.1.0
	 *
	 * @param  string $svg SVG markup.
	 * @return bool        True when an external presentation url() is found.
	 */
	public static function has_external_presentation_reference( string $svg ): bool {
		$pattern = '/\b(?:' . self::PRESENTATION_URL_ATTRS . ')\s*=\s*["\']url\((?!#)[^)]*\)["\']/i';

		return 1 === preg_match( $pattern, $svg );
	}
}
