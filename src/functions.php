<?php
/**
 * Public API functions.
 *
 * Defines the single global function wp_kses_svg() that mirrors the familiar
 * wp_kses() signature, making the intent clear to Core reviewers and third-party
 * developers alike.
 *
 * @package WpKsesSvg
 * @since   0.1.0
 */

use WpKsesSvg\Sanitizer\Sanitizer;

if ( ! function_exists( 'wp_kses_svg' ) ) {
	/**
	 * Sanitize an SVG string, keeping only safe tags and attributes.
	 *
	 * Drop-in companion to wp_kses() / wp_kses_post() for SVG content.
	 * Internally uses wp_kses() with an SVG-specific allowlist, preceded by
	 * XML validation, XXE/DOCTYPE stripping, blocked-tag early rejection,
	 * fragment-only href enforcement, and inline style sanitization.
	 *
	 * Usage:
	 *   $safe_svg = wp_kses_svg( $raw_svg );
	 *
	 * Returns an empty string when:
	 *   - The input is not well-formed XML.
	 *   - The input contains blocked tags (script, foreignObject, handler…).
	 *   - The sanitized output fails re-validation.
	 *
	 * @since  0.1.0
	 *
	 * @param  string $svg Raw SVG markup (string only — file reading is the
	 *                     caller's responsibility).
	 * @return string      Sanitized SVG markup, or '' on failure.
	 */
	function wp_kses_svg( string $svg ): string {
		return Sanitizer::sanitize( $svg );
	}
}
