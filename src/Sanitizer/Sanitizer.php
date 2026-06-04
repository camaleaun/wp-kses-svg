<?php
/**
 * SVG sanitisation pipeline orchestrator.
 *
 * Sanitizer is a thin coordinator: it runs the staged pipeline in order and
 * owns no detection logic itself.  Each stage is a single-responsibility,
 * independently testable collaborator:
 *
 *   XmlValidator    — XML well-formedness, XXE/DOCTYPE protection, preamble strip.
 *   ThreatScanner   — deny-first hard-reject of fatal threats.
 *   ReferenceGuard  — href/url() reference safety.
 *   StyleSanitizer  — inline style="..." filtering.
 *   CaseBridge      — camelCase round-trip across the wp_kses() boundary.
 *   Allowlist       — the wp_kses() tag/attribute allowlist.
 *
 * Pipeline order (each step may short-circuit to '' on rejection):
 *
 *   1.  Validate XML well-formedness (XXE/SSRF disabled at libxml level).
 *   2.  Strip XML declaration, DOCTYPE, comments, whitespace escapes.
 *   3.  Hard-reject on any fatal threat (deny-first).
 *   4.  Strip non-fragment href/xlink:href on reference elements.
 *   5.  Hard-reject external url() in filter and presentation attributes.
 *   6.  Sanitise inline style attributes.
 *   7.  Lowercase camelCase → wp_kses() → restore camelCase.
 *   8.  Re-validate the sanitised output; reject if no longer well-formed.
 *
 * Public surface: Sanitizer::sanitize(), exposed globally as wp_kses_svg().
 *
 * @package WpKsesSvg\Sanitizer
 * @since   0.1.0
 */

namespace WpKsesSvg\Sanitizer;

defined( 'ABSPATH' ) || exit;

/**
 * Orchestrates the staged SVG sanitisation pipeline.
 *
 * @since 0.1.0
 */
final class Sanitizer {

	/**
	 * Sanitise an SVG string and return safe markup.
	 *
	 * Returns an empty string when the input is not well-formed XML, contains
	 * a fatal threat, or when the sanitised output fails re-validation.  The
	 * pipeline is deny-first: any rejection discards the entire file rather
	 * than salvaging a partially cleaned fragment.
	 *
	 * @since  0.1.0
	 *
	 * @param  string $svg Raw SVG markup.
	 * @return string      Sanitised SVG markup, or '' on failure.
	 */
	public static function sanitize( string $svg ): string {
		$svg = trim( $svg );

		if ( '' === $svg ) {
			return '';
		}

		// Step 1 — XML well-formedness + XXE/DOCTYPE protection.
		if ( ! XmlValidator::is_well_formed( $svg ) ) {
			return '';
		}

		// Step 2 — Strip preamble and normalise whitespace escapes.
		$svg = XmlValidator::strip_preamble( $svg );

		// Step 3 — Deny-first hard-reject of fatal threats.
		if ( ThreatScanner::has_threat( $svg ) ) {
			return '';
		}

		// Step 4 — Strip non-fragment references on reference elements.
		$svg = ReferenceGuard::strip_external_references( $svg );

		// Step 5 — Hard-reject external url() in filter/presentation attributes.
		if ( ReferenceGuard::has_external_filter_reference( $svg )
			|| ReferenceGuard::has_external_presentation_reference( $svg ) ) {
			return '';
		}

		// Step 6 — Sanitise inline style attributes.
		$svg = StyleSanitizer::sanitize( $svg );

		// Step 7 — camelCase round-trip across the wp_kses() boundary.
		//
		// The HTML API walk is the costliest part of the pipeline, so it is
		// skipped entirely when the markup contains no camelCase attribute name.
		// In that case wp_kses() cannot introduce one either, so both the
		// normalize and restore passes are provably no-ops.
		if ( CaseBridge::needs_rewrite( $svg ) ) {
			$svg = CaseBridge::normalize( $svg );
			$svg = wp_kses( $svg, Allowlist::get() );
			$svg = CaseBridge::restore( $svg );
		} else {
			$svg = wp_kses( $svg, Allowlist::get() );
		}

		// Step 8 — Re-validate the sanitised output.
		if ( '' !== $svg && ! XmlValidator::is_well_formed( $svg ) ) {
			return '';
		}

		return $svg;
	}
}
