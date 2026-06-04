<?php
/**
 * Unit tests for CaseBridge — the camelCase round-trip stage.
 *
 * Focuses on the needs_rewrite() fast-path guard, which determines whether the
 * (expensive) HTML API walk can be skipped.  The normalize()/restore() round
 * trip itself is exercised end-to-end through SanitizerTest's case-preservation
 * tests; here we lock down the skip decision so a future change cannot silently
 * route camelCase markup down the no-op path.
 *
 * @package WpKsesSvg\Tests\Unit
 */

declare( strict_types=1 );

namespace WpKsesSvg\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use WpKsesSvg\Sanitizer\Allowlist;
use WpKsesSvg\Sanitizer\CaseBridge;

/**
 * @covers \WpKsesSvg\Sanitizer\CaseBridge
 */
class CaseBridgeTest extends TestCase {

	/**
	 * Markup containing a camelCase attribute name must request a rewrite.
	 *
	 * @param string $svg Markup expected to contain a camelCase attribute.
	 */
	#[DataProvider( 'camelcase_markup' )]
	public function test_needs_rewrite_true_for_camelcase( string $svg ): void {
		$this->assertTrue( CaseBridge::needs_rewrite( $svg ) );
	}

	public static function camelcase_markup(): array {
		return [
			'viewBox'             => [ '<svg viewBox="0 0 10 10"><circle r="5"/></svg>' ],
			'preserveAspectRatio' => [ '<svg preserveAspectRatio="xMidYMid"><rect/></svg>' ],
			'gradientUnits'       => [ '<linearGradient gradientUnits="userSpaceOnUse"/>' ],
			'gradientTransform'   => [ '<radialGradient gradientTransform="rotate(45)"/>' ],
			'patternUnits'        => [ '<pattern patternUnits="userSpaceOnUse"/>' ],
			'attributeName'       => [ '<animate attributeName="fill"/>' ],
			'stdDeviation'        => [ '<feGaussianBlur stdDeviation="2"/>' ],
		];
	}

	/**
	 * Markup with only lowercase attribute names must skip the rewrite.
	 *
	 * @param string $svg Markup expected to contain no camelCase attribute.
	 */
	#[DataProvider( 'lowercase_markup' )]
	public function test_needs_rewrite_false_for_lowercase( string $svg ): void {
		$this->assertFalse( CaseBridge::needs_rewrite( $svg ) );
	}

	public static function lowercase_markup(): array {
		return [
			'simple circle'   => [ '<svg xmlns="http://www.w3.org/2000/svg"><circle cx="5" cy="5" r="5" fill="red"/></svg>' ],
			'path with d'     => [ '<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0 L10 10 Z" fill="blue" stroke-width="2"/></svg>' ],
			'hyphenated attrs' => [ '<rect fill-opacity="0.5" stroke-linecap="round" clip-rule="evenodd"/>' ],
			'empty string'    => [ '' ],
		];
	}

	/**
	 * normalize() and restore() are no-ops on lowercase-only markup.
	 *
	 * When there is no camelCase attribute, both passes must return the input
	 * byte-for-byte unchanged (the skip in Sanitizer relies on this property).
	 */
	public function test_round_trip_is_noop_on_lowercase_markup(): void {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg"><circle cx="5" cy="5" r="5" fill="red"/></svg>';

		$this->assertSame( $svg, CaseBridge::restore( CaseBridge::normalize( $svg ) ) );
	}

	/**
	 * A camelCase attribute survives a full normalize() → restore() round trip.
	 */
	public function test_round_trip_preserves_camelcase(): void {
		$svg        = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="40"/></svg>';
		$round_trip = CaseBridge::restore( CaseBridge::normalize( $svg ) );

		$this->assertStringContainsString( 'viewBox=', $round_trip );
		$this->assertStringNotContainsString( 'viewbox=', $round_trip );
	}

	/**
	 * normalize() lowercases a camelCase attribute name so wp_kses() can match it.
	 */
	public function test_normalize_lowercases_camelcase(): void {
		$svg        = '<svg viewBox="0 0 10 10"><circle r="5"/></svg>';
		$normalized = CaseBridge::normalize( $svg );

		$this->assertStringContainsString( 'viewbox=', $normalized );
		$this->assertStringNotContainsString( 'viewBox=', $normalized );
	}

	/** An empty string passes through both passes unchanged. */
	public function test_empty_string_unchanged(): void {
		$this->assertSame( '', CaseBridge::normalize( '' ) );
		$this->assertSame( '', CaseBridge::restore( '' ) );
	}

	// -----------------------------------------------------------------------
	// Value-safety: the rewrite must NEVER touch attribute values or text.
	//
	// These are the regressions that a naive (unmasked) regex would introduce.
	// They are the reason quoted values are masked before the name lookup runs.
	// -----------------------------------------------------------------------

	/**
	 * A value equal to a camelCase name must not be rewritten.
	 *
	 * fill="viewBox" must keep the value "viewBox" untouched; only attribute
	 * names are subject to case rewriting.
	 */
	public function test_value_equal_to_camelcase_name_is_untouched(): void {
		$svg        = '<rect fill="viewBox" width="10"/>';
		$round_trip = CaseBridge::restore( CaseBridge::normalize( $svg ) );

		$this->assertStringContainsString( 'fill="viewBox"', $round_trip );
	}

	/**
	 * A camelCase token followed by "=" *inside* a quoted value is untouched.
	 *
	 * This is the adversarial case that breaks an unmasked regex: the substring
	 * " viewBox=" lives inside the font-family value and must survive verbatim.
	 */
	public function test_camelcase_inside_value_is_untouched(): void {
		$svg        = '<text font-family="a viewBox=b">x</text>';
		$round_trip = CaseBridge::restore( CaseBridge::normalize( $svg ) );

		$this->assertStringContainsString( 'font-family="a viewBox=b"', $round_trip );
	}

	/** The same protection applies to single-quoted values. */
	public function test_camelcase_inside_single_quoted_value_is_untouched(): void {
		$svg        = "<text font-family='a viewBox=b'>x</text>";
		$round_trip = CaseBridge::restore( CaseBridge::normalize( $svg ) );

		$this->assertStringContainsString( "font-family='a viewBox=b'", $round_trip );
	}

	/** Element text content containing a camelCase token is never rewritten. */
	public function test_text_content_is_untouched(): void {
		$svg        = '<text>preserveAspectRatio=xMidYMid</text>';
		$round_trip = CaseBridge::restore( CaseBridge::normalize( $svg ) );

		$this->assertStringContainsString( 'preserveAspectRatio=xMidYMid', $round_trip );
	}

	/** Multiple camelCase attributes on one element all round-trip correctly. */
	public function test_multiple_camelcase_attributes(): void {
		$svg        = '<svg viewBox="0 0 1 1" preserveAspectRatio="none"><rect/></svg>';
		$round_trip = CaseBridge::restore( CaseBridge::normalize( $svg ) );

		$this->assertStringContainsString( 'viewBox=', $round_trip );
		$this->assertStringContainsString( 'preserveAspectRatio=', $round_trip );
		$this->assertStringNotContainsString( 'viewbox=', $round_trip );
		$this->assertStringNotContainsString( 'preserveaspectratio=', $round_trip );
	}

	// -----------------------------------------------------------------------
	// Spec-conformance guard.
	//
	// CaseBridge uses the hand-maintained Allowlist::case_map() table instead
	// of WP_HTML_Processor::get_qualified_attribute_name() for speed.  This test
	// pins every *attribute* entry in case_map() to the canonical name the HTML
	// API reports, so the table can never silently drift from the spec mapping.
	//
	// Tag-name entries are excluded: get_qualified_attribute_name() maps only
	// attribute names, and wp_kses() itself preserves tag-name case, so the
	// HTML API is not the authority for those.
	// -----------------------------------------------------------------------

	/**
	 * Every attribute entry in case_map() must match the HTML API's canonical form.
	 *
	 * @requires extension dom
	 */
	public function test_case_map_attributes_match_html_api(): void {
		if ( ! class_exists( \WP_HTML_Processor::class ) ) {
			$this->markTestSkipped( 'WP_HTML_Processor not available in this environment.' );
		}

		foreach ( Allowlist::case_map() as $lowercase => $canonical ) {
			$processor = \WP_HTML_Processor::create_fragment( '<svg ' . $lowercase . '="x"></svg>' );

			if ( ! $processor || ! $processor->next_tag() ) {
				$this->fail( "Could not parse fragment for '{$lowercase}'." );
			}

			$api = $processor->get_qualified_attribute_name( $lowercase );

			// The HTML API reports the lowercase form for SVG tag names (it maps
			// attribute names only). Skip entries the API does not camelCase —
			// those are tag-name entries kept for documentation, validated
			// instead by the round-trip tests above.
			if ( $api === $lowercase ) {
				continue;
			}

			$this->assertSame(
				$api,
				$canonical,
				"case_map()['{$lowercase}'] must match the HTML API canonical name."
			);
		}
	}
}
