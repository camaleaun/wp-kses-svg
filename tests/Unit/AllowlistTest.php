<?php
/**
 * Unit tests for Allowlist.
 *
 * Verifies that the allowlist structure mirrors the wp_kses() contract and
 * that no known dangerous tags or attributes are present.
 *
 * @package WpKsesSvg\Tests\Unit
 */

declare( strict_types=1 );

namespace WpKsesSvg\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WpKsesSvg\Sanitizer\Allowlist;

/**
 * @covers \WpKsesSvg\Sanitizer\Allowlist
 */
class AllowlistTest extends TestCase {

	// -----------------------------------------------------------------------
	// Structure.
	// -----------------------------------------------------------------------

	/** The return value of get() must be a non-empty array. */
	public function test_get_returns_non_empty_array(): void {
		$this->assertNotEmpty( Allowlist::get() );
	}

	/** Every value in get() must be an array (the attributes map). */
	public function test_get_values_are_arrays(): void {
		foreach ( Allowlist::get() as $tag => $attrs ) {
			$this->assertIsArray( $attrs, "Tag '{$tag}' must map to an array of attributes." );
		}
	}

	/** Every attribute value inside a tag map must be boolean true. */
	public function test_attribute_values_are_true(): void {
		foreach ( Allowlist::get() as $tag => $attrs ) {
			foreach ( $attrs as $attr => $value ) {
				$this->assertTrue( $value, "Attribute '{$attr}' on tag '{$tag}' must be true." );
			}
		}
	}

	/**
	 * All tag keys must be lowercase so wp_kses() can match them.
	 * camelCase is handled by normalize_case() / restore_case() in Sanitizer.
	 */
	public function test_tag_keys_are_all_lowercase(): void {
		foreach ( array_keys( Allowlist::get() ) as $tag ) {
			$this->assertSame(
				strtolower( $tag ),
				$tag,
				"Tag key '{$tag}' must be lowercase in the allowlist."
			);
		}
	}

	// -----------------------------------------------------------------------
	// Required safe elements.
	// -----------------------------------------------------------------------

	/** The root <svg> element must be in the allowlist. */
	public function test_svg_root_is_allowed(): void {
		$this->assertArrayHasKey( 'svg', Allowlist::get() );
	}

	/**
	 * Core shape elements required for any practical SVG.
	 *
	 * @dataProvider provider_required_shape_tags
	 */
	public function test_required_shape_tags_are_allowed( string $tag ): void {
		$this->assertArrayHasKey( $tag, Allowlist::get(), "Shape tag '{$tag}' must be allowed." );
	}

	/** @return array<string, array{string}> */
	public static function provider_required_shape_tags(): array {
		return [
			'circle'   => [ 'circle' ],
			'ellipse'  => [ 'ellipse' ],
			'line'     => [ 'line' ],
			'path'     => [ 'path' ],
			'polygon'  => [ 'polygon' ],
			'polyline' => [ 'polyline' ],
			'rect'     => [ 'rect' ],
		];
	}

	/**
	 * Accessibility elements must be present.
	 *
	 * @dataProvider provider_accessibility_tags
	 */
	public function test_accessibility_tags_are_allowed( string $tag ): void {
		$this->assertArrayHasKey( $tag, Allowlist::get(), "Accessibility tag '{$tag}' must be allowed." );
	}

	/** @return array<string, array{string}> */
	public static function provider_accessibility_tags(): array {
		return [
			'title' => [ 'title' ],
			'desc'  => [ 'desc' ],
		];
	}

	/** Shared presentation attributes must appear on the <svg> root. */
	public function test_presentation_attrs_on_svg(): void {
		$svg_attrs = Allowlist::get()['svg'] ?? [];

		foreach ( [ 'fill', 'stroke', 'opacity', 'transform', 'class', 'id' ] as $attr ) {
			$this->assertArrayHasKey( $attr, $svg_attrs, "Presentation attr '{$attr}' must be on <svg>." );
		}
	}

	// -----------------------------------------------------------------------
	// Blocked / dangerous elements.
	// -----------------------------------------------------------------------

	/**
	 * Explicitly dangerous tags must NOT appear in the allowlist.
	 *
	 * @dataProvider provider_blocked_tags
	 */
	public function test_blocked_tags_not_in_allowlist( string $tag ): void {
		$this->assertArrayNotHasKey( $tag, Allowlist::get(), "Dangerous tag '{$tag}' must NOT be in the allowlist." );
	}

	/** @return array<string, array{string}> */
	public static function provider_blocked_tags(): array {
		return [
			'script'        => [ 'script' ],
			'handler'       => [ 'handler' ],
			'foreignObject' => [ 'foreignObject' ],
			'image'         => [ 'image' ],
			'feImage'       => [ 'feImage' ],
		];
	}

	/** blocked_tags() must return a non-empty array. */
	public function test_blocked_tags_method_returns_non_empty_array(): void {
		$this->assertNotEmpty( Allowlist::blocked_tags() );
	}

	/** Every entry in blocked_tags() must be a non-empty string. */
	public function test_blocked_tags_are_strings(): void {
		foreach ( Allowlist::blocked_tags() as $tag ) {
			$this->assertIsString( $tag );
			$this->assertNotEmpty( $tag );
		}
	}

	// -----------------------------------------------------------------------
	// Fragment reference attrs.
	// -----------------------------------------------------------------------

	/**
	 * Elements that carry href / xlink:href must declare those attributes so
	 * wp_kses() does not strip them before our fragment validator runs.
	 *
	 * @dataProvider provider_href_elements
	 */
	public function test_href_attrs_declared_on_reference_elements( string $tag ): void {
		$attrs = Allowlist::get()[ $tag ] ?? [];
		$this->assertTrue(
			isset( $attrs['href'] ) || isset( $attrs['xlink:href'] ),
			"Tag '{$tag}' should declare href or xlink:href."
		);
	}

	/** @return array<string, array{string}> */
	public static function provider_href_elements(): array {
		return [
			'use'      => [ 'use' ],
			'mpath'    => [ 'mpath' ],
			'textpath' => [ 'textpath' ],  // allowlist key is lowercase; canonical form is textPath.
		];
	}

	// -----------------------------------------------------------------------
	// All attribute keys must also be lowercase.
	// -----------------------------------------------------------------------

	/** Every attribute key in every tag map must be lowercase. */
	public function test_attribute_keys_are_all_lowercase(): void {
		foreach ( Allowlist::get() as $tag => $attrs ) {
			foreach ( array_keys( $attrs ) as $attr ) {
				// xlink:href and xml:space use a namespace prefix — normalise after colon.
				$this->assertSame(
					strtolower( $attr ),
					$attr,
					"Attribute '{$attr}' on tag '{$tag}' must be lowercase in the allowlist."
				);
			}
		}
	}

	// -----------------------------------------------------------------------
	// case_map() contract.
	// -----------------------------------------------------------------------

	/** case_map() must return a non-empty array. */
	public function test_case_map_returns_non_empty_array(): void {
		$this->assertNotEmpty( Allowlist::case_map() );
	}

	/** Every key in case_map() must be the lowercase form of its value. */
	public function test_case_map_keys_are_lowercase_of_values(): void {
		foreach ( Allowlist::case_map() as $lowercase => $canonical ) {
			$this->assertSame(
				strtolower( $canonical ),
				$lowercase,
				"case_map key '{$lowercase}' must equal strtolower('{$canonical}')."
			);
		}
	}

	/** Every canonical value in case_map() must contain at least one uppercase letter. */
	public function test_case_map_values_contain_uppercase(): void {
		foreach ( Allowlist::case_map() as $lowercase => $canonical ) {
			$this->assertNotSame(
				strtolower( $canonical ),
				$canonical,
				"case_map value '{$canonical}' must have at least one uppercase letter."
			);
		}
	}

	/** Key SVG camelCase attributes must be in case_map(). */
	public function test_case_map_includes_core_camelcase_attrs(): void {
		$map = Allowlist::case_map();

		foreach ( [ 'viewbox', 'preserveaspectratio', 'gradientunits', 'lineargradient', 'pathlength' ] as $key ) {
			$this->assertArrayHasKey( $key, $map, "case_map must include '{$key}'." );
		}
	}

	// -----------------------------------------------------------------------
	// presentation_attrs() helper.
	// -----------------------------------------------------------------------

	/** presentation_attrs() must return a non-empty array. */
	public function test_presentation_attrs_returns_non_empty_array(): void {
		$this->assertNotEmpty( Allowlist::presentation_attrs() );
	}

	/** presentation_attrs() must include the most common visual properties. */
	public function test_presentation_attrs_includes_core_properties(): void {
		$attrs = Allowlist::presentation_attrs();

		foreach ( [ 'fill', 'stroke', 'opacity', 'transform', 'style' ] as $attr ) {
			$this->assertArrayHasKey( $attr, $attrs, "presentation_attrs() must include '{$attr}'." );
		}
	}

	// -----------------------------------------------------------------------
	// <a> element.
	// -----------------------------------------------------------------------

	/**
	 * The <a> tag must be in the allowlist (navigation links are legitimate SVG).
	 *
	 * javascript: / data: / vbscript: are blocked upstream by Layer 3 and by
	 * wp_kses() via wp_allowed_protocols(). The allowlist presence of <a> is
	 * the explicit design decision to preserve https:// links.
	 */
	public function test_anchor_tag_in_allowlist(): void {
		$tags = Allowlist::get();
		$this->assertArrayHasKey( 'a', $tags, '<a> must be in the allowlist.' );
	}

	/** The <a> entry must include href. */
	public function test_anchor_has_href_attr(): void {
		$attrs = Allowlist::get()['a'];
		$this->assertArrayHasKey( 'href', $attrs );
	}

	/** The <a> entry must include xlink:href for SVG 1.1 compatibility. */
	public function test_anchor_has_xlink_href_attr(): void {
		$attrs = Allowlist::get()['a'];
		$this->assertArrayHasKey( 'xlink:href', $attrs );
	}

	/** The <a> tag key must be lowercase (wp_kses requirement). */
	public function test_anchor_key_is_lowercase(): void {
		$tags = array_keys( Allowlist::get() );
		$this->assertContains( 'a', $tags );
		$this->assertNotContains( 'A', $tags );
	}
}
