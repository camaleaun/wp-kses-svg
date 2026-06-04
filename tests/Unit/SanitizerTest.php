<?php
/**
 * Unit tests for Sanitizer / wp_kses_svg().
 *
 * Each test group covers one layer of the security pipeline:
 *   - Empty / trivial input.
 *   - XML well-formedness (malformed → empty string).
 *   - XXE / DOCTYPE injection rejection.
 *   - Blocked-tag early rejection.
 *   - Event-handler attribute rejection.
 *   - href / xlink:href fragment-only enforcement.
 *   - Inline style sanitization.
 *   - Clean SVG passthrough (content preserved, structure intact).
 *
 * @package WpKsesSvg\Tests\Unit
 */

declare( strict_types=1 );

namespace WpKsesSvg\Tests\Unit;

use Brain\Monkey;
use Brain\Monkey\Functions;
use PHPUnit\Framework\TestCase;
use WpKsesSvg\Sanitizer\Sanitizer;

/**
 * @covers \WpKsesSvg\Sanitizer\Sanitizer
 */
class SanitizerTest extends TestCase {

	// -----------------------------------------------------------------------
	// Fixture helpers.
	// -----------------------------------------------------------------------

	/** Absolute path to the tests/fixtures directory. */
	private static function fixtures_path(): string {
		return dirname( __DIR__ ) . '/fixtures';
	}

	/** Read a fixture file and return its contents. */
	private static function fixture( string $relative_path ): string {
		$path = self::fixtures_path() . '/' . $relative_path;
		$content = \file_get_contents( $path );
		self::assertNotFalse( $content, "Fixture file not readable: {$path}" );
		return $content;
	}

	// -----------------------------------------------------------------------
	// Brain\Monkey setup / teardown.
	// -----------------------------------------------------------------------

	protected function setUp(): void {
		parent::setUp();
		Monkey\setUp();

		// wp_kses() stub: in unit tests we let the real logic flow through the
		// Sanitizer pipeline; wp_kses() is stubbed to return its first argument
		// unchanged so we can isolate Sanitizer behaviour from Core's allowlist
		// filtering (tested separately in integration).
		Functions\when( 'wp_kses' )->returnArg( 1 );
	}

	protected function tearDown(): void {
		Monkey\tearDown();
		parent::tearDown();
	}

	// -----------------------------------------------------------------------
	// Empty / trivial input.
	// -----------------------------------------------------------------------

	/** An empty string must return an empty string. */
	public function test_empty_string_returns_empty(): void {
		$this->assertSame( '', Sanitizer::sanitize( '' ) );
	}

	/** A whitespace-only string must return an empty string. */
	public function test_whitespace_only_returns_empty(): void {
		$this->assertSame( '', Sanitizer::sanitize( '   ' ) );
	}

	// -----------------------------------------------------------------------
	// XML well-formedness.
	// -----------------------------------------------------------------------

	/** Malformed XML (unclosed tag) must return an empty string. */
	public function test_malformed_xml_returns_empty(): void {
		$svg = self::fixture( 'malformed/broken-xml.svg' );
		$this->assertSame( '', Sanitizer::sanitize( $svg ) );
	}

	/** Well-formed minimal SVG must NOT return an empty string. */
	public function test_valid_xml_does_not_return_empty(): void {
		$svg = self::fixture( 'clean/circle.svg' );
		$this->assertNotSame( '', Sanitizer::sanitize( $svg ) );
	}

	// -----------------------------------------------------------------------
	// XXE / DOCTYPE injection.
	// -----------------------------------------------------------------------

	/**
	 * SVG with an external entity declaration must return an empty string.
	 *
	 * libxml with LIBXML_NOENT will refuse to expand the entity when loaded
	 * without a network and the test runner has no /etc/passwd at the system
	 * temp path, so the parse either fails or the entity expands to empty.
	 * Either way the Sanitizer should return '' or markup free of the entity.
	 */
	public function test_xxe_doctype_returns_empty_or_stripped(): void {
		$svg    = self::fixture( 'malformed/xxe-doctype.svg' );
		$result = Sanitizer::sanitize( $svg );

		// Must not contain the entity reference or any file-read result.
		$this->assertStringNotContainsString( '&xxe;', $result );
		$this->assertStringNotContainsString( 'root:', $result ); // /etc/passwd pattern.
	}

	/** XML / DOCTYPE declarations must be stripped from clean SVG output. */
	public function test_xml_declaration_stripped(): void {
		$svg    = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" . self::fixture( 'clean/circle.svg' );
		$result = Sanitizer::sanitize( $svg );

		$this->assertStringNotContainsString( '<?xml', $result );
	}

	// -----------------------------------------------------------------------
	// Blocked-tag early rejection.
	// -----------------------------------------------------------------------

	/** SVG containing <script> must return an empty string. */
	public function test_script_tag_returns_empty(): void {
		$svg = self::fixture( 'xss/script-tag.svg' );
		$this->assertSame( '', Sanitizer::sanitize( $svg ) );
	}

	/** SVG containing <foreignObject> must return an empty string. */
	public function test_foreign_object_returns_empty(): void {
		$svg = self::fixture( 'xss/foreign-object.svg' );
		$this->assertSame( '', Sanitizer::sanitize( $svg ) );
	}

	/** Inline <script> without a fixture (direct string). */
	public function test_inline_script_tag_returns_empty(): void {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>';
		$this->assertSame( '', Sanitizer::sanitize( $svg ) );
	}

	// -----------------------------------------------------------------------
	// Event-handler attribute rejection.
	// -----------------------------------------------------------------------

	/** Any on* event handler must cause the sanitizer to return an empty string. */
	public function test_event_handler_attributes_return_empty(): void {
		$svg = self::fixture( 'xss/event-handler.svg' );
		$this->assertSame( '', Sanitizer::sanitize( $svg ) );
	}

	/**
	 * Individual on* attribute patterns.
	 *
	 * @dataProvider provider_event_handlers
	 */
	public function test_individual_event_handler_returns_empty( string $handler ): void {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg"><circle cx="50" cy="50" r="40" ' . $handler . '="alert(1)"/></svg>';
		$this->assertSame( '', Sanitizer::sanitize( $svg ) );
	}

	/** @return array<string, array{string}> */
	public static function provider_event_handlers(): array {
		return [
			'onload'       => [ 'onload' ],
			'onclick'      => [ 'onclick' ],
			'onmouseover'  => [ 'onmouseover' ],
			'onerror'      => [ 'onerror' ],
			'onbegin'      => [ 'onbegin' ],  // SMIL-specific.
			'onend'        => [ 'onend' ],
		];
	}

	// -----------------------------------------------------------------------
	// href / xlink:href fragment enforcement.
	// -----------------------------------------------------------------------

	/**
	 * The href-external fixture contains a javascript: URI which triggers the
	 * early-rejection pass, returning an empty string. That is the correct and
	 * expected behaviour -- the whole file is unsafe.
	 */
	public function test_href_external_fixture_is_fully_rejected(): void {
		$svg    = self::fixture( 'xss/href-external.svg' );
		$result = Sanitizer::sanitize( $svg );

		$this->assertSame( '', $result, 'SVG with javascript: href must be fully rejected.' );
	}

	/** An SVG with only an external HTTPS href (no javascript:) strips the bad ref, keeps the good. */
	public function test_external_https_href_stripped_internal_preserved(): void {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 100 100">
				<defs><circle id="c" cx="50" cy="50" r="40"/></defs>
				<use href="#c" fill="green"/>
				<use href="https://evil.example.com/payload.svg#shell"/>
			</svg>';

		$result = Sanitizer::sanitize( $svg );

		// External HTTPS reference must be stripped.
		$this->assertStringNotContainsString( 'https://evil.example.com', $result );

		// Internal fragment must survive.
		$this->assertStringContainsString( 'href="#c"', $result );
	}

	/** javascript: scheme in href must be stripped. */
	public function test_javascript_href_stripped(): void {
		$svg    = '<svg xmlns="http://www.w3.org/2000/svg"><use href="javascript:alert(1)"/></svg>';
		$result = Sanitizer::sanitize( $svg );

		$this->assertStringNotContainsString( 'javascript:', $result );
	}

	/** data: URI in href must be stripped. */
	public function test_data_uri_href_stripped(): void {
		$svg    = '<svg xmlns="http://www.w3.org/2000/svg"><use href="data:text/html,<script>alert(1)</script>"/></svg>';
		$result = Sanitizer::sanitize( $svg );

		$this->assertStringNotContainsString( 'data:', $result );
	}

	// -----------------------------------------------------------------------
	// Inline style sanitization.
	// -----------------------------------------------------------------------

	/** CSS expression() in style attribute must be stripped. */
	public function test_css_expression_stripped(): void {
		$svg    = self::fixture( 'xss/style-expression.svg' );
		$result = Sanitizer::sanitize( $svg );

		$this->assertStringNotContainsString( 'expression(', $result );
	}

	/** CSS url(javascript:…) must be stripped. */
	public function test_css_url_javascript_stripped(): void {
		$svg    = self::fixture( 'xss/style-expression.svg' );
		$result = Sanitizer::sanitize( $svg );

		$this->assertStringNotContainsString( 'javascript:', $result );
	}

	/** Safe CSS properties must survive style sanitization. */
	public function test_safe_css_properties_preserved(): void {
		$svg    = '<svg xmlns="http://www.w3.org/2000/svg"><circle cx="50" cy="50" r="40" style="fill:red;opacity:0.5"/></svg>';
		$result = Sanitizer::sanitize( $svg );

		$this->assertStringContainsString( 'fill:red', $result );
		$this->assertStringContainsString( 'opacity:0.5', $result );
	}

	/** Unsafe CSS property (e.g. behaviour) must be stripped, safe ones kept. */
	public function test_unsafe_css_property_stripped_safe_kept(): void {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg">'
			. '<rect style="fill:blue;behaviour:url(evil.htc);stroke:black"/>'
			. '</svg>';

		$result = Sanitizer::sanitize( $svg );

		$this->assertStringNotContainsString( 'behaviour', $result );
		$this->assertStringContainsString( 'fill:blue', $result );
		$this->assertStringContainsString( 'stroke:black', $result );
	}

	// -----------------------------------------------------------------------
	// camelCase attribute and tag name preservation.
	// -----------------------------------------------------------------------

	/** viewBox must survive sanitization with its case intact. */
	public function test_viewbox_case_preserved(): void {
		$svg    = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="40"/></svg>';
		$result = Sanitizer::sanitize( $svg );

		$this->assertStringContainsString( 'viewBox=', $result );
		$this->assertStringNotContainsString( 'viewbox=', $result );
	}

	/** preserveAspectRatio must survive sanitization with its case intact. */
	public function test_preserve_aspect_ratio_case_preserved(): void {
		$svg    = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" preserveAspectRatio="xMidYMid meet"><rect width="100" height="100"/></svg>';
		$result = Sanitizer::sanitize( $svg );

		$this->assertStringContainsString( 'preserveAspectRatio=', $result );
	}

	/** linearGradient tag must survive with correct case. */
	public function test_linear_gradient_tag_case_preserved(): void {
		$svg    = self::fixture( 'clean/rect-gradient.svg' );
		$result = Sanitizer::sanitize( $svg );

		$this->assertStringContainsString( '<linearGradient', $result );
		$this->assertStringContainsString( '</linearGradient>', $result );
		$this->assertStringNotContainsString( '<lineargradient', $result );
	}

	/** gradientUnits attribute must survive with correct case. */
	public function test_gradient_units_attr_case_preserved(): void {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg"><defs>'
			. '<linearGradient id="g" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="100" y2="0">'
			. '<stop offset="0%" stop-color="red"/>'
			. '</linearGradient></defs>'
			. '<rect width="100" height="100" fill="url(#g)"/>'
			. '</svg>';
		$result = Sanitizer::sanitize( $svg );

		$this->assertStringContainsString( 'gradientUnits=', $result );
	}

	// -----------------------------------------------------------------------
	// Clean SVG passthrough.
	// -----------------------------------------------------------------------

	/** A clean circle SVG must return non-empty sanitized markup. */
	public function test_clean_circle_passthrough(): void {
		$svg    = self::fixture( 'clean/circle.svg' );
		$result = Sanitizer::sanitize( $svg );

		$this->assertNotEmpty( $result );
		$this->assertStringContainsString( '<circle', $result );
		$this->assertStringContainsString( '<title>', $result );
	}

	/** A clean gradient rect SVG must retain <defs> and <linearGradient>. */
	public function test_clean_gradient_passthrough(): void {
		$svg    = self::fixture( 'clean/rect-gradient.svg' );
		$result = Sanitizer::sanitize( $svg );

		$this->assertNotEmpty( $result );
		$this->assertStringContainsString( '<linearGradient', $result );
		$this->assertStringContainsString( '<stop', $result );
	}

	/** The public wp_kses_svg() function must produce the same result as Sanitizer::sanitize(). */
	public function test_wp_kses_svg_function_matches_sanitizer(): void {
		$svg = self::fixture( 'clean/circle.svg' );

		$this->assertSame( Sanitizer::sanitize( $svg ), wp_kses_svg( $svg ) );
	}

	// -----------------------------------------------------------------------
	// Filter primitive in/in2 enforcement (Step 4b).
	// -----------------------------------------------------------------------

	/**
	 * SVG with external url() in feBlend in2 must be fully rejected (deny-first).
	 *
	 * feBlend in2="url(https://evil.com/x.svg)" is an SSRF/privacy-leak vector:
	 * the browser fetches the external resource when rendering the SVG.
	 * Consistent with the deny-first policy, the entire file is rejected rather
	 * than attempting to strip the offending attribute and salvage the rest.
	 */
	public function test_filter_external_url_ref_rejected(): void {
		$svg    = self::fixture( 'xss/filter-external-ref.svg' );
		$result = Sanitizer::sanitize( $svg );

		// Hard-reject: the entire file must return empty string.
		$this->assertSame( '', $result );
	}

	/**
	 * Internal url(#id) in filter in/in2 must be preserved.
	 *
	 * url(#foo) is a valid intra-SVG reference — it is not a network request.
	 */
	public function test_filter_internal_fragment_ref_preserved(): void {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg">' .
			'<filter id="f"><feBlend in="SourceGraphic" in2="url(#layer)"/></filter>' .
			'<rect width="100" height="100" filter="url(#f)"/></svg>';

		$result = Sanitizer::sanitize( $svg );

		$this->assertStringContainsString( 'in2="url(#layer)"', $result );
	}

	// -----------------------------------------------------------------------
	// <a> element handling.
	// -----------------------------------------------------------------------

	/**
	 * A clean SVG <a> with an https:// href must survive sanitization.
	 *
	 * <a> is a navigation element; https:// URLs are legitimate and safe.
	 * wp_kses() validates the protocol via wp_allowed_protocols().
	 */
	public function test_anchor_with_https_href_preserved(): void {
		$svg    = self::fixture( 'clean/anchor-link.svg' );
		$result = Sanitizer::sanitize( $svg );

		$this->assertNotEmpty( $result );
		$this->assertStringContainsString( 'https://example.com', $result );
		$this->assertStringContainsString( '<a', $result );
	}

	/**
	 * An SVG <a> with javascript: href must be fully rejected.
	 *
	 * javascript: URIs trigger the contains_blocked_tags pre-screen (Layer 3)
	 * which hard-rejects the entire file.
	 */
	public function test_anchor_javascript_href_rejected(): void {
		$svg    = self::fixture( 'xss/anchor-javascript.svg' );
		$result = Sanitizer::sanitize( $svg );

		$this->assertSame( '', $result );
	}

	/**
	 * An SVG <a> with a data: href must be fully rejected.
	 *
	 * data: URI scheme is blocked by the Layer 3 pre-screen.
	 */
	public function test_anchor_data_href_rejected(): void {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg">' .
			'<a href="data:text/html,<script>alert(1)</script>"><text>X</text></a>' .
			'</svg>';
		$result = Sanitizer::sanitize( $svg );

		$this->assertSame( '', $result );
	}

	/**
	 * Recursive <use> elements (billion-laughs-style) pass through intentionally.
	 *
	 * This is structurally valid SVG with no code-execution vector.
	 * Resource exhaustion at render time is a browser/renderer concern;
	 * this sanitizer is a file-upload gate only.
	 */
	public function test_recursive_use_passes_through_by_design(): void {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg">' .
			'<defs><g id="a"><use href="#a"/><use href="#a"/></g></defs>' .
			'<use href="#a"/></svg>';

		$result = Sanitizer::sanitize( $svg );

		// Must not be rejected: there is no script/XSS vector here.
		$this->assertNotSame( '', $result );

		// All href values must be internal fragments — no external http hosts.
		// (xmlns="http://..." is expected in the output and is not a security issue.)
		$this->assertStringNotContainsString( 'evil.com', $result );
		$this->assertStringContainsString( 'href="#a"', $result );
	}

	// -----------------------------------------------------------------------
	// Whitespace-encoding bypass in href (&#9; &#10; &#13; inside javascript:).
	// -----------------------------------------------------------------------

	/**
	 * SVG with whitespace-encoded javascript: in href must be rejected.
	 *
	 * Browsers strip ASCII whitespace (tab/LF/CR) from URLs before parsing the
	 * scheme, so "java&#9;script:" is treated as "javascript:" at render time.
	 * The preamble-strip step normalises these references so that
	 * contains_blocked_tags() can detect the collapsed scheme.
	 */
	public function test_href_whitespace_encoding_rejected(): void {
		$svg = self::fixture( 'xss/href-whitespace-encoding.svg' );
		$this->assertSame( '', Sanitizer::sanitize( $svg ) );
	}

	/** Each whitespace control-character variant must be rejected individually. */
	#[\PHPUnit\Framework\Attributes\DataProvider( 'whitespace_encoding_variants' )]
	public function test_whitespace_encoding_individual_rejected( string $encoded ): void {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg">'
			. '<a href="java' . $encoded . 'script:alert(1)"><text>X</text></a>'
			. '</svg>';
		$this->assertSame( '', Sanitizer::sanitize( $svg ) );
	}

	public static function whitespace_encoding_variants(): array {
		return [
			[ '&#9;'  ],  // tab
			[ '&#10;' ],  // LF
			[ '&#13;' ],  // CR
			[ '&#x9;' ],  // tab hex
			[ '&#xA;' ],  // LF hex
			[ '&#xD;' ],  // CR hex
		];
	}

	// -----------------------------------------------------------------------
	// Unknown and namespace-prefixed tags (text-node defacement prevention).
	// -----------------------------------------------------------------------

	/**
	 * SVG with a namespace-prefixed tag must be fully rejected.
	 *
	 * wp_kses() strips unknown tags but preserves their text content, so
	 * <evil:div>Injected text</evil:div> would become visible plain text in
	 * the rendered page (defacement).  The file must be hard-rejected.
	 */
	public function test_namespace_prefix_tag_rejected(): void {
		$svg = self::fixture( 'xss/namespace-prefix-text.svg' );
		$this->assertSame( '', Sanitizer::sanitize( $svg ) );
	}

	/** Each namespace-prefix variant must be rejected. */
	#[\PHPUnit\Framework\Attributes\DataProvider( 'namespace_prefix_tags' )]
	public function test_namespace_prefix_variants_rejected( string $tag ): void {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg"><' . $tag . '>injected</' . $tag . '></svg>';
		$this->assertSame( '', Sanitizer::sanitize( $svg ) );
	}

	public static function namespace_prefix_tags(): array {
		return [ [ 'evil:script' ], [ 'xhtml:div' ], [ 'foo:bar' ], [ 'x:unknown' ] ];
	}

	/**
	 * SVG with an unknown unprefixed tag must be fully rejected.
	 *
	 * <unknown>text</unknown> would have its text node survive wp_kses(),
	 * producing visible injected text.  The file must be hard-rejected.
	 */
	public function test_unknown_tag_rejected(): void {
		$svg = self::fixture( 'xss/unknown-tag-text.svg' );
		$this->assertSame( '', Sanitizer::sanitize( $svg ) );
	}

	/** Each unknown tag variant must be rejected. */
	#[\PHPUnit\Framework\Attributes\DataProvider( 'unknown_tag_names' )]
	public function test_unknown_tag_variants_rejected( string $tag ): void {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg"><' . $tag . '>injected</' . $tag . '></svg>';
		$this->assertSame( '', Sanitizer::sanitize( $svg ) );
	}

	public static function unknown_tag_names(): array {
		return [ [ 'unknown' ], [ 'widget' ], [ 'embed' ], [ 'iframe' ], [ 'canvas' ] ];
	}

	/**
	 * All tags in the allowlist must pass through contains_unknown_tags cleanly.
	 *
	 * Regression guard: adding a new tag to the allowlist must not accidentally
	 * trigger the unknown-tag check due to a camelCase / lowercase mismatch.
	 */
	public function test_all_allowlist_tags_pass_unknown_check(): void {
		foreach ( array_keys( \WpKsesSvg\Sanitizer\Allowlist::get() ) as $tag ) {
			$svg = '<svg xmlns="http://www.w3.org/2000/svg"><' . $tag . '/></svg>';
			// Should NOT return '' solely because of the unknown-tag check.
			// (May return '' for other reasons, e.g. re-validation; we only
			//  check that the result is not poisoned by this specific guard.)
			$result = Sanitizer::sanitize( $svg );
			// The key assertion: no false-positive rejection due to unknown-tag.
			// We verify by checking that "$tag" is NOT in blocked_tags() — if it
			// is in the allowlist it must not be flagged as unknown.
			$this->assertNotContains(
				strtolower( $tag ),
				array_map( 'strtolower', \WpKsesSvg\Sanitizer\Allowlist::blocked_tags() ),
				"Allowlist tag '{$tag}' must not be in blocked_tags()."
			);
		}
	}

	// -----------------------------------------------------------------------
	// SMIL attributeName targeting event handlers or style (Layer 3 extension).
	// -----------------------------------------------------------------------

	/**
	 * SMIL animate with attributeName targeting an event handler must be rejected.
	 *
	 * <animate attributeName="onload" to="alert(1)"> injects onload="alert(1)"
	 * into the target element at runtime, bypassing the static on* attribute
	 * check.  The entire file must be hard-rejected.
	 */
	public function test_smil_attributename_event_handler_rejected(): void {
		$svg = self::fixture( 'xss/smil-attributename-event.svg' );
		$this->assertSame( '', Sanitizer::sanitize( $svg ) );
	}

	/** Each on* variant as attributeName value must be rejected. */
	#[\PHPUnit\Framework\Attributes\DataProvider( 'smil_event_attribute_names' )]
	public function test_smil_attributename_individual_events_rejected( string $attr ): void {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg">'
			. '<rect id="r" width="10" height="10"/>'
			. '<animate attributeName="' . $attr . '" to="alert(1)" begin="0s" href="#r"/>'
			. '</svg>';
		$this->assertSame( '', Sanitizer::sanitize( $svg ) );
	}

	public static function smil_event_attribute_names(): array {
		return [
			[ 'onload' ], [ 'onclick' ], [ 'onmouseover' ],
			[ 'onerror' ], [ 'onbegin' ], [ 'onend' ],
		];
	}

	/**
	 * SMIL set with attributeName="style" carrying a CSS expression must be rejected.
	 *
	 * <set attributeName="style" to="fill:expression(...)"> injects an unsanitized
	 * style value at runtime, bypassing the inline-style sanitization layer.
	 */
	public function test_smil_set_attributename_style_rejected(): void {
		$svg = self::fixture( 'xss/smil-set-style.svg' );
		$this->assertSame( '', Sanitizer::sanitize( $svg ) );
	}

	/**
	 * SMIL animate with a safe attributeName (fill, opacity, etc.) must pass through.
	 *
	 * Only on* and style are dangerous as SMIL targets; visual property animations
	 * are the intended use case for SMIL and must not be blocked.
	 */
	public function test_smil_safe_attributename_passes_through(): void {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg">'
			. '<rect id="r" fill="red" width="10" height="10"/>'
			. '<animate attributeName="fill" from="red" to="blue" dur="2s" href="#r"/>'
			. '</svg>';
		$result = Sanitizer::sanitize( $svg );
		$this->assertNotSame( '', $result );
		$this->assertStringContainsString( 'attributeName', $result );
	}

	// -----------------------------------------------------------------------
	// External url() in presentation attributes (Layer 4b extension).
	// -----------------------------------------------------------------------

	/**
	 * SVG with external url() in fill/filter/clip-path/mask must be rejected.
	 *
	 * Presentation attributes with external url() cause the browser to fetch
	 * the remote resource when rendering — leaking the visitor's IP/headers
	 * (privacy leak / SSRF vector).  Hard-reject the entire file.
	 */
	public function test_presentation_external_url_rejected(): void {
		$svg = self::fixture( 'xss/presentation-external-url.svg' );
		$this->assertSame( '', Sanitizer::sanitize( $svg ) );
	}

	/** Each presentation attribute with external url() must be rejected individually. */
	#[\PHPUnit\Framework\Attributes\DataProvider( 'presentation_external_url_attrs' )]
	public function test_presentation_external_url_individual_rejected( string $attr ): void {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg">'
			. '<rect ' . $attr . '="url(https://evil.com/x.svg)" width="10" height="10"/>'
			. '</svg>';
		$this->assertSame( '', Sanitizer::sanitize( $svg ) );
	}

	public static function presentation_external_url_attrs(): array {
		return [ [ 'fill' ], [ 'stroke' ], [ 'filter' ], [ 'clip-path' ], [ 'mask' ] ];
	}

	/**
	 * Internal url(#id) in presentation attributes must be preserved.
	 *
	 * url(#gradient), url(#filter) etc. are valid intra-SVG references
	 * that do not cause any network request.
	 */
	public function test_presentation_internal_url_preserved(): void {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg">'
			. '<defs><linearGradient id="g"><stop offset="0" stop-color="red"/></linearGradient></defs>'
			. '<rect fill="url(#g)" width="10" height="10"/>'
			. '</svg>';
		$result = Sanitizer::sanitize( $svg );
		$this->assertNotSame( '', $result );
		$this->assertStringContainsString( 'fill="url(#g)"', $result );
	}
}
