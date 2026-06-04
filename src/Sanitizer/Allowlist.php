<?php
/**
 * SVG Allowlist — allowed tags and attributes.
 *
 * Intentionally mirrors the wp_kses() Core architecture:
 * every entry is [ 'tag' => [ 'attr' => true ] ].
 *
 * Inclusion rules:
 *   ✔ Tag/attribute has a legitimate use documented in the SVG 1.1 / SVG 2 spec.
 *   ✔ Does not execute code (no <script>, no on* event handlers).
 *   ✔ Does not load arbitrary external resources (no <image xlink:href="http:...">).
 *   ✔ Does not reference external entities (blocked at the DOMDocument level).
 *
 * Tags intentionally omitted:
 *   ✗ <script>        — code execution.
 *   ✗ <handler>       — code execution (SVG 1.2 Tiny).
 *   ✗ <foreignObject> — embeds arbitrary HTML.
 *   ✗ <image>         — may reference external URLs; needs extra validation layer.
 *   ✗ <feImage>       — same concern as <image>.
 *
 * Tags included with restrictions:
 *   ✔ <a href>    — allowed with href restricted to https?:// and mailto: only.
 *                   javascript: and data: are rejected by ReferenceGuard and
 *                   the ThreatScanner deny-first pre-screen.
 *
 * Case-normalisation contract:
 *   wp_kses() lowercases both tag keys and attribute keys when matching.
 *   All keys in this file are therefore lowercase so wp_kses() can match them.
 *   CaseBridge::normalize() / restore() handles the round-trip so the output
 *   preserves the original SVG camelCase attribute names.  The canonical
 *   camelCase forms are also enumerated in case_map() for reviewer reference.
 *
 * @package WpKsesSvg\Sanitizer
 * @since   0.1.0
 */

namespace WpKsesSvg\Sanitizer;

defined( 'ABSPATH' ) || exit;

/**
 * Provides the SVG safe-tag/attribute allowlist.
 *
 * @since 0.1.0
 */
class Allowlist {

	/**
	 * Memoised copy of the full tag => attributes allowlist.
	 *
	 * The get() method is invoked once per sanitize() pass (by wp_kses) and the array is
	 * structurally constant, so building it a single time and reusing the cached
	 * copy removes redundant array construction from the hot path.
	 *
	 * @since 0.1.0
	 * @var array<string, array<string, true>>|null
	 */
	private static ?array $allowlist_cache = null;

	/**
	 * Memoised set of allowed tag names, lowercased, as a fast O(1) lookup map.
	 *
	 * Shape: [ 'svg' => true, 'circle' => true, ... ].  Used by the threat
	 * scanner to test "is this tag known?" without rebuilding array_keys() +
	 * array_map('strtolower', ...) on every call.
	 *
	 * @since 0.1.0
	 * @var array<string, true>|null
	 */
	private static ?array $tag_lookup_cache = null;

	// -----------------------------------------------------------------------
	// Shared presentation attributes.
	// All keys are lowercase so wp_kses() can match them.
	// -----------------------------------------------------------------------

	/**
	 * Property type.
	 *
	 * @var array<string, true>
	 */
	private const PRESENTATION = array(
		'id'                  => true,
		'class'               => true,
		'lang'                => true,
		'tabindex'            => true,
		'role'                => true,
		'aria-label'          => true,
		'aria-labelledby'     => true,
		'aria-describedby'    => true,
		'aria-hidden'         => true,
		'transform'           => true,
		'x'                   => true,
		'y'                   => true,
		'width'               => true,
		'height'              => true,
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
		'color-interpolation' => true,
		'color-rendering'     => true,
		'shape-rendering'     => true,
		'image-rendering'     => true,
		'text-rendering'      => true,
		'vector-effect'       => true,
		'paint-order'         => true,
		'style'               => true,
	);

	/**
	 * Property type.
	 *
	 * @var array<string, true>
	 */
	private const GRADIENT = array(
		'gradientunits'     => true,  // canonical: gradientUnits.
		'gradienttransform' => true,  // canonical: gradientTransform.
		'spreadmethod'      => true,  // canonical: spreadMethod.
		'x1'                => true,
		'y1'                => true,
		'x2'                => true,
		'y2'                => true,
		'cx'                => true,
		'cy'                => true,
		'r'                 => true,
		'fx'                => true,
		'fy'                => true,
		'href'              => true,
		'xlink:href'        => true,
	);

	// -----------------------------------------------------------------------
	// Main allowlist — all keys lowercase, comments note canonical form.
	// -----------------------------------------------------------------------

	/**
	 * Returns the full tag => attributes map, ready for wp_kses().
	 *
	 * The result is memoised: the structure is constant for the lifetime of the
	 * request, so it is built once and the cached copy is returned thereafter.
	 *
	 * @since  0.1.0
	 * @return array<string, array<string, true>>
	 */
	public static function get(): array {
		if ( null !== self::$allowlist_cache ) {
			return self::$allowlist_cache;
		}

		self::$allowlist_cache = self::build();

		return self::$allowlist_cache;
	}

	/**
	 * Returns the set of allowed tag names as a lowercase O(1) lookup map.
	 *
	 * Shape: [ 'svg' => true, 'circle' => true, ... ].  Memoised so the
	 * lowercasing pass over the tag keys happens at most once per request.
	 *
	 * @since  0.1.0
	 * @return array<string, true>
	 */
	public static function tag_lookup(): array {
		if ( null !== self::$tag_lookup_cache ) {
			return self::$tag_lookup_cache;
		}

		$lookup = array();
		foreach ( array_keys( self::get() ) as $tag ) {
			$lookup[ strtolower( $tag ) ] = true;
		}

		self::$tag_lookup_cache = $lookup;

		return self::$tag_lookup_cache;
	}

	/**
	 * Build the full tag => attributes map.
	 *
	 * Separated from get() so the construction logic stays pure and the caching
	 * concern lives entirely in get().
	 *
	 * @since  0.1.0
	 * @return array<string, array<string, true>>
	 */
	private static function build(): array {
		$p = self::PRESENTATION;

		return array(
			'svg'                 => array_merge(
				$p,
				array(
					'xmlns'               => true,
					'xmlns:xlink'         => true,
					'version'             => true,
					'viewbox'             => true,  // canonical: viewBox.
					'preserveaspectratio' => true,  // canonical: preserveAspectRatio.
					'xml:space'           => true,
					'title'               => true,
				)
			),

			'title'               => array( 'id' => true ),
			'desc'                => array( 'id' => true ),

			'g'                   => $p,
			'defs'                => $p,

			'symbol'              => array_merge(
				$p,
				array(
					'viewbox'             => true,  // canonical: viewBox.
					'preserveaspectratio' => true,  // canonical: preserveAspectRatio.
					'refx'                => true,  // canonical: refX.
					'refy'                => true,  // canonical: refY.
				)
			),

			'use'                 => array_merge(
				$p,
				array(
					'href'       => true,
					'xlink:href' => true,
				)
			),

			'switch'              => $p,

			'circle'              => array_merge(
				$p,
				array(
					'cx'         => true,
					'cy'         => true,
					'r'          => true,
					'pathlength' => true,
				)
			),
			'ellipse'             => array_merge(
				$p,
				array(
					'cx'         => true,
					'cy'         => true,
					'rx'         => true,
					'ry'         => true,
					'pathlength' => true,
				)
			),
			'line'                => array_merge(
				$p,
				array(
					'x1'         => true,
					'y1'         => true,
					'x2'         => true,
					'y2'         => true,
					'pathlength' => true,
				)
			),
			'path'                => array_merge(
				$p,
				array(
					'd'          => true,
					'pathlength' => true,
				)
			),
			'polygon'             => array_merge(
				$p,
				array(
					'points'     => true,
					'pathlength' => true,
				)
			),
			'polyline'            => array_merge(
				$p,
				array(
					'points'     => true,
					'pathlength' => true,
				)
			),
			'rect'                => array_merge(
				$p,
				array(
					'rx'         => true,
					'ry'         => true,
					'pathlength' => true,
				)
			),

			'text'                => array_merge(
				$p,
				array(
					'dx'                => true,
					'dy'                => true,
					'rotate'            => true,
					'textlength'        => true,  // canonical: textLength.
					'lengthadjust'      => true,  // canonical: lengthAdjust.
					'text-anchor'       => true,
					'dominant-baseline' => true,
					'font-family'       => true,
					'font-size'         => true,
					'font-style'        => true,
					'font-weight'       => true,
					'letter-spacing'    => true,
					'word-spacing'      => true,
					'text-decoration'   => true,
					'writing-mode'      => true,
				)
			),

			'tspan'               => array_merge(
				$p,
				array(
					'dx'                => true,
					'dy'                => true,
					'rotate'            => true,
					'textlength'        => true,
					'lengthadjust'      => true,
					'text-anchor'       => true,
					'dominant-baseline' => true,
					'font-family'       => true,
					'font-size'         => true,
					'font-style'        => true,
					'font-weight'       => true,
				)
			),

			'textpath'            => array_merge(
				$p,
				array(  // canonical tag: textPath.
					'href'         => true,
					'xlink:href'   => true,
					'startoffset'  => true,  // canonical: startOffset.
					'method'       => true,
					'spacing'      => true,
					'textlength'   => true,
					'lengthadjust' => true,
				)
			),

			'lineargradient'      => array_merge( $p, self::GRADIENT ),  // canonical: linearGradient.
			'radialgradient'      => array_merge( $p, self::GRADIENT ),  // canonical: radialGradient.

			'stop'                => array_merge(
				$p,
				array(
					'offset'       => true,
					'stop-color'   => true,
					'stop-opacity' => true,
				)
			),

			'pattern'             => array_merge(
				$p,
				array(
					'patternunits'        => true,  // canonical: patternUnits.
					'patterncontentunits' => true,  // canonical: patternContentUnits.
					'patterntransform'    => true,  // canonical: patternTransform.
					'viewbox'             => true,
					'preserveaspectratio' => true,
				)
			),

			'mask'                => array_merge(
				$p,
				array(
					'maskunits'        => true,  // canonical: maskUnits.
					'maskcontentunits' => true,  // canonical: maskContentUnits.
				)
			),
			'clippath'            => array_merge( $p, array( 'clippathunits' => true ) ),  // canonical tag: clipPath.

			'filter'              => array_merge(
				$p,
				array(
					'filterunits'    => true,  // canonical: filterUnits.
					'primitiveunits' => true,  // canonical: primitiveUnits.
				)
			),

			'feblend'             => array_merge(
				$p,
				array(
					'in'     => true,
					'in2'    => true,
					'mode'   => true,
					'result' => true,
				)
			),
			'fecolormatrix'       => array_merge(
				$p,
				array(
					'in'     => true,
					'type'   => true,
					'values' => true,
					'result' => true,
				)
			),
			'fecomposite'         => array_merge(
				$p,
				array(
					'in'       => true,
					'in2'      => true,
					'operator' => true,
					'k1'       => true,
					'k2'       => true,
					'k3'       => true,
					'k4'       => true,
					'result'   => true,
				)
			),
			'feflood'             => array_merge(
				$p,
				array(
					'flood-color'   => true,
					'flood-opacity' => true,
					'result'        => true,
				)
			),
			'fegaussianblur'      => array_merge(
				$p,
				array(
					'in'           => true,
					'stddeviation' => true,
					'edgemode'     => true,
					'result'       => true,
				)
			),
			'femerge'             => array_merge( $p, array( 'result' => true ) ),
			'femergenode'         => array( 'in' => true ),
			'feoffset'            => array_merge(
				$p,
				array(
					'in'     => true,
					'dx'     => true,
					'dy'     => true,
					'result' => true,
				)
			),
			'feturbulence'        => array_merge(
				$p,
				array(
					'type'          => true,
					'basefrequency' => true,
					'numoctaves'    => true,
					'seed'          => true,
					'stitchtiles'   => true,
					'result'        => true,
				)
			),
			'femorphology'        => array_merge(
				$p,
				array(
					'in'       => true,
					'operator' => true,
					'radius'   => true,
					'result'   => true,
				)
			),
			'fedisplacementmap'   => array_merge(
				$p,
				array(
					'in'               => true,
					'in2'              => true,
					'scale'            => true,
					'xchannelselector' => true,
					'ychannelselector' => true,
					'result'           => true,
				)
			),
			'fecomponenttransfer' => array_merge(
				$p,
				array(
					'in'     => true,
					'result' => true,
				)
			),

			'fefuncr'             => array(
				'type'        => true,
				'tablevalues' => true,
				'slope'       => true,
				'intercept'   => true,
				'amplitude'   => true,
				'exponent'    => true,
				'offset'      => true,
			),
			'fefuncg'             => array(
				'type'        => true,
				'tablevalues' => true,
				'slope'       => true,
				'intercept'   => true,
				'amplitude'   => true,
				'exponent'    => true,
				'offset'      => true,
			),
			'fefuncb'             => array(
				'type'        => true,
				'tablevalues' => true,
				'slope'       => true,
				'intercept'   => true,
				'amplitude'   => true,
				'exponent'    => true,
				'offset'      => true,
			),
			'fefunca'             => array(
				'type'        => true,
				'tablevalues' => true,
				'slope'       => true,
				'intercept'   => true,
				'amplitude'   => true,
				'exponent'    => true,
				'offset'      => true,
			),

			'animate'             => array_merge(
				$p,
				array(
					'attributename' => true,
					'from'          => true,
					'to'            => true,
					'values'        => true,
					'dur'           => true,
					'begin'         => true,
					'end'           => true,
					'repeatcount'   => true,
					'repeatdur'     => true,
					'calcmode'      => true,
					'keytimes'      => true,
					'keysplines'    => true,
					'fill'          => true,
					'additive'      => true,
					'accumulate'    => true,
				)
			),

			'animatetransform'    => array_merge(
				$p,
				array(  // canonical: animateTransform.
					'attributename' => true,
					'type'          => true,
					'from'          => true,
					'to'            => true,
					'values'        => true,
					'dur'           => true,
					'begin'         => true,
					'end'           => true,
					'repeatcount'   => true,
					'repeatdur'     => true,
					'calcmode'      => true,
					'keytimes'      => true,
					'keysplines'    => true,
					'additive'      => true,
					'accumulate'    => true,
				)
			),

			'animatemotion'       => array_merge(
				$p,
				array(  // canonical: animateMotion.
					'path'        => true,
					'keypoints'   => true,
					'rotate'      => true,
					'origin'      => true,
					'dur'         => true,
					'begin'       => true,
					'end'         => true,
					'repeatcount' => true,
					'repeatdur'   => true,
					'calcmode'    => true,
					'keytimes'    => true,
				)
			),

			'mpath'               => array(
				'href'       => true,
				'xlink:href' => true,
			),

			'set'                 => array_merge(
				$p,
				array(
					'attributename' => true,
					'to'            => true,
					'dur'           => true,
					'begin'         => true,
					'end'           => true,
					'repeatcount'   => true,
				)
			),

			'marker'              => array_merge(
				$p,
				array(
					'markerunits'         => true,  // canonical: markerUnits.
					'markerwidth'         => true,  // canonical: markerWidth.
					'markerheight'        => true,  // canonical: markerHeight.
					'orient'              => true,
					'refx'                => true,  // canonical: refX.
					'refy'                => true,  // canonical: refY.
					'viewbox'             => true,
					'preserveaspectratio' => true,
				)
			),

			'metadata'            => array(),

			// <a> with href restricted to https?:// and mailto: only.
			// javascript: / data: / vbscript: are blocked upstream by.
			// enforce_fragment_refs() and contains_blocked_tags().
			// wp_kses() strips href values for protocols not in wp_allowed_protocols().
			'a'                   => array_merge(
				$p,
				array(
					'href'       => true,
					'xlink:href' => true,
					'target'     => true,
					'rel'        => true,
					'tabindex'   => true,
					'aria-label' => true,
				)
			),
		);
	}

	// -----------------------------------------------------------------------
	// Case normalisation map.
	// -----------------------------------------------------------------------

	/**
	 * Bidirectional map: lowercase => canonical SVG camelCase.
	 *
	 * Used by Sanitizer::normalize_case() before wp_kses() and
	 * Sanitizer::restore_case() after wp_kses() to round-trip camelCase
	 * attribute and tag names that wp_kses() would permanently lowercase.
	 *
	 * @since  0.1.0
	 * @return array<string, string>
	 */
	public static function case_map(): array {
		return array(
			// Attributes.
			'viewbox'             => 'viewBox',
			'preserveaspectratio' => 'preserveAspectRatio',
			'gradientunits'       => 'gradientUnits',
			'gradienttransform'   => 'gradientTransform',
			'spreadmethod'        => 'spreadMethod',
			'patternunits'        => 'patternUnits',
			'patterncontentunits' => 'patternContentUnits',
			'patterntransform'    => 'patternTransform',
			'maskunits'           => 'maskUnits',
			'maskcontentunits'    => 'maskContentUnits',
			'clippathunits'       => 'clipPathUnits',
			'filterunits'         => 'filterUnits',
			'primitiveunits'      => 'primitiveUnits',
			'markerunits'         => 'markerUnits',
			'markerwidth'         => 'markerWidth',
			'markerheight'        => 'markerHeight',
			'refx'                => 'refX',
			'refy'                => 'refY',
			'pathlength'          => 'pathLength',
			'textlength'          => 'textLength',
			'lengthadjust'        => 'lengthAdjust',
			'startoffset'         => 'startOffset',
			'attributename'       => 'attributeName',
			'repeatcount'         => 'repeatCount',
			'repeatdur'           => 'repeatDur',
			'calcmode'            => 'calcMode',
			'keytimes'            => 'keyTimes',
			'keysplines'          => 'keySplines',
			'keypoints'           => 'keyPoints',
			'basefrequency'       => 'baseFrequency',
			'numoctaves'          => 'numOctaves',
			'stitchtiles'         => 'stitchTiles',
			'stddeviation'        => 'stdDeviation',
			'edgemode'            => 'edgeMode',
			'tablevalues'         => 'tableValues',
			'xchannelselector'    => 'xChannelSelector',
			'ychannelselector'    => 'yChannelSelector',

			// Tag names.
			'lineargradient'      => 'linearGradient',
			'radialgradient'      => 'radialGradient',
			'clippath'            => 'clipPath',
			'textpath'            => 'textPath',
			'animatetransform'    => 'animateTransform',
			'animatemotion'       => 'animateMotion',
			'feblend'             => 'feBlend',
			'fecolormatrix'       => 'feColorMatrix',
			'fecomposite'         => 'feComposite',
			'feflood'             => 'feFlood',
			'fegaussianblur'      => 'feGaussianBlur',
			'femerge'             => 'feMerge',
			'femergenode'         => 'feMergeNode',
			'feoffset'            => 'feOffset',
			'feturbulence'        => 'feTurbulence',
			'femorphology'        => 'feMorphology',
			'fedisplacementmap'   => 'feDisplacementMap',
			'fecomponenttransfer' => 'feComponentTransfer',
			'fefuncr'             => 'feFuncR',
			'fefuncg'             => 'feFuncG',
			'fefuncb'             => 'feFuncB',
			'fefunca'             => 'feFuncA',
		);
	}

	// -----------------------------------------------------------------------
	// Helpers.
	// -----------------------------------------------------------------------

	/**
	 * Returns the shared presentation attributes array.
	 *
	 * @since  0.1.0
	 * @return array<string, true>
	 */
	public static function presentation_attrs(): array {
		return self::PRESENTATION;
	}

	/**
	 * Tags that are explicitly blocked.
	 *
	 * These never reach wp_kses(); listed here for documentation and for the
	 * Sanitizer's early-rejection pass.
	 *
	 * @since  0.1.0
	 * @return string[]
	 */
	public static function blocked_tags(): array {
		return array(
			'script',        // Code execution.
			'handler',       // Code execution (SVG 1.2 Tiny).
			'foreignObject', // Embeds arbitrary HTML.
			'image',         // May reference external URLs.
			'feImage',       // Same concern as <image>.
		);
	}
}
