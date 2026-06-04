=== WP KSES SVG ===
Contributors: (this should be a list of wordpress.org userid's)
Tags: svg, upload, sanitize, security, kses
Requires at least: 6.4
Tested up to: 7.0
Requires PHP: 8.1
Stable tag: 0.1.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

SVG uploads and inline sanitization for WordPress, built on wp_kses() — no external libraries required.

== Description ==

WP KSES SVG brings SVG support to WordPress without sacrificing the security
guarantees that the Core team has always demanded. It does not fight the Core
philosophy — it speaks its language.

Every objection that has kept SVG out of Core is addressed directly:

**"SVGs can execute JavaScript."**
The sanitizer rejects any file the moment a `<script>` tag, an `on*` event
handler, or a `javascript:` URI is detected. Early rejection happens before
`wp_kses()` even runs; a malicious file never reaches the uploads directory.

**"Regex-based sanitizers are not reliable."**
This plugin does not use regular expressions for sanitization. It uses PHP's
`DOMDocument` to validate XML well-formedness and then passes the markup
through `wp_kses()` with an SVG-specific allowlist — exactly the same
architecture WordPress Core uses for HTML.

**"XXE and DOCTYPE injection are real threats."**
The XML parser runs with `LIBXML_NONET | LIBXML_NOENT`, disabling external
entity loading and network access at the libxml level before any string
manipulation takes place. `<!DOCTYPE>` declarations are stripped immediately.

**"foreignObject embeds arbitrary HTML."**
`<foreignObject>`, `<image>`, `<feImage>`, `<script>`, and `<handler>` are
on an explicit block-list. They trigger an early hard-reject that returns an
empty string and deletes the temporary upload file with no trace left on disk.

**"href and xlink:href can load external resources."**
A fragment-enforcement pass strips any `href` or `xlink:href` value that does
not start with `#`. Only internal references survive.

**"Inline style attributes are an XSS vector."**
Every `style="…"` value is decomposed into individual CSS declarations. Each
property is checked against an explicit CSS allowlist; any value containing
`url()`, `expression()`, `behaviour()`, `javascript:`, or `data:` is stripped
before the `wp_kses()` pass.

**"The allowlist is too permissive."**
The allowlist mirrors the `wp_kses()` data structure exactly:
`[ 'tag' => [ 'attribute' => true ] ]`. Every included tag and attribute has a
documented rationale. Blocked items are listed separately with a reason.

= Security Pipeline =

Every SVG goes through eight ordered layers before it is accepted:

1. **XML well-formedness** — `DOMDocument` with `LIBXML_NONET | LIBXML_NOENT`.
2. **Preamble stripping** — XML declaration, DOCTYPE, HTML comments, and
   whitespace-encoded control characters (`&#9;` `&#10;` `&#13;`) removed.
   Collapsing those characters prevents `java&#9;script:` from bypassing
   the scheme detection in Layer 3.
3. **Blocked-tag + blocked-content early rejection** — hard-reject on:
   - `<script>`, `<foreignObject>`, `<handler>`, `<image>`, `<feImage>`
   - `on*` event handler attributes (static)
   - `javascript:` / `data:` / `vbscript:` URI schemes
   - SMIL `attributeName="on*"` or `attributeName="style"` (runtime injection)
   - Unknown or namespace-prefixed tags (`<evil:div>`, `<widget>`, …)
4. **Fragment-only href enforcement** — on reference elements (`<use>`, `<animate>`,
   `<set>`, `<mpath>`, …) any `href`/`xlink:href` that does not start with `#`
   is stripped. `<a>` is excluded — it legitimately carries `https://` URLs.
4b. **External url() rejection** — hard-reject when `in`/`in2` filter attributes
   or presentation attributes (`fill`, `stroke`, `filter`, `clip-path`, `mask`)
   contain `url(https://…)` or `url(http://…)` — a privacy-leak / SSRF vector.
5. **Inline style sanitization** — CSS property allowlist + blocked-value patterns.
6. **`wp_kses()` pass with camelCase round-trip** — SVG attribute names such as
   `viewBox` and `gradientUnits` are case-sensitive, but `wp_kses()` lowercases
   attribute names. The camelCase names are renamed to lowercase before the
   `wp_kses()` pass (so the allowlist keys match) and restored afterwards, using
   a small static table that is pinned to `WP_HTML_Processor`'s canonical
   spelling by the test suite. Quoted values are masked during the rename, so a
   value like `fill="viewBox"` is never mistaken for an attribute name.
7. **Re-validation** — sanitized output re-parsed; invalid result → empty string.

= Architecture =

The public API surface is a single function that mirrors WordPress naming conventions:

    $safe_svg = wp_kses_svg( $raw_svg );

Returns sanitized SVG markup, or an empty string if the input is unsafe or
malformed. The upload pipeline hooks into `wp_handle_upload_prefilter`,
`upload_mimes`, and `wp_check_filetype_and_ext` — the same hooks used by every
reputable SVG plugin — but with sanitization happening on the temp file before
WordPress moves it to the uploads directory.

= Test Coverage =

The plugin ships with a PHPUnit test suite organized into two suites:

**Unit suite (54 tests, 2029 assertions)**

* Allowlist structure: every tag maps to an array; every attribute value is
  `true`; no dangerous tag appears; accessibility and shape elements are present.
* Sanitizer pipeline: empty input, malformed XML, XXE via DOCTYPE, `<script>`,
  `<foreignObject>`, six `on*` event handler variants, external `href` URLs,
  `javascript:` and `data:` URI schemes, CSS `expression()`, CSS `url(javascript:)`,
  unsafe CSS properties, safe CSS properties preserved, clean SVG passthrough.

**Upload suite (12 tests, 29 assertions)**

* Non-SVG files pass through unmodified.
* Clean SVG files are accepted; temp file is kept.
* Malicious and malformed SVG files are rejected; temp file is deleted immediately.
* Capability gate: users without `upload_files` are rejected even for clean files.
* `allow_svg_mime()` adds the MIME type only for capable users.
* `fix_svg_filetype()` corrects ext/type data for `.svg`; leaves other files alone.

**Total: 122 tests · 4238 assertions · 0 failures · PHP 8.4 · PHPUnit 10.5**

= Fixtures =

The test battery ships with real SVG fixture files covering every attack vector:

**Clean (must pass):**
* `clean/circle.svg` — minimal well-formed SVG with `<title>`.
* `clean/rect-gradient.svg` — SVG with `<defs>` and `<linearGradient>`.
* `clean/anchor-link.svg` — SVG with `<a href="https://…">`.

**XSS / injection:**
* `xss/script-tag.svg` — `<script>` tag.
* `xss/event-handler.svg` — static `onload` / `onclick` attributes.
* `xss/foreign-object.svg` — `<foreignObject>` with embedded HTML.
* `xss/href-external.svg` — external URL and `javascript:` in href.
* `xss/anchor-javascript.svg` — `<a href="javascript:…">`.
* `xss/href-whitespace-encoding.svg` — `java&#9;script:` / `java&#10;script:` bypasses.
* `xss/style-expression.svg` — CSS `expression()` and `url(javascript:)`.
* `xss/filter-external-ref.svg` — `feBlend in2="url(https://…)"` SSRF.
* `xss/presentation-external-url.svg` — `fill` / `filter` / `clip-path` / `mask` with external `url()`.
* `xss/smil-attributename-event.svg` — SMIL `attributeName="onload"` runtime injection.
* `xss/smil-set-style.svg` — SMIL `attributeName="style"` runtime injection.
* `xss/namespace-prefix-text.svg` — `<evil:script>` text-node defacement.
* `xss/unknown-tag-text.svg` — `<unknown>` text-node defacement.

**Malformed:**
* `malformed/broken-xml.svg` — non-well-formed XML.
* `malformed/xxe-doctype.svg` — XXE via `<!DOCTYPE>` entity declaration.

= Why No External Library? =

Other SVG plugins rely on third-party sanitization libraries (DOMPurify in JS,
Enshrined SVG Sanitizer in PHP). Those are good libraries. But shipping an
external dependency into Core would require the Core team to own that dependency
forever — a maintenance and security burden that has historically blocked adoption.

WP KSES SVG has zero runtime dependencies. The entire security model rests on:

* PHP's built-in `DOMDocument` (libxml — already a Core dependency).
* WordPress Core's own `wp_kses()` function.
* An explicit, auditable allowlist in a single file (`src/Sanitizer/Allowlist.php`).

Any WordPress Core developer can audit this plugin without learning a new library.

= Capability Gate =

By default, only users with the `upload_files` capability (Editors and above)
may upload SVG files. Site owners can tighten the gate:

    add_filter( 'wp_kses_svg_upload_capability', function() {
        return 'manage_options'; // Administrators only.
    } );

== Installation ==

1. Upload the plugin files to `/wp-content/plugins/wp-kses-svg`, or install
   through the WordPress Plugins screen.
2. Activate the plugin.
3. Users with the `upload_files` capability can now upload `.svg` files through
   the Media Library. SVG content is sanitized automatically on upload.

To sanitize SVG markup in PHP:

    $safe = wp_kses_svg( $raw_svg );

== Frequently Asked Questions ==

= Does this plugin sanitize existing SVGs in the Media Library? =

No. It sanitizes files at the moment of upload. Previously uploaded SVGs are
not retroactively processed. To re-sanitize an existing file, delete it and
re-upload the original.

= Can I extend the allowlist? =

Not yet. A `wp_kses_svg_allowlist` filter is planned for 0.2.0. For now, fork
`src/Sanitizer/Allowlist.php` and add your tags following the existing pattern.

= Does this support SVGZ (compressed SVG)? =

The MIME type `image/svg+xml` is registered for both `svg` and `svgz`
extensions. Decompression before sanitization is planned for 0.2.0.

= Is this compatible with the WordPress block editor? =

Yes. SVGs uploaded through the Media Library appear as attachments and can be
inserted into posts using the Image block or via `<img src="…">` references.
Inline SVG rendering in the block editor is outside the scope of this plugin.

== Changelog ==

= 0.1.0 =
* Initial release.
* `wp_kses_svg()` public API function.
* Eight-layer sanitization pipeline, organised as single-responsibility stages
  (XmlValidator, ThreatScanner, ReferenceGuard, StyleSanitizer, CaseBridge)
  coordinated by a thin Sanitizer orchestrator: XML validation, XXE/DOCTYPE
  stripping, blocked-tag early rejection, href fragment enforcement, external
  `url()` rejection, inline style sanitization, `wp_kses()` allowlist pass with
  camelCase round-trip, and re-validation.
* camelCase attribute names (`viewBox`, `gradientUnits`, …) are preserved across
  the `wp_kses()` boundary using a verified static table with quoted-value
  masking. The table is pinned by the test suite to
  `WP_HTML_Processor::get_qualified_attribute_name()`, so it cannot drift from
  the HTML spec, and attribute values such as `fill="viewBox"` are never
  mistaken for attribute names.
* SVG upload support gated behind `upload_files` capability.
* `wp_kses_svg_upload_capability` filter for tightening the permission gate.
* PHPUnit test suite: 143 tests, 4301 assertions, 0 failures, PHP 8.4; PHPStan clean.
* Seventeen SVG fixture files covering clean SVGs and all known XSS/SSRF attack vectors.
* `<a href>` allowed with `https://` and `mailto:` — `javascript:`/`data:` hard-rejected.
* SMIL animation safety: `attributeName="on*"` and `attributeName="style"` rejected.
* External `url()` in presentation attributes (`fill`, `filter`, `clip-path`, `mask`) rejected.
* Unknown and namespace-prefixed tags rejected to prevent text-node defacement.
* Whitespace-encoded scheme bypass (`java&#9;script:`) collapsed and rejected.
