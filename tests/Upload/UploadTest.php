<?php
/**
 * Upload pipeline tests for UploadFilter.
 *
 * Uses a real temporary file on disk to simulate WordPress's $_FILES array,
 * verifying that:
 *   - Clean SVG files are accepted and their content optionally overwritten.
 *   - Malicious / malformed SVG files are rejected (error key set, temp file deleted).
 *   - Non-SVG files are passed through untouched.
 *   - The capability gate prevents unprivileged uploads.
 *
 * @package WpKsesSvg\Tests\Upload
 */

declare( strict_types=1 );

namespace WpKsesSvg\Tests\Upload;

use Brain\Monkey;
use Brain\Monkey\Functions;
use PHPUnit\Framework\TestCase;
use WpKsesSvg\Upload\UploadFilter;

/**
 * @covers \WpKsesSvg\Upload\UploadFilter
 */
class UploadTest extends TestCase {

	// -----------------------------------------------------------------------
	// Fixture helpers.
	// -----------------------------------------------------------------------

	private static function fixtures_path(): string {
		return dirname( __DIR__ ) . '/fixtures';
	}

	private static function fixture_contents( string $relative ): string {
		$path    = self::fixtures_path() . '/' . $relative;
		$content = \file_get_contents( $path );
		self::assertNotFalse( $content, "Fixture not readable: {$path}" );
		return $content;
	}

	/**
	 * Write $contents to a real temp file and return its path.
	 * The test must call unlink() if the filter doesn't delete it first.
	 */
	private function make_temp_file( string $contents ): string {
		$path = tempnam( sys_get_temp_dir(), 'wp_kses_svg_test_' );
		\file_put_contents( $path, $contents );
		return $path;
	}

	/**
	 * Build a minimal $_FILES-like array.
	 *
	 * Note: 'error' is intentionally omitted here. WordPress's real $_FILES
	 * entry has error=UPLOAD_ERR_OK (0) but the UploadFilter only reads
	 * 'name' and 'tmp_name'. Tests assert that the filter does NOT add the
	 * 'error' key (rejection signal) — having no key at all is the clearest
	 * way to assert that without confusion with the upload-error numeric field.
	 *
	 * @param string $tmp_path  Absolute path to the temp file.
	 * @param string $filename  Original filename (used for extension detection).
	 * @return array<string, string>
	 */
	private function make_file_array( string $tmp_path, string $filename = 'test.svg' ): array {
		return [
			'name'     => $filename,
			'type'     => 'image/svg+xml',
			'tmp_name' => $tmp_path,
			'size'     => (string) filesize( $tmp_path ),
		];
	}

	// -----------------------------------------------------------------------
	// Brain\Monkey setup / teardown.
	// -----------------------------------------------------------------------

	protected function setUp(): void {
		parent::setUp();
		Monkey\setUp();

		// wp_kses() — pass through first arg in upload tests so Sanitizer logic runs.
		Functions\when( 'wp_kses' )->returnArg( 1 );

		// apply_filters — return second arg (the value) unchanged.
		Functions\when( 'apply_filters' )->returnArg( 2 );

		// __() — return first arg unchanged.
		Functions\when( '__' )->returnArg( 1 );
	}

	protected function tearDown(): void {
		Monkey\tearDown();
		parent::tearDown();
	}

	// -----------------------------------------------------------------------
	// Non-SVG files — must pass through untouched.
	// -----------------------------------------------------------------------

	/** A PNG upload must not be touched by the filter. */
	public function test_non_svg_file_passes_through(): void {
		Functions\when( 'current_user_can' )->justReturn( true );

		$tmp  = $this->make_temp_file( "\x89PNG\r\n\x1a\n" );
		$file = $this->make_file_array( $tmp, 'photo.png' );

		$result = UploadFilter::sanitize_on_upload( $file );

		$this->assertArrayNotHasKey( 'error', $result );
		$this->assertSame( $file['tmp_name'], $result['tmp_name'] );

		@unlink( $tmp );
	}

	// -----------------------------------------------------------------------
	// Clean SVG — must be accepted.
	// -----------------------------------------------------------------------

	/** A clean, well-formed SVG must be accepted (no error key). */
	public function test_clean_svg_accepted(): void {
		Functions\when( 'current_user_can' )->justReturn( true );

		$tmp  = $this->make_temp_file( self::fixture_contents( 'clean/circle.svg' ) );
		$file = $this->make_file_array( $tmp );

		$result = UploadFilter::sanitize_on_upload( $file );

		$this->assertArrayNotHasKey( 'error', $result, 'Clean SVG must not trigger an error.' );
		$this->assertFileExists( $tmp, 'Temp file must NOT be deleted for a clean upload.' );

		@unlink( $tmp );
	}

	/** A clean gradient SVG must also be accepted. */
	public function test_clean_gradient_svg_accepted(): void {
		Functions\when( 'current_user_can' )->justReturn( true );

		$tmp  = $this->make_temp_file( self::fixture_contents( 'clean/rect-gradient.svg' ) );
		$file = $this->make_file_array( $tmp, 'gradient.svg' );

		$result = UploadFilter::sanitize_on_upload( $file );

		$this->assertArrayNotHasKey( 'error', $result );

		@unlink( $tmp );
	}

	// -----------------------------------------------------------------------
	// Malicious SVG — must be rejected.
	// -----------------------------------------------------------------------

	/** An SVG with <script> must be rejected and the temp file deleted. */
	public function test_script_tag_svg_rejected(): void {
		Functions\when( 'current_user_can' )->justReturn( true );

		$tmp  = $this->make_temp_file( self::fixture_contents( 'xss/script-tag.svg' ) );
		$file = $this->make_file_array( $tmp );

		$result = UploadFilter::sanitize_on_upload( $file );

		$this->assertArrayHasKey( 'error', $result, 'Malicious SVG must set the error key.' );
		$this->assertNotEmpty( $result['error'] );
		$this->assertFileDoesNotExist( $tmp, 'Temp file must be deleted after rejection.' );
	}

	/** An SVG with event handler attributes must be rejected. */
	public function test_event_handler_svg_rejected(): void {
		Functions\when( 'current_user_can' )->justReturn( true );

		$tmp  = $this->make_temp_file( self::fixture_contents( 'xss/event-handler.svg' ) );
		$file = $this->make_file_array( $tmp );

		$result = UploadFilter::sanitize_on_upload( $file );

		$this->assertArrayHasKey( 'error', $result );
		$this->assertFileDoesNotExist( $tmp );
	}

	/** An SVG with <foreignObject> must be rejected. */
	public function test_foreign_object_svg_rejected(): void {
		Functions\when( 'current_user_can' )->justReturn( true );

		$tmp  = $this->make_temp_file( self::fixture_contents( 'xss/foreign-object.svg' ) );
		$file = $this->make_file_array( $tmp );

		$result = UploadFilter::sanitize_on_upload( $file );

		$this->assertArrayHasKey( 'error', $result );
		$this->assertFileDoesNotExist( $tmp );
	}

	// -----------------------------------------------------------------------
	// Malformed SVG — must be rejected.
	// -----------------------------------------------------------------------

	/** A malformed (non-well-formed XML) SVG must be rejected. */
	public function test_malformed_xml_svg_rejected(): void {
		Functions\when( 'current_user_can' )->justReturn( true );

		$tmp  = $this->make_temp_file( self::fixture_contents( 'malformed/broken-xml.svg' ) );
		$file = $this->make_file_array( $tmp );

		$result = UploadFilter::sanitize_on_upload( $file );

		$this->assertArrayHasKey( 'error', $result );
		$this->assertFileDoesNotExist( $tmp );
	}

	// -----------------------------------------------------------------------
	// Capability gate.
	// -----------------------------------------------------------------------

	/** A user without the upload capability must be rejected even for clean SVG. */
	public function test_no_capability_rejects_upload(): void {
		Functions\when( 'current_user_can' )->justReturn( false );

		$tmp  = $this->make_temp_file( self::fixture_contents( 'clean/circle.svg' ) );
		$file = $this->make_file_array( $tmp );

		$result = UploadFilter::sanitize_on_upload( $file );

		$this->assertArrayHasKey( 'error', $result, 'Unprivileged user must be rejected.' );

		// Temp file is NOT deleted here — the user isn't allowed but the file itself is clean.
		@unlink( $tmp );
	}

	// -----------------------------------------------------------------------
	// allow_svg_mime().
	// -----------------------------------------------------------------------

	/** SVG MIME type must be added when the user has the capability. */
	public function test_allow_svg_mime_adds_mime_type(): void {
		Functions\when( 'current_user_can' )->justReturn( true );

		$mimes  = [ 'jpg|jpeg|jpe' => 'image/jpeg' ];
		$result = UploadFilter::allow_svg_mime( $mimes );

		$this->assertArrayHasKey( 'svg', $result );
		$this->assertSame( 'image/svg+xml', $result['svg'] );
	}

	/** SVG MIME type must NOT be added when the user lacks capability. */
	public function test_allow_svg_mime_not_added_without_capability(): void {
		Functions\when( 'current_user_can' )->justReturn( false );

		$mimes  = [ 'jpg|jpeg|jpe' => 'image/jpeg' ];
		$result = UploadFilter::allow_svg_mime( $mimes );

		$this->assertArrayNotHasKey( 'svg', $result );
	}

	// -----------------------------------------------------------------------
	// fix_svg_filetype().
	// -----------------------------------------------------------------------

	/** fix_svg_filetype() must return correct type/ext for .svg files. */
	public function test_fix_svg_filetype_returns_correct_data(): void {
		Functions\when( 'current_user_can' )->justReturn( true );

		$data   = [ 'ext' => false, 'type' => false, 'proper_filename' => false ];
		$result = UploadFilter::fix_svg_filetype( $data, '/tmp/abc123', 'icon.svg', null );

		$this->assertSame( 'svg', $result['ext'] );
		$this->assertSame( 'image/svg+xml', $result['type'] );
	}

	/** fix_svg_filetype() must not alter data for non-SVG files. */
	public function test_fix_svg_filetype_ignores_non_svg(): void {
		Functions\when( 'current_user_can' )->justReturn( true );

		$data   = [ 'ext' => 'jpg', 'type' => 'image/jpeg', 'proper_filename' => false ];
		$result = UploadFilter::fix_svg_filetype( $data, '/tmp/abc123', 'photo.jpg', null );

		$this->assertSame( 'jpg', $result['ext'] );
		$this->assertSame( 'image/jpeg', $result['type'] );
	}

	// -----------------------------------------------------------------------
	// filter-external-ref upload rejection.
	// -----------------------------------------------------------------------

	/** SVG with external url() in filter in2 must be rejected at upload time. */
	public function test_filter_external_ref_svg_rejected(): void {
		Functions\when( 'current_user_can' )->justReturn( true );

		$tmp  = $this->make_temp_file( self::fixture_contents( 'xss/filter-external-ref.svg' ) );
		$file = $this->make_file_array( $tmp );

		$result = UploadFilter::sanitize_on_upload( $file );

		$this->assertArrayHasKey( 'error', $result, 'SVG with external filter ref must be rejected.' );
		$this->assertFileDoesNotExist( $tmp );
	}

	// -----------------------------------------------------------------------
	// anchor-link upload acceptance.
	// -----------------------------------------------------------------------

	/** SVG with a clean <a href="https://..."> must be accepted at upload time. */
	public function test_anchor_link_svg_accepted(): void {
		Functions\when( 'current_user_can' )->justReturn( true );

		$tmp  = $this->make_temp_file( self::fixture_contents( 'clean/anchor-link.svg' ) );
		$file = $this->make_file_array( $tmp );

		$result = UploadFilter::sanitize_on_upload( $file );

		$this->assertArrayNotHasKey( 'error', $result, 'Clean SVG with https:// link must be accepted.' );
		@unlink( $tmp );
	}
}
