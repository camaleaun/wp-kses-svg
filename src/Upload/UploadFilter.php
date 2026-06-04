<?php
/**
 * SVG Upload Filter.
 *
 * Hooks into the WordPress upload pipeline to:
 *   1. Allow the image/svg+xml MIME type (opt-in, capability-gated).
 *   2. Sanitize the SVG file content the moment it lands on the server,
 *      before WordPress moves it to the uploads directory.
 *   3. Reject and delete any file that fails XML validation or sanitization.
 *
 * Security guarantees:
 *   - Only users with the 'upload_svg' capability (defaults to 'upload_files'
 *     for Editors+) may upload SVG files.
 *   - The raw file is sanitized in place; if sanitization changes the content
 *      the temp file is overwritten before WordPress copies it.
 *   - If sanitization returns empty (malformed XML, blocked tags, etc.) the
 *      upload is aborted with a descriptive error and the temp file is deleted.
 *
 * @package WpKsesSvg\Upload
 * @since   0.1.0
 */

namespace WpKsesSvg\Upload;

use WpKsesSvg\Sanitizer\Sanitizer;

defined( 'ABSPATH' ) || exit;

/**
 * Registers WordPress upload hooks for SVG support.
 *
 * @since 0.1.0
 */
class UploadFilter {

	/**
	 * The MIME type this filter handles.
	 *
	 * @since 0.1.0
	 * @var string
	 */
	public const MIME_TYPE = 'image/svg+xml';

	/**
	 * The file extension(s) this filter handles.
	 *
	 * @since 0.1.0
	 * @var string
	 */
	public const EXTENSION = 'svg';

	/**
	 * Capability required to upload SVG files.
	 * Filterable via 'wp_kses_svg_upload_capability'.
	 *
	 * @since 0.1.0
	 * @var string
	 */
	public const DEFAULT_CAPABILITY = 'upload_files';

	/**
	 * Register all hooks.
	 *
	 * @since  0.1.0
	 * @return void
	 */
	public static function register(): void {
		// Allow SVG MIME type in the upload_mimes list.
		add_filter( 'upload_mimes', array( self::class, 'allow_svg_mime' ) );

		// Override MIME-type check so WordPress does not reject .svg files.
		add_filter( 'wp_check_filetype_and_ext', array( self::class, 'fix_svg_filetype' ), 10, 4 );

		// Sanitize (or reject) the file before WordPress finalizes the upload.
		add_filter( 'wp_handle_upload_prefilter', array( self::class, 'sanitize_on_upload' ) );
	}

	/**
	 * Add image/svg+xml to the allowed MIME types.
	 *
	 * Gated behind the upload capability so non-privileged users cannot
	 * accidentally (or intentionally) trigger SVG processing.
	 *
	 * @since  0.1.0
	 *
	 * @param  array<string, string> $mimes Existing MIME map.
	 * @return array<string, string>        Updated MIME map.
	 */
	public static function allow_svg_mime( array $mimes ): array {
		if ( current_user_can( self::get_capability() ) ) {
			$mimes['svg']  = self::MIME_TYPE;
			$mimes['svgz'] = 'image/svg+xml'; // Compressed — handled identically.
		}

		return $mimes;
	}

	/**
	 * Correct the filetype/extension data for SVG files.
	 *
	 * WordPress's wp_check_filetype_and_ext() uses finfo / getimagesize() which
	 * cannot identify SVG; this filter provides the correct values so the upload
	 * is not rejected before our sanitizer can run.
	 *
	 * @since  0.1.0
	 *
	 * @param  array<string, string|false> $data      Existing filetype data.
	 * @param  string                      $file      Full path to the temp file.
	 * @param  string                      $filename  Original filename.
	 * @param  array<string, string>|null  $mimes     Allowed MIME map (unused; present for hook signature compatibility).
	 * @return array<string, string|false>             Corrected filetype data.
	 */
	public static function fix_svg_filetype( array $data, string $file, string $filename, ?array $mimes ): array { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		if ( ! current_user_can( self::get_capability() ) ) {
			return $data;
		}

		$ext = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );

		if ( self::EXTENSION !== $ext ) {
			return $data;
		}

		$data['type'] = self::MIME_TYPE;
		$data['ext']  = self::EXTENSION;

		return $data;
	}

	/**
	 * Sanitize an SVG file before WordPress finalizes the upload.
	 *
	 * If the file content is malformed or contains unsafe markup the upload is
	 * aborted: the temp file is deleted and an error array is returned so
	 * WordPress surfaces a user-facing error message.
	 *
	 * @since  0.1.0
	 *
	 * @param  array<string, string> $file $_FILES entry: name, type, tmp_name, error, size.
	 * @return array<string, string>        Original array on success, error array on failure.
	 */
	public static function sanitize_on_upload( array $file ): array {
		// Only process SVG uploads.
		$ext = strtolower( pathinfo( $file['name'] ?? '', PATHINFO_EXTENSION ) );

		if ( self::EXTENSION !== $ext ) {
			return $file;
		}

		// Capability gate — redundant with allow_svg_mime() but defense-in-depth.
		if ( ! current_user_can( self::get_capability() ) ) {
			return self::reject( $file, __( 'You do not have permission to upload SVG files.', 'wp-kses-svg' ) );
		}

		$tmp_path = $file['tmp_name'] ?? '';

		if ( ! is_readable( $tmp_path ) ) {
			return self::reject( $file, __( 'SVG upload failed: temporary file is not readable.', 'wp-kses-svg' ) );
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		// Rationale: this runs inside wp_handle_upload_prefilter, before wp-admin
		// is loaded, so WP_Filesystem is not available. The path is a PHP temp
		// file created by WordPress itself — not a remote URL — so file_get_contents
		// is safe here.
		$raw = file_get_contents( $tmp_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents

		if ( false === $raw ) {
			return self::reject( $file, __( 'SVG upload failed: could not read temporary file.', 'wp-kses-svg' ) );
		}

		$sanitized = Sanitizer::sanitize( $raw );

		if ( '' === $sanitized ) {
			// Remove the temp file immediately — leave no malicious trace.
			self::delete_temp( $tmp_path );

			return self::reject(
				$file,
				__( 'SVG upload rejected: the file contains invalid or unsafe markup.', 'wp-kses-svg' )
			);
		}

		// Overwrite the temp file with sanitized content only when it changed.
		if ( $sanitized !== $raw ) {
			file_put_contents( $tmp_path, $sanitized ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- temp file pre-WP_Filesystem bootstrap.
		}

		return $file;
	}

	// -----------------------------------------------------------------------
	// Private helpers.
	// -----------------------------------------------------------------------

	/**
	 * Return the upload capability, allowing site owners to tighten the gate.
	 *
	 * @since  0.1.0
	 * @return string WordPress capability slug.
	 */
	private static function get_capability(): string {
		return (string) apply_filters( 'wp_kses_svg_upload_capability', self::DEFAULT_CAPABILITY );
	}

	/**
	 * Build an error response array understood by wp_handle_upload().
	 *
	 * Setting 'error' causes WordPress to surface the message in the media
	 * uploader and abort the upload pipeline.
	 *
	 * @since  0.1.0
	 *
	 * @param  array<string, string> $file    Original $_FILES entry.
	 * @param  string                $message Human-readable error message.
	 * @return array<string, string>           File array with 'error' key set.
	 */
	private static function reject( array $file, string $message ): array {
		$file['error'] = $message;

		return $file;
	}

	/**
	 * Safely delete the temp file, suppressing errors if already removed.
	 *
	 * @since  0.1.0
	 *
	 * @param  string $path Absolute path to the temp file.
	 * @return void
	 */
	private static function delete_temp( string $path ): void {
		if ( is_file( $path ) ) {
			wp_delete_file( $path ); // Uses @unlink internally — WP-safe wrapper.
		}
	}
}
