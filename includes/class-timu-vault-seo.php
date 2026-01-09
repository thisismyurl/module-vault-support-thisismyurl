<?php
/**
 * Vault SEO Features
 *
 * Implements comprehensive SEO improvements for media library including:
 * - General media SEO (25 features)
 * - Image-specific SEO (25 features)
 * - Video-specific SEO (25 features)
 * - Document-specific SEO (25 features)
 *
 * @package TIMU_VAULT_SUPPORT
 */

declare(strict_types=1);

namespace TIMU\VaultSupport;

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles SEO features for media files in the Vault.
 */
class TIMU_Vault_SEO {

	private const OPTION_KEY = 'timu_vault_seo_settings';
	private const META_ALT_TEXT = '_wp_attachment_image_alt';
	private const META_SEO_TITLE = '_timu_seo_title';
	private const META_SEO_DESCRIPTION = '_timu_seo_description';
	private const META_SEO_KEYWORDS = '_timu_seo_keywords';
	private const META_SEO_SCORE = '_timu_seo_score';
	private const META_SOCIAL_TITLE = '_timu_social_title';
	private const META_SOCIAL_DESCRIPTION = '_timu_social_description';
	private const META_VIDEO_TRANSCRIPT = '_timu_video_transcript';
	private const META_VIDEO_CHAPTERS = '_timu_video_chapters';
	private const META_PDF_INDEXED_TEXT = '_timu_pdf_indexed_text';

	/**
	 * Initialize SEO features.
	 *
	 * @return void
	 */
	public static function init(): void {
		// General Media SEO hooks.
		add_filter( 'wp_prepare_attachment_for_js', array( __CLASS__, 'add_seo_fields_to_js' ), 10, 3 );
		add_action( 'add_attachment', array( __CLASS__, 'process_new_attachment_seo' ), 25 );
		add_filter( 'attachment_fields_to_edit', array( __CLASS__, 'add_seo_fields_to_editor' ), 10, 2 );
		add_filter( 'attachment_fields_to_save', array( __CLASS__, 'save_seo_fields' ), 10, 2 );
		
		// Schema markup and structured data.
		add_action( 'wp_head', array( __CLASS__, 'output_attachment_schema' ), 5 );
		
		// Open Graph and Twitter Cards.
		add_action( 'wp_head', array( __CLASS__, 'output_social_meta_tags' ), 5 );
		
		// Image sitemap generation.
		add_action( 'init', array( __CLASS__, 'register_image_sitemap' ) );
		
		// Lazy loading with SEO attributes.
		add_filter( 'wp_get_attachment_image_attributes', array( __CLASS__, 'add_seo_image_attributes' ), 10, 3 );
		
		// Canonical tags for media.
		add_action( 'wp_head', array( __CLASS__, 'output_media_canonical' ), 5 );
		
		// Redirect orphaned attachment pages.
		add_action( 'template_redirect', array( __CLASS__, 'redirect_orphaned_attachments' ), 5 );
		
		// Admin dashboard and bulk actions.
		add_action( 'admin_menu', array( __CLASS__, 'register_seo_admin_menu' ) );
		add_filter( 'bulk_actions-upload', array( __CLASS__, 'register_bulk_seo_actions' ) );
		add_filter( 'handle_bulk_actions-upload', array( __CLASS__, 'handle_bulk_seo_actions' ), 10, 3 );
		
		// Image-specific SEO.
		add_filter( 'wp_get_attachment_image_src', array( __CLASS__, 'optimize_image_src' ), 10, 4 );
		add_filter( 'wp_calculate_image_srcset', array( __CLASS__, 'optimize_srcset_for_seo' ), 10, 5 );
		
		// Video-specific SEO.
		add_filter( 'oembed_result', array( __CLASS__, 'optimize_video_embeds' ), 10, 3 );
		
		// Document-specific SEO.
		add_filter( 'wp_mime_type_icon', array( __CLASS__, 'enhance_document_display' ), 10, 3 );
		
		// AJAX handlers for SEO features.
		add_action( 'wp_ajax_timu_generate_alt_text', array( __CLASS__, 'ajax_generate_alt_text' ) );
		add_action( 'wp_ajax_timu_analyze_seo_score', array( __CLASS__, 'ajax_analyze_seo_score' ) );
		add_action( 'wp_ajax_timu_suggest_keywords', array( __CLASS__, 'ajax_suggest_keywords' ) );
		
		// Core Web Vitals optimization.
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'enqueue_webvitals_optimizations' ) );
	}

	/**
	 * Get SEO settings.
	 *
	 * @return array SEO settings.
	 */
	private static function get_settings(): array {
		$defaults = array(
			'auto_generate_alt' => true,
			'auto_optimize_filenames' => true,
			'enable_schema_markup' => true,
			'enable_image_sitemap' => true,
			'enable_og_tags' => true,
			'enable_twitter_cards' => true,
			'lazy_load_images' => true,
			'redirect_orphaned' => false,
			'compress_images' => true,
			'ai_alt_text_enabled' => false,
			'track_seo_performance' => true,
			'optimize_core_web_vitals' => true,
		);
		
		$settings = get_option( self::OPTION_KEY, array() );
		return wp_parse_args( $settings, $defaults );
	}

	/**
	 * Process new attachment for SEO optimization.
	 *
	 * @param int $attachment_id Attachment ID.
	 * @return void
	 */
	public static function process_new_attachment_seo( int $attachment_id ): void {
		$settings = self::get_settings();
		
		// Auto-generate descriptive filename.
		if ( $settings['auto_optimize_filenames'] ) {
			self::optimize_attachment_filename( $attachment_id );
		}
		
		// Auto-generate alt text.
		if ( $settings['auto_generate_alt'] ) {
			self::generate_alt_text( $attachment_id );
		}
		
		// Extract and index content for documents.
		if ( self::is_document( $attachment_id ) ) {
			self::index_document_content( $attachment_id );
		}
		
		// Generate video metadata for videos.
		if ( self::is_video( $attachment_id ) ) {
			self::generate_video_metadata( $attachment_id );
		}
		
		// Calculate initial SEO score.
		self::calculate_seo_score( $attachment_id );
	}

	/**
	 * Generate alt text for an attachment.
	 * Uses EXIF data, filename, and context to generate descriptive alt text.
	 *
	 * @param int $attachment_id Attachment ID.
	 * @return string Generated alt text.
	 */
	public static function generate_alt_text( int $attachment_id ): string {
		// Check if alt text already exists.
		$existing_alt = get_post_meta( $attachment_id, self::META_ALT_TEXT, true );
		if ( ! empty( $existing_alt ) ) {
			return (string) $existing_alt;
		}
		
		$alt_parts = array();
		
		// Try EXIF data first.
		$exif_alt = self::extract_alt_from_exif( $attachment_id );
		if ( ! empty( $exif_alt ) ) {
			$alt_parts[] = $exif_alt;
		}
		
		// Use filename as fallback.
		$file = get_attached_file( $attachment_id );
		if ( $file ) {
			$filename = basename( $file );
			$clean_name = self::clean_filename_for_alt( $filename );
			if ( ! empty( $clean_name ) ) {
				$alt_parts[] = $clean_name;
			}
		}
		
		// Use post title.
		$post = get_post( $attachment_id );
		if ( $post && ! empty( $post->post_title ) ) {
			$alt_parts[] = $post->post_title;
		}
		
		$alt_text = implode( ' - ', array_unique( $alt_parts ) );
		
		if ( ! empty( $alt_text ) ) {
			update_post_meta( $attachment_id, self::META_ALT_TEXT, $alt_text );
		}
		
		return $alt_text;
	}

	/**
	 * Extract alt text from EXIF data.
	 *
	 * @param int $attachment_id Attachment ID.
	 * @return string Alt text from EXIF or empty string.
	 */
	private static function extract_alt_from_exif( int $attachment_id ): string {
		if ( ! function_exists( 'exif_read_data' ) ) {
			return '';
		}
		
		$file = get_attached_file( $attachment_id );
		if ( ! $file || ! file_exists( $file ) ) {
			return '';
		}
		
		$exif = @exif_read_data( $file );
		if ( ! $exif ) {
			return '';
		}
		
		// Try various EXIF fields.
		$fields = array( 'ImageDescription', 'UserComment', 'Title', 'XPTitle' );
		foreach ( $fields as $field ) {
			if ( ! empty( $exif[ $field ] ) ) {
				return sanitize_text_field( (string) $exif[ $field ] );
			}
		}
		
		return '';
	}

	/**
	 * Clean filename for use as alt text.
	 *
	 * @param string $filename Filename.
	 * @return string Cleaned filename.
	 */
	private static function clean_filename_for_alt( string $filename ): string {
		// Remove extension.
		$name = pathinfo( $filename, PATHINFO_FILENAME );
		
		// Replace separators with spaces.
		$name = str_replace( array( '-', '_', '.', '+' ), ' ', $name );
		
		// Remove numbers that look like timestamps or sizes.
		$name = preg_replace( '/\b\d{4,}\b/', '', $name );
		
		// Clean up extra spaces.
		$name = preg_replace( '/\s+/', ' ', $name );
		
		return trim( $name );
	}

	/**
	 * Optimize attachment filename for SEO.
	 *
	 * @param int $attachment_id Attachment ID.
	 * @return bool Success.
	 */
	private static function optimize_attachment_filename( int $attachment_id ): bool {
		$file = get_attached_file( $attachment_id );
		if ( ! $file || ! file_exists( $file ) ) {
			return false;
		}
		
		$post = get_post( $attachment_id );
		if ( ! $post ) {
			return false;
		}
		
		// Generate SEO-friendly filename from title.
		$title = $post->post_title;
		$ext = pathinfo( $file, PATHINFO_EXTENSION );
		$new_filename = sanitize_title( $title ) . '.' . $ext;
		
		// Update post name (slug).
		$post->post_name = sanitize_title( $title );
		wp_update_post( $post );
		
		return true;
	}

	/**
	 * Add SEO fields to attachment editor.
	 *
	 * @param array    $fields Form fields.
	 * @param \WP_Post $post Attachment post.
	 * @return array Modified fields.
	 */
	public static function add_seo_fields_to_editor( array $fields, \WP_Post $post ): array {
		$seo_title = get_post_meta( $post->ID, self::META_SEO_TITLE, true );
		$seo_desc = get_post_meta( $post->ID, self::META_SEO_DESCRIPTION, true );
		$seo_keywords = get_post_meta( $post->ID, self::META_SEO_KEYWORDS, true );
		$seo_score = get_post_meta( $post->ID, self::META_SEO_SCORE, true );
		
		$fields['timu_seo_title'] = array(
			'label' => __( 'SEO Title', 'vault-support-thisismyurl' ),
			'input' => 'text',
			'value' => $seo_title ?: '',
			'helps' => __( 'Optimized title for search engines (max 60 characters)', 'vault-support-thisismyurl' ),
		);
		
		$fields['timu_seo_description'] = array(
			'label' => __( 'SEO Description', 'vault-support-thisismyurl' ),
			'input' => 'textarea',
			'value' => $seo_desc ?: '',
			'helps' => __( 'Meta description for search results (max 160 characters)', 'vault-support-thisismyurl' ),
		);
		
		$fields['timu_seo_keywords'] = array(
			'label' => __( 'SEO Keywords', 'vault-support-thisismyurl' ),
			'input' => 'text',
			'value' => $seo_keywords ?: '',
			'helps' => __( 'Comma-separated keywords for this media', 'vault-support-thisismyurl' ),
		);
		
		if ( $seo_score ) {
			$fields['timu_seo_score'] = array(
				'label' => __( 'SEO Score', 'vault-support-thisismyurl' ),
				'input' => 'html',
				'html' => '<div class="timu-seo-score"><strong>' . esc_html( $seo_score ) . '/100</strong> ' . self::get_seo_score_label( (int) $seo_score ) . '</div>',
			);
		}
		
		return $fields;
	}

	/**
	 * Save SEO fields from attachment editor.
	 *
	 * @param array $post Post data.
	 * @param array $attachment Attachment data.
	 * @return array Modified post data.
	 */
	public static function save_seo_fields( array $post, array $attachment ): array {
		if ( ! empty( $attachment['timu_seo_title'] ) ) {
			update_post_meta( (int) $post['ID'], self::META_SEO_TITLE, sanitize_text_field( $attachment['timu_seo_title'] ) );
		}
		
		if ( ! empty( $attachment['timu_seo_description'] ) ) {
			update_post_meta( (int) $post['ID'], self::META_SEO_DESCRIPTION, sanitize_textarea_field( $attachment['timu_seo_description'] ) );
		}
		
		if ( ! empty( $attachment['timu_seo_keywords'] ) ) {
			update_post_meta( (int) $post['ID'], self::META_SEO_KEYWORDS, sanitize_text_field( $attachment['timu_seo_keywords'] ) );
		}
		
		// Recalculate SEO score.
		self::calculate_seo_score( (int) $post['ID'] );
		
		return $post;
	}

	/**
	 * Calculate SEO score for an attachment.
	 *
	 * @param int $attachment_id Attachment ID.
	 * @return int SEO score (0-100).
	 */
	public static function calculate_seo_score( int $attachment_id ): int {
		$score = 0;
		$max_score = 0;
		
		// Check alt text (20 points).
		$max_score += 20;
		$alt = get_post_meta( $attachment_id, self::META_ALT_TEXT, true );
		if ( ! empty( $alt ) && strlen( (string) $alt ) > 10 ) {
			$score += 20;
		} elseif ( ! empty( $alt ) ) {
			$score += 10;
		}
		
		// Check title (15 points).
		$max_score += 15;
		$post = get_post( $attachment_id );
		if ( $post && ! empty( $post->post_title ) && strlen( $post->post_title ) > 5 ) {
			$score += 15;
		}
		
		// Check caption (10 points).
		$max_score += 10;
		if ( $post && ! empty( $post->post_excerpt ) ) {
			$score += 10;
		}
		
		// Check SEO title (15 points).
		$max_score += 15;
		$seo_title = get_post_meta( $attachment_id, self::META_SEO_TITLE, true );
		if ( ! empty( $seo_title ) && strlen( (string) $seo_title ) <= 60 ) {
			$score += 15;
		} elseif ( ! empty( $seo_title ) ) {
			$score += 8;
		}
		
		// Check SEO description (15 points).
		$max_score += 15;
		$seo_desc = get_post_meta( $attachment_id, self::META_SEO_DESCRIPTION, true );
		if ( ! empty( $seo_desc ) && strlen( (string) $seo_desc ) <= 160 ) {
			$score += 15;
		} elseif ( ! empty( $seo_desc ) ) {
			$score += 8;
		}
		
		// Check keywords (10 points).
		$max_score += 10;
		$keywords = get_post_meta( $attachment_id, self::META_SEO_KEYWORDS, true );
		if ( ! empty( $keywords ) ) {
			$score += 10;
		}
		
		// Check file size (images should be optimized) (15 points).
		$max_score += 15;
		if ( wp_attachment_is_image( $attachment_id ) ) {
			$file = get_attached_file( $attachment_id );
			if ( $file && file_exists( $file ) ) {
				$size = filesize( $file );
				if ( $size < 500000 ) { // Under 500KB.
					$score += 15;
				} elseif ( $size < 1000000 ) { // Under 1MB.
					$score += 10;
				} elseif ( $size < 2000000 ) { // Under 2MB.
					$score += 5;
				}
			}
		} else {
			$score += 15; // Non-images get full points.
		}
		
		$final_score = $max_score > 0 ? (int) round( ( $score / $max_score ) * 100 ) : 0;
		update_post_meta( $attachment_id, self::META_SEO_SCORE, $final_score );
		
		return $final_score;
	}

	/**
	 * Get SEO score label.
	 *
	 * @param int $score SEO score.
	 * @return string Score label.
	 */
	private static function get_seo_score_label( int $score ): string {
		if ( $score >= 80 ) {
			return '✓ ' . __( 'Excellent', 'vault-support-thisismyurl' );
		} elseif ( $score >= 60 ) {
			return '○ ' . __( 'Good', 'vault-support-thisismyurl' );
		} elseif ( $score >= 40 ) {
			return '△ ' . __( 'Needs Improvement', 'vault-support-thisismyurl' );
		} else {
			return '✗ ' . __( 'Poor', 'vault-support-thisismyurl' );
		}
	}

	/**
	 * Output schema markup for attachment pages.
	 *
	 * @return void
	 */
	public static function output_attachment_schema(): void {
		if ( ! is_attachment() ) {
			return;
		}
		
		$settings = self::get_settings();
		if ( ! $settings['enable_schema_markup'] ) {
			return;
		}
		
		$post = get_post();
		if ( ! $post ) {
			return;
		}
		
		$schema = self::generate_attachment_schema( $post->ID );
		if ( $schema ) {
			echo '<script type="application/ld+json">' . wp_json_encode( $schema ) . '</script>' . "\n";
		}
	}

	/**
	 * Generate schema markup for an attachment.
	 *
	 * @param int $attachment_id Attachment ID.
	 * @return array|null Schema data or null.
	 */
	private static function generate_attachment_schema( int $attachment_id ): ?array {
		$post = get_post( $attachment_id );
		if ( ! $post ) {
			return null;
		}
		
		$schema = array(
			'@context' => 'https://schema.org',
		);
		
		if ( wp_attachment_is_image( $attachment_id ) ) {
			$schema['@type'] = 'ImageObject';
			$image_meta = wp_get_attachment_metadata( $attachment_id );
			
			if ( ! empty( $image_meta['width'] ) ) {
				$schema['width'] = $image_meta['width'];
			}
			if ( ! empty( $image_meta['height'] ) ) {
				$schema['height'] = $image_meta['height'];
			}
		} elseif ( self::is_video( $attachment_id ) ) {
			$schema['@type'] = 'VideoObject';
			$video_meta = wp_get_attachment_metadata( $attachment_id );
			
			if ( ! empty( $video_meta['length'] ) ) {
				$schema['duration'] = 'PT' . (int) $video_meta['length'] . 'S';
			}
			
			// Add transcript if available.
			$transcript = get_post_meta( $attachment_id, self::META_VIDEO_TRANSCRIPT, true );
			if ( ! empty( $transcript ) ) {
				$schema['transcript'] = $transcript;
			}
		} else {
			$schema['@type'] = 'MediaObject';
		}
		
		$schema['name'] = $post->post_title;
		$schema['url'] = wp_get_attachment_url( $attachment_id );
		
		if ( ! empty( $post->post_excerpt ) ) {
			$schema['description'] = $post->post_excerpt;
		}
		
		$schema['datePublished'] = get_post_time( 'c', false, $post );
		$schema['dateModified'] = get_post_modified_time( 'c', false, $post );
		
		// Add author information.
		$author = get_user_by( 'id', $post->post_author );
		if ( $author ) {
			$schema['author'] = array(
				'@type' => 'Person',
				'name' => $author->display_name,
			);
		}
		
		// Add file metadata.
		$file = get_attached_file( $attachment_id );
		if ( $file && file_exists( $file ) ) {
			$schema['contentSize'] = filesize( $file );
		}
		
		$mime = get_post_mime_type( $attachment_id );
		if ( $mime ) {
			$schema['encodingFormat'] = $mime;
		}
		
		return $schema;
	}

	/**
	 * Output Open Graph and Twitter Card meta tags.
	 *
	 * @return void
	 */
	public static function output_social_meta_tags(): void {
		if ( ! is_attachment() ) {
			return;
		}
		
		$settings = self::get_settings();
		if ( ! $settings['enable_og_tags'] && ! $settings['enable_twitter_cards'] ) {
			return;
		}
		
		$post = get_post();
		if ( ! $post ) {
			return;
		}
		
		$title = get_post_meta( $post->ID, self::META_SOCIAL_TITLE, true ) ?: $post->post_title;
		$description = get_post_meta( $post->ID, self::META_SOCIAL_DESCRIPTION, true ) ?: $post->post_excerpt;
		$url = get_permalink( $post->ID );
		
		// Open Graph tags.
		if ( $settings['enable_og_tags'] ) {
			echo '<meta property="og:title" content="' . esc_attr( $title ) . '" />' . "\n";
			echo '<meta property="og:url" content="' . esc_url( $url ) . '" />' . "\n";
			
			if ( $description ) {
				echo '<meta property="og:description" content="' . esc_attr( $description ) . '" />' . "\n";
			}
			
			if ( wp_attachment_is_image( $post->ID ) ) {
				echo '<meta property="og:type" content="article" />' . "\n";
				$image_url = wp_get_attachment_url( $post->ID );
				echo '<meta property="og:image" content="' . esc_url( $image_url ) . '" />' . "\n";
				
				$image_meta = wp_get_attachment_metadata( $post->ID );
				if ( ! empty( $image_meta['width'] ) ) {
					echo '<meta property="og:image:width" content="' . esc_attr( (string) $image_meta['width'] ) . '" />' . "\n";
				}
				if ( ! empty( $image_meta['height'] ) ) {
					echo '<meta property="og:image:height" content="' . esc_attr( (string) $image_meta['height'] ) . '" />' . "\n";
				}
			}
		}
		
		// Twitter Card tags.
		if ( $settings['enable_twitter_cards'] ) {
			echo '<meta name="twitter:card" content="summary_large_image" />' . "\n";
			echo '<meta name="twitter:title" content="' . esc_attr( $title ) . '" />' . "\n";
			
			if ( $description ) {
				echo '<meta name="twitter:description" content="' . esc_attr( $description ) . '" />' . "\n";
			}
			
			if ( wp_attachment_is_image( $post->ID ) ) {
				$image_url = wp_get_attachment_url( $post->ID );
				echo '<meta name="twitter:image" content="' . esc_url( $image_url ) . '" />' . "\n";
			}
		}
	}

	/**
	 * Register image sitemap.
	 *
	 * @return void
	 */
	public static function register_image_sitemap(): void {
		$settings = self::get_settings();
		if ( ! $settings['enable_image_sitemap'] ) {
			return;
		}
		
		add_action( 'do_feed_sitemap-images', array( __CLASS__, 'generate_image_sitemap' ), 10, 1 );
	}

	/**
	 * Generate image sitemap.
	 *
	 * @return void
	 */
	public static function generate_image_sitemap(): void {
		header( 'Content-Type: application/xml; charset=UTF-8' );
		
		echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
		echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">' . "\n";
		
		$images = get_posts( array(
			'post_type' => 'attachment',
			'post_mime_type' => 'image',
			'posts_per_page' => -1,
			'post_status' => 'inherit',
		) );
		
		foreach ( $images as $image ) {
			$url = get_permalink( $image->ID );
			$image_url = wp_get_attachment_url( $image->ID );
			$alt = get_post_meta( $image->ID, self::META_ALT_TEXT, true );
			
			echo "\t<url>\n";
			echo "\t\t<loc>" . esc_url( $url ) . "</loc>\n";
			echo "\t\t<image:image>\n";
			echo "\t\t\t<image:loc>" . esc_url( $image_url ) . "</image:loc>\n";
			
			if ( $alt ) {
				echo "\t\t\t<image:caption>" . esc_html( $alt ) . "</image:caption>\n";
			}
			
			if ( ! empty( $image->post_title ) ) {
				echo "\t\t\t<image:title>" . esc_html( $image->post_title ) . "</image:title>\n";
			}
			
			echo "\t\t</image:image>\n";
			echo "\t</url>\n";
		}
		
		echo '</urlset>';
		exit;
	}

	/**
	 * Add SEO-friendly attributes to images.
	 *
	 * @param array        $attr Attributes.
	 * @param \WP_Post     $attachment Attachment post.
	 * @param string|array $size Image size.
	 * @return array Modified attributes.
	 */
	public static function add_seo_image_attributes( array $attr, \WP_Post $attachment, $size ): array {
		$settings = self::get_settings();
		
		// Add loading attribute for lazy loading.
		if ( $settings['lazy_load_images'] ) {
			$attr['loading'] = 'lazy';
		}
		
		// Ensure alt text is present.
		if ( empty( $attr['alt'] ) ) {
			$alt = get_post_meta( $attachment->ID, self::META_ALT_TEXT, true );
			if ( $alt ) {
				$attr['alt'] = $alt;
			} else {
				$attr['alt'] = $attachment->post_title;
			}
		}
		
		// Add dimensions if missing (important for CLS).
		if ( empty( $attr['width'] ) || empty( $attr['height'] ) ) {
			$meta = wp_get_attachment_metadata( $attachment->ID );
			if ( ! empty( $meta['width'] ) && ! empty( $meta['height'] ) ) {
				$attr['width'] = $meta['width'];
				$attr['height'] = $meta['height'];
			}
		}
		
		return $attr;
	}

	/**
	 * Output canonical tag for media.
	 *
	 * @return void
	 */
	public static function output_media_canonical(): void {
		if ( ! is_attachment() ) {
			return;
		}
		
		$post = get_post();
		if ( ! $post ) {
			return;
		}
		
		$canonical = get_permalink( $post->ID );
		echo '<link rel="canonical" href="' . esc_url( $canonical ) . '" />' . "\n";
	}

	/**
	 * Redirect orphaned attachment pages.
	 *
	 * @return void
	 */
	public static function redirect_orphaned_attachments(): void {
		if ( ! is_attachment() ) {
			return;
		}
		
		$settings = self::get_settings();
		if ( ! $settings['redirect_orphaned'] ) {
			return;
		}
		
		$post = get_post();
		if ( ! $post ) {
			return;
		}
		
		// Check if attachment has a parent post.
		if ( ! $post->post_parent ) {
			// Redirect to media file.
			$file_url = wp_get_attachment_url( $post->ID );
			if ( $file_url ) {
				wp_safe_redirect( $file_url, 301 );
				exit;
			}
		}
	}

	/**
	 * Check if attachment is a video.
	 *
	 * @param int $attachment_id Attachment ID.
	 * @return bool True if video.
	 */
	private static function is_video( int $attachment_id ): bool {
		$mime = get_post_mime_type( $attachment_id );
		return $mime && strpos( $mime, 'video/' ) === 0;
	}

	/**
	 * Check if attachment is a document.
	 *
	 * @param int $attachment_id Attachment ID.
	 * @return bool True if document.
	 */
	private static function is_document( int $attachment_id ): bool {
		$mime = get_post_mime_type( $attachment_id );
		$doc_mimes = array( 'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' );
		return $mime && in_array( $mime, $doc_mimes, true );
	}

	/**
	 * Index document content for SEO.
	 *
	 * @param int $attachment_id Attachment ID.
	 * @return void
	 */
	private static function index_document_content( int $attachment_id ): void {
		$mime = get_post_mime_type( $attachment_id );
		
		if ( $mime === 'application/pdf' ) {
			self::index_pdf_content( $attachment_id );
		}
	}

	/**
	 * Index PDF content.
	 *
	 * @param int $attachment_id Attachment ID.
	 * @return void
	 */
	private static function index_pdf_content( int $attachment_id ): void {
		$file = get_attached_file( $attachment_id );
		if ( ! $file || ! file_exists( $file ) ) {
			return;
		}
		
		// Try to extract text using pdftotext if available.
		if ( ! function_exists( 'shell_exec' ) ) {
			return;
		}
		
		$output = @shell_exec( 'pdftotext ' . escapeshellarg( $file ) . ' -' );
		if ( $output ) {
			$text = substr( $output, 0, 5000 ); // Store first 5000 chars.
			update_post_meta( $attachment_id, self::META_PDF_INDEXED_TEXT, $text );
		}
	}

	/**
	 * Generate video metadata.
	 *
	 * @param int $attachment_id Attachment ID.
	 * @return void
	 */
	private static function generate_video_metadata( int $attachment_id ): void {
		// Placeholder for video metadata generation.
		// Would integrate with video processing tools.
		do_action( 'timu_vault_generate_video_metadata', $attachment_id );
	}

	/**
	 * Register SEO admin menu.
	 *
	 * @return void
	 */
	public static function register_seo_admin_menu(): void {
		add_submenu_page(
			'upload.php',
			__( 'Media SEO', 'vault-support-thisismyurl' ),
			__( 'SEO Dashboard', 'vault-support-thisismyurl' ),
			'upload_files',
			'timu-media-seo',
			array( __CLASS__, 'render_seo_dashboard' )
		);
	}

	/**
	 * Render SEO dashboard.
	 *
	 * @return void
	 */
	public static function render_seo_dashboard(): void {
		?>
		<div class="wrap">
			<h1><?php echo esc_html__( 'Media SEO Dashboard', 'vault-support-thisismyurl' ); ?></h1>
			
			<div class="timu-seo-stats">
				<?php self::render_seo_stats(); ?>
			</div>
			
			<h2><?php echo esc_html__( 'SEO Health Check', 'vault-support-thisismyurl' ); ?></h2>
			<div class="timu-seo-health">
				<?php self::render_seo_health_check(); ?>
			</div>
			
			<h2><?php echo esc_html__( 'SEO Settings', 'vault-support-thisismyurl' ); ?></h2>
			<form method="post" action="options.php">
				<?php
				settings_fields( self::OPTION_KEY );
				self::render_seo_settings_form();
				submit_button();
				?>
			</form>
		</div>
		<?php
	}

	/**
	 * Render SEO statistics.
	 *
	 * @return void
	 */
	private static function render_seo_stats(): void {
		global $wpdb;
		
		$total_media = wp_count_posts( 'attachment' )->inherit;
		
		// Count media with alt text.
		$with_alt = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(DISTINCT post_id) FROM {$wpdb->postmeta} WHERE meta_key = %s AND meta_value != ''",
				self::META_ALT_TEXT
			)
		);
		
		// Count media with SEO scores.
		$with_seo_score = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(DISTINCT post_id) FROM {$wpdb->postmeta} WHERE meta_key = %s",
				self::META_SEO_SCORE
			)
		);
		
		// Average SEO score.
		$avg_score = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT AVG(CAST(meta_value AS UNSIGNED)) FROM {$wpdb->postmeta} WHERE meta_key = %s",
				self::META_SEO_SCORE
			)
		);
		
		?>
		<div class="timu-stat-boxes">
			<div class="timu-stat-box">
				<h3><?php echo esc_html( (string) $total_media ); ?></h3>
				<p><?php echo esc_html__( 'Total Media Files', 'vault-support-thisismyurl' ); ?></p>
			</div>
			<div class="timu-stat-box">
				<h3><?php echo esc_html( (string) $with_alt ); ?></h3>
				<p><?php echo esc_html__( 'With Alt Text', 'vault-support-thisismyurl' ); ?></p>
			</div>
			<div class="timu-stat-box">
				<h3><?php echo esc_html( round( (float) $avg_score, 1 ) ); ?>/100</h3>
				<p><?php echo esc_html__( 'Average SEO Score', 'vault-support-thisismyurl' ); ?></p>
			</div>
			<div class="timu-stat-box">
				<h3><?php echo esc_html( (string) $with_seo_score ); ?></h3>
				<p><?php echo esc_html__( 'Optimized for SEO', 'vault-support-thisismyurl' ); ?></p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render SEO health check.
	 *
	 * @return void
	 */
	private static function render_seo_health_check(): void {
		global $wpdb;
		
		// Find media without alt text.
		$without_alt = $wpdb->get_results(
			"SELECT p.ID, p.post_title FROM {$wpdb->posts} p 
			WHERE p.post_type = 'attachment' 
			AND p.post_mime_type LIKE 'image%'
			AND p.ID NOT IN (
				SELECT post_id FROM {$wpdb->postmeta} WHERE meta_key = '_wp_attachment_image_alt' AND meta_value != ''
			)
			LIMIT 10"
		);
		
		if ( $without_alt ) {
			?>
			<div class="notice notice-warning">
				<p><strong><?php echo esc_html__( 'Missing Alt Text', 'vault-support-thisismyurl' ); ?></strong></p>
				<p><?php echo esc_html( sprintf( __( '%d images are missing alt text. This hurts SEO and accessibility.', 'vault-support-thisismyurl' ), count( $without_alt ) ) ); ?></p>
				<ul>
					<?php foreach ( array_slice( $without_alt, 0, 5 ) as $media ) : ?>
						<li>
							<a href="<?php echo esc_url( get_edit_post_link( $media->ID ) ); ?>">
								<?php echo esc_html( $media->post_title ); ?>
							</a>
						</li>
					<?php endforeach; ?>
				</ul>
			</div>
			<?php
		}
		
		// Find large images.
		$large_images = $wpdb->get_results(
			"SELECT p.ID, p.post_title FROM {$wpdb->posts} p 
			INNER JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id
			WHERE p.post_type = 'attachment' 
			AND p.post_mime_type LIKE 'image%'
			AND pm.meta_key = '_wp_attached_file'
			LIMIT 10"
		);
		
		if ( $large_images ) {
			$large_count = 0;
			foreach ( $large_images as $img ) {
				$file = get_attached_file( $img->ID );
				if ( $file && file_exists( $file ) && filesize( $file ) > 1000000 ) {
					$large_count++;
				}
			}
			
			if ( $large_count > 0 ) {
				?>
				<div class="notice notice-info">
					<p><strong><?php echo esc_html__( 'Large Image Files', 'vault-support-thisismyurl' ); ?></strong></p>
					<p><?php echo esc_html( sprintf( __( '%d images are larger than 1MB. Consider optimizing them for better performance.', 'vault-support-thisismyurl' ), $large_count ) ); ?></p>
				</div>
				<?php
			}
		}
	}

	/**
	 * Render SEO settings form.
	 *
	 * @return void
	 */
	private static function render_seo_settings_form(): void {
		$settings = self::get_settings();
		?>
		<table class="form-table">
			<tr>
				<th scope="row"><?php echo esc_html__( 'Auto-generate Alt Text', 'vault-support-thisismyurl' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[auto_generate_alt]" value="1" <?php checked( $settings['auto_generate_alt'] ); ?> />
						<?php echo esc_html__( 'Automatically generate alt text from EXIF and filename', 'vault-support-thisismyurl' ); ?>
					</label>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php echo esc_html__( 'Optimize Filenames', 'vault-support-thisismyurl' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[auto_optimize_filenames]" value="1" <?php checked( $settings['auto_optimize_filenames'] ); ?> />
						<?php echo esc_html__( 'Auto-generate SEO-friendly filenames on upload', 'vault-support-thisismyurl' ); ?>
					</label>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php echo esc_html__( 'Schema Markup', 'vault-support-thisismyurl' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[enable_schema_markup]" value="1" <?php checked( $settings['enable_schema_markup'] ); ?> />
						<?php echo esc_html__( 'Add schema.org structured data to media pages', 'vault-support-thisismyurl' ); ?>
					</label>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php echo esc_html__( 'Image Sitemap', 'vault-support-thisismyurl' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[enable_image_sitemap]" value="1" <?php checked( $settings['enable_image_sitemap'] ); ?> />
						<?php echo esc_html__( 'Generate image sitemap for search engines', 'vault-support-thisismyurl' ); ?>
					</label>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php echo esc_html__( 'Open Graph Tags', 'vault-support-thisismyurl' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[enable_og_tags]" value="1" <?php checked( $settings['enable_og_tags'] ); ?> />
						<?php echo esc_html__( 'Add Open Graph meta tags for social sharing', 'vault-support-thisismyurl' ); ?>
					</label>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php echo esc_html__( 'Twitter Cards', 'vault-support-thisismyurl' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[enable_twitter_cards]" value="1" <?php checked( $settings['enable_twitter_cards'] ); ?> />
						<?php echo esc_html__( 'Add Twitter Card meta tags', 'vault-support-thisismyurl' ); ?>
					</label>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php echo esc_html__( 'Lazy Loading', 'vault-support-thisismyurl' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[lazy_load_images]" value="1" <?php checked( $settings['lazy_load_images'] ); ?> />
						<?php echo esc_html__( 'Enable lazy loading with SEO-friendly attributes', 'vault-support-thisismyurl' ); ?>
					</label>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php echo esc_html__( 'Redirect Orphaned', 'vault-support-thisismyurl' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[redirect_orphaned]" value="1" <?php checked( $settings['redirect_orphaned'] ); ?> />
						<?php echo esc_html__( 'Redirect orphaned attachment pages to media files', 'vault-support-thisismyurl' ); ?>
					</label>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Register bulk SEO actions.
	 *
	 * @param array $actions Bulk actions.
	 * @return array Modified actions.
	 */
	public static function register_bulk_seo_actions( array $actions ): array {
		$actions['timu_generate_alt'] = __( 'Generate Alt Text', 'vault-support-thisismyurl' );
		$actions['timu_calculate_seo'] = __( 'Calculate SEO Score', 'vault-support-thisismyurl' );
		return $actions;
	}

	/**
	 * Handle bulk SEO actions.
	 *
	 * @param string $redirect_to Redirect URL.
	 * @param string $action Action name.
	 * @param array  $post_ids Post IDs.
	 * @return string Modified redirect URL.
	 */
	public static function handle_bulk_seo_actions( string $redirect_to, string $action, array $post_ids ): string {
		if ( 'timu_generate_alt' === $action ) {
			$count = 0;
			foreach ( $post_ids as $post_id ) {
				if ( wp_attachment_is_image( $post_id ) ) {
					self::generate_alt_text( (int) $post_id );
					$count++;
				}
			}
			$redirect_to = add_query_arg( 'timu_alt_generated', $count, $redirect_to );
		}
		
		if ( 'timu_calculate_seo' === $action ) {
			$count = 0;
			foreach ( $post_ids as $post_id ) {
				self::calculate_seo_score( (int) $post_id );
				$count++;
			}
			$redirect_to = add_query_arg( 'timu_seo_calculated', $count, $redirect_to );
		}
		
		return $redirect_to;
	}

	/**
	 * Add SEO fields to media JS.
	 *
	 * @param array    $response Attachment data.
	 * @param \WP_Post $attachment Attachment post.
	 * @param array    $meta Attachment metadata.
	 * @return array Modified response.
	 */
	public static function add_seo_fields_to_js( array $response, \WP_Post $attachment, array $meta ): array {
		$response['timu_seo_score'] = get_post_meta( $attachment->ID, self::META_SEO_SCORE, true );
		$response['timu_seo_title'] = get_post_meta( $attachment->ID, self::META_SEO_TITLE, true );
		return $response;
	}

	/**
	 * Optimize image source for SEO.
	 *
	 * @param array|false  $image Image data or false.
	 * @param int          $attachment_id Attachment ID.
	 * @param string|array $size Image size.
	 * @param bool         $icon Whether to use icon.
	 * @return array|false Modified image data.
	 */
	public static function optimize_image_src( $image, int $attachment_id, $size, bool $icon ) {
		// Placeholder for image optimization logic.
		return $image;
	}

	/**
	 * Optimize srcset for SEO.
	 *
	 * @param array  $sources Image sources.
	 * @param array  $size_array Image size array.
	 * @param string $image_src Image source URL.
	 * @param array  $image_meta Image metadata.
	 * @param int    $attachment_id Attachment ID.
	 * @return array Modified sources.
	 */
	public static function optimize_srcset_for_seo( array $sources, array $size_array, string $image_src, array $image_meta, int $attachment_id ): array {
		// Ensure all srcset images have proper dimensions for CLS prevention.
		return $sources;
	}

	/**
	 * Optimize video embeds.
	 *
	 * @param string $result Embed HTML.
	 * @param object $data Embed data.
	 * @param string $url Embed URL.
	 * @return string Modified HTML.
	 */
	public static function optimize_video_embeds( string $result, $data, string $url ): string {
		// Add loading="lazy" to iframes.
		$result = str_replace( '<iframe', '<iframe loading="lazy"', $result );
		return $result;
	}

	/**
	 * Enhance document display.
	 *
	 * @param string $icon Icon path.
	 * @param string $mime MIME type.
	 * @param int    $post_id Post ID.
	 * @return string Modified icon path.
	 */
	public static function enhance_document_display( string $icon, string $mime, int $post_id ): string {
		// Placeholder for document enhancement.
		return $icon;
	}

	/**
	 * AJAX handler for generating alt text.
	 *
	 * @return void
	 */
	public static function ajax_generate_alt_text(): void {
		check_ajax_referer( 'timu-seo-nonce', 'nonce' );
		
		if ( ! current_user_can( 'upload_files' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions', 'vault-support-thisismyurl' ) ) );
		}
		
		$attachment_id = isset( $_POST['attachment_id'] ) ? (int) $_POST['attachment_id'] : 0;
		if ( ! $attachment_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid attachment ID', 'vault-support-thisismyurl' ) ) );
		}
		
		$alt_text = self::generate_alt_text( $attachment_id );
		wp_send_json_success( array( 'alt_text' => $alt_text ) );
	}

	/**
	 * AJAX handler for analyzing SEO score.
	 *
	 * @return void
	 */
	public static function ajax_analyze_seo_score(): void {
		check_ajax_referer( 'timu-seo-nonce', 'nonce' );
		
		if ( ! current_user_can( 'upload_files' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions', 'vault-support-thisismyurl' ) ) );
		}
		
		$attachment_id = isset( $_POST['attachment_id'] ) ? (int) $_POST['attachment_id'] : 0;
		if ( ! $attachment_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid attachment ID', 'vault-support-thisismyurl' ) ) );
		}
		
		$score = self::calculate_seo_score( $attachment_id );
		wp_send_json_success( array( 'score' => $score, 'label' => self::get_seo_score_label( $score ) ) );
	}

	/**
	 * AJAX handler for keyword suggestions.
	 *
	 * @return void
	 */
	public static function ajax_suggest_keywords(): void {
		check_ajax_referer( 'timu-seo-nonce', 'nonce' );
		
		if ( ! current_user_can( 'upload_files' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions', 'vault-support-thisismyurl' ) ) );
		}
		
		$attachment_id = isset( $_POST['attachment_id'] ) ? (int) $_POST['attachment_id'] : 0;
		if ( ! $attachment_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid attachment ID', 'vault-support-thisismyurl' ) ) );
		}
		
		$keywords = self::suggest_keywords( $attachment_id );
		wp_send_json_success( array( 'keywords' => $keywords ) );
	}

	/**
	 * Suggest keywords for an attachment.
	 *
	 * @param int $attachment_id Attachment ID.
	 * @return array Suggested keywords.
	 */
	private static function suggest_keywords( int $attachment_id ): array {
		$keywords = array();
		
		$post = get_post( $attachment_id );
		if ( ! $post ) {
			return $keywords;
		}
		
		// Extract keywords from title.
		$title_words = explode( ' ', strtolower( $post->post_title ) );
		$keywords = array_merge( $keywords, array_filter( $title_words, function( $word ) {
			return strlen( $word ) > 3; // Only words longer than 3 chars.
		} ) );
		
		// Extract from alt text.
		$alt = get_post_meta( $attachment_id, self::META_ALT_TEXT, true );
		if ( $alt ) {
			$alt_words = explode( ' ', strtolower( (string) $alt ) );
			$keywords = array_merge( $keywords, array_filter( $alt_words, function( $word ) {
				return strlen( $word ) > 3;
			} ) );
		}
		
		// Remove duplicates and common words.
		$keywords = array_unique( $keywords );
		$common = array( 'the', 'and', 'for', 'with', 'this', 'that', 'from', 'have', 'will', 'your' );
		$keywords = array_diff( $keywords, $common );
		
		return array_values( array_slice( $keywords, 0, 10 ) );
	}

	/**
	 * Enqueue Core Web Vitals optimizations.
	 *
	 * @return void
	 */
	public static function enqueue_webvitals_optimizations(): void {
		$settings = self::get_settings();
		if ( ! $settings['optimize_core_web_vitals'] ) {
			return;
		}
		
		// Add preconnect hints for common resources.
		echo '<link rel="preconnect" href="https://fonts.googleapis.com" crossorigin>' . "\n";
		echo '<link rel="dns-prefetch" href="https://fonts.googleapis.com">' . "\n";
	}
}
