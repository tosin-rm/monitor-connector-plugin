<?php
/** Read-only inventory collector. */

namespace MonitorConnector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Inventory {
	const MAX_PLUGINS = 500;
	const MAX_PAYLOAD_BYTES = 262144;
	const MAX_CORE_FILES = 10000;
	const MAX_CORE_FINDINGS = 100;

	/** @return array<string,mixed>|\WP_Error */
	public static function collect() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$installed = get_plugins();
		if ( ! is_array( $installed ) || count( $installed ) > self::MAX_PLUGINS ) {
			return new \WP_Error( 'inventory_plugin_limit' );
		}
		if ( ! function_exists( 'get_site_transient' ) ) {
			return new \WP_Error( 'inventory_updates_unavailable' );
		}
		$updates = get_site_transient( 'update_plugins' );
		$plugins = array();
		foreach ( $installed as $file => $data ) {
			$slug = self::plugin_slug( $file, $data );
			$update_available = null;
			$update_version = null;
			if ( is_object( $updates ) && isset( $updates->response ) && is_array( $updates->response ) && isset( $updates->response[ $file ] ) ) {
				$update_available = true;
				if ( isset( $updates->response[ $file ]->new_version ) ) {
					$update_version = sanitize_text_field( $updates->response[ $file ]->new_version );
				}
			} elseif ( is_object( $updates ) && isset( $updates->no_update ) && is_array( $updates->no_update ) && isset( $updates->no_update[ $file ] ) ) {
				$update_available = false;
			} // Missing both response records means update status is unknown.
			$plugins[] = array(
				'slug'             => $slug,
				'name'             => sanitize_text_field( isset( $data['Name'] ) ? $data['Name'] : $slug ),
				'version'          => sanitize_text_field( isset( $data['Version'] ) ? $data['Version'] : '' ),
				'active'           => is_plugin_active( $file ),
				'update_available' => $update_available,
				'update_version'   => $update_version,
			);
		}
		$spam = wp_count_comments();
		if ( ! is_object( $spam ) || ! isset( $spam->spam ) || ! is_numeric( $spam->spam ) ) {
			return new \WP_Error( 'inventory_spam_count_unavailable' );
		}
		$payload = self::report_payload( $plugins, absint( $spam->spam ), get_bloginfo( 'version' ) );
		$json = wp_json_encode( $payload, JSON_UNESCAPED_SLASHES );
		if ( false === $json || strlen( $json ) > self::MAX_PAYLOAD_BYTES ) {
			return new \WP_Error( 'inventory_payload_limit' );
		}
		return $payload;
	}

	/** Build the schema-versioned report. @param array<int,array<string,mixed>> $plugins @param int $spam_count @param string $wordpress_version @return array<string,mixed> */
	public static function report_payload( $plugins, $spam_count, $wordpress_version ) {
		$default_schema = defined( 'MONITOR_CONNECTOR_SCHEMA_VERSION' ) ? MONITOR_CONNECTOR_SCHEMA_VERSION : '1.1';
		$schema_version = apply_filters( 'monitor_connector_schema_version', $default_schema );
		if ( ! in_array( $schema_version, array( '1.0', '1.1' ), true ) ) {
			$schema_version = '1.0';
		}
		$plugins = array_map(
			static function ( $plugin ) {
				if ( ! is_array( $plugin ) ) {
					return $plugin;
				}
				if ( array_key_exists( 'update_available', $plugin ) ) {
					$plugin['update_status'] = true === $plugin['update_available'] ? 'available' : ( false === $plugin['update_available'] ? 'unavailable' : 'unknown' );
					unset( $plugin['update_available'] );
				} elseif ( ! isset( $plugin['update_status'] ) || ! in_array( $plugin['update_status'], array( 'available', 'unavailable', 'unknown' ), true ) ) {
					$plugin['update_status'] = 'unknown';
				}
				return $plugin;
			},
			$plugins
		);
		$payload = array(
			'schema_version' => (float) $schema_version,
			'request_id'     => self::request_id(),
			'collected_at'   => gmdate( 'Y-m-d\TH:i:s\Z' ),
			'wordpress_version' => sanitize_text_field( $wordpress_version ),
			'plugins'        => $plugins,
			'spam_comment_count' => absint( $spam_count ),
		);
		if ( '1.1' === $schema_version ) {
			$payload['security'] = self::security_status( $plugins );
		}
		return $payload;
	}

	/**
	 * Vulnerabilities are matched centrally; this connector reports a bounded core
	 * checksum comparison but does not claim malware or activity scanning.
	 * @param array<int,array<string,mixed>> $plugins
	 * @return array<string,mixed>
	 */
	public static function security_status( $plugins ) {
		return array(
			'vulnerability_data' => array(
				'status'       => 'unavailable',
				'source'       => null,
				'checked_at'   => null,
				'findings'     => array(),
				'note'         => 'Vulnerability matching is performed centrally by Monitor using installed plugin slugs and versions; no site-side vulnerability findings are included.',
			),
			'suspicious_activity' => array(
				'status'       => 'unsupported',
				'source'       => null,
				'findings'     => array(),
			),
			'core_integrity' => self::check_core_integrity(),
			'last_successful_scan_at' => null,
			'scan_status'             => 'unsupported',
		);
	}

	/** Compare official WordPress core files against WordPress.org checksums. */
	private static function check_core_integrity() {
		$unavailable = array(
			'status' => 'unavailable',
			'source' => null,
			'checked_at' => null,
			'checked_file_count' => 0,
			'modified_file_count' => 0,
			'missing_file_count' => 0,
			'modified_files' => array(),
			'missing_files' => array(),
			'findings_truncated' => false,
		);
		if ( ! function_exists( 'get_core_checksums' ) ) {
			$update_file = ABSPATH . 'wp-admin/includes/update.php';
			if ( ! is_file( $update_file ) ) {
				return $unavailable;
			}
			require_once $update_file;
		}
		if ( ! function_exists( 'get_core_checksums' ) || ! function_exists( 'get_locale' ) ) {
			return $unavailable;
		}
		$checksums = get_core_checksums( get_bloginfo( 'version' ), get_locale() );
		if ( ! is_array( $checksums ) || empty( $checksums ) || count( $checksums ) > self::MAX_CORE_FILES ) {
			return $unavailable;
		}
		$root = realpath( ABSPATH );
		if ( false === $root ) {
			return $unavailable;
		}
		$root = rtrim( wp_normalize_path( $root ), '/' ) . '/';
		$modified = array();
		$missing = array();
		$modified_count = 0;
		$missing_count = 0;
		foreach ( $checksums as $relative => $expected ) {
			if ( ! is_string( $relative ) || '' === $relative || ! preg_match( '#\A[A-Za-z0-9._/-]+\z#', $relative ) || '/' === $relative[0] || preg_match( '#(?:^|/)\.\.(?:/|$)#', $relative ) || ! is_string( $expected ) || ! preg_match( '/\A[a-f0-9]{32}\z/i', $expected ) ) {
				return $unavailable;
			}
			$path = ABSPATH . $relative;
			if ( ! is_file( $path ) ) {
				$missing_count++;
				if ( count( $missing ) < self::MAX_CORE_FINDINGS ) {
					$missing[] = $relative;
				}
				continue;
			}
			$real_file = realpath( $path );
			if ( false === $real_file || 0 !== strpos( wp_normalize_path( $real_file ), $root ) ) {
				return $unavailable;
			}
			$actual = md5_file( $real_file );
			if ( false === $actual ) {
				return $unavailable;
			}
			if ( ! hash_equals( strtolower( $expected ), strtolower( $actual ) ) ) {
				$modified_count++;
				if ( count( $modified ) < self::MAX_CORE_FINDINGS ) {
					$modified[] = $relative;
				}
			}
		}
		return array(
			'status' => 'complete',
			'source' => 'wordpress_core_checksums',
			'checked_at' => gmdate( 'Y-m-d\TH:i:s\Z' ),
			'checked_file_count' => count( $checksums ),
			'modified_file_count' => $modified_count,
			'missing_file_count' => $missing_count,
			'modified_files' => $modified,
			'missing_files' => $missing,
			'findings_truncated' => $modified_count > count( $modified ) || $missing_count > count( $missing ),
		);
	}

	/** @param string $file @param array<string,mixed> $data @return string */
	public static function plugin_slug( $file, $data ) {
		$parts = explode( '/', dirname( $file ) );
		if ( '.' !== $parts[0] ) {
			$slug = $parts[0];
		} else {
			$slug = basename( $file, '.php' );
		}
		return sanitize_key( $slug );
	}

	/** @return string */
	public static function request_id() {
		if ( function_exists( 'wp_generate_uuid4' ) ) {
			return wp_generate_uuid4();
		}
		return bin2hex( random_bytes( 16 ) );
	}
}
