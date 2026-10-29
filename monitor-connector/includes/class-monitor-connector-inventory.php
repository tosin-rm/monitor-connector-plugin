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
	const MAX_PLUGIN_CHECKSUM_FETCHES = 8;
	const MAX_EXTENSION_CHECKSUM_FILES = 5000;
	const MAX_PLUGIN_CHECKSUM_FILE_TOTAL = 20000;
	const MAX_FILE_SCAN_FILES = 2000;
	const MAX_FILE_SCAN_BYTES = 20971520;
	const MAX_FILE_SCAN_FINDINGS = 100;

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
	 * Vulnerabilities are matched centrally; this connector reports bounded local
	 * checksum and static file checks, without claiming antivirus or activity-log coverage.
	 * @param array<int,array<string,mixed>> $plugins
	 * @return array<string,mixed>
	 */
	public static function security_status( $plugins ) {
		$file_scan = self::scan_local_code();
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
			'software_integrity' => self::check_plugin_integrity( $plugins ),
			'local_file_scan' => $file_scan,
			'last_successful_scan_at' => null,
			'scan_status'             => 'unsupported',
		);
	}

	/** Compare official WordPress core files against WordPress.org checksums. */
	private static function check_core_integrity() {
		$unavailable = array(
			'status' => 'unavailable',
			'reason' => 'checksum_check_failed',
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
				$unavailable['reason'] = 'checksum_api_missing';
				return $unavailable;
			}
			require_once $update_file;
		}
		if ( ! function_exists( 'get_core_checksums' ) || ! function_exists( 'get_locale' ) ) {
			$unavailable['reason'] = 'checksum_api_missing';
			return $unavailable;
		}
		$checksums = get_core_checksums( get_bloginfo( 'version' ), get_locale() );
		if ( ! is_array( $checksums ) || empty( $checksums ) || count( $checksums ) > self::MAX_CORE_FILES ) {
			$unavailable['reason'] = 'checksum_list_unavailable';
			return $unavailable;
		}
		$root = realpath( ABSPATH );
		if ( false === $root ) {
			$unavailable['reason'] = 'wordpress_root_unavailable';
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
				$unavailable['reason'] = 'core_path_unreadable';
				return $unavailable;
			}
			$actual = md5_file( $real_file );
			if ( false === $actual ) {
				$unavailable['reason'] = 'core_path_unreadable';
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
			'reason' => null,
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

	/** Check installed plugins against WordPress.org checksums when that source has a checksum set. */
	private static function check_plugin_integrity( $plugins ) {
		$result = array(
			'status' => empty( $plugins ) ? 'not_run' : 'unavailable',
			'source' => null,
			'checked_at' => null,
			'checked_plugin_count' => 0,
			'unavailable_plugin_count' => 0,
			'not_checked_plugin_count' => 0,
			'checked_file_count' => 0,
			'modified_file_count' => 0,
			'missing_file_count' => 0,
			'modified_files' => array(),
			'missing_files' => array(),
			'findings_truncated' => false,
		);
		if ( empty( $plugins ) || ! function_exists( 'get_plugins' ) || ! defined( 'WP_PLUGIN_DIR' ) ) {
			return $result;
		}
		$plugin_files = get_plugins();
		if ( ! is_array( $plugin_files ) ) {
			return $result;
		}
		$directories = array();
		foreach ( $plugin_files as $file => $data ) {
			$slug = self::plugin_slug( $file, $data );
			if ( ! isset( $directories[ $slug ] ) ) {
				$directories[ $slug ] = '.' === dirname( $file ) ? WP_PLUGIN_DIR : trailingslashit( WP_PLUGIN_DIR ) . dirname( $file );
			}
		}
		$fetches = 0;
		foreach ( $plugins as $plugin ) {
			$slug = isset( $plugin['slug'] ) ? sanitize_key( $plugin['slug'] ) : '';
			$version = isset( $plugin['version'] ) ? (string) $plugin['version'] : '';
			if ( ! preg_match( '/\A[a-z0-9_-]{1,100}\z/', $slug ) || ! preg_match( '/\A[0-9]+(?:\.[0-9A-Za-z_-]+)*\z/', $version ) || ! isset( $directories[ $slug ] ) ) {
				$result['unavailable_plugin_count']++;
				continue;
			}
			$cache_key = 'mc_plugin_sum_' . md5( $slug . ':' . $version );
			$cached = get_transient( $cache_key );
			if ( false === $cached && $fetches < self::MAX_PLUGIN_CHECKSUM_FETCHES ) {
				$fetches++;
				$cached = self::download_plugin_checksums( $slug, $version );
				if ( is_array( $cached ) ) {
					set_transient( $cache_key, $cached, 12 * HOUR_IN_SECONDS );
				}
			}
			if ( ! is_array( $cached ) || empty( $cached['files'] ) || ! is_array( $cached['files'] ) ) {
				if ( false === $cached && $fetches >= self::MAX_PLUGIN_CHECKSUM_FETCHES ) {
					$result['not_checked_plugin_count']++;
				} else {
					$result['unavailable_plugin_count']++;
				}
				continue;
			}
			$checksums = $cached['files'];
			if ( count( $checksums ) > self::MAX_EXTENSION_CHECKSUM_FILES || $result['checked_file_count'] + count( $checksums ) > self::MAX_PLUGIN_CHECKSUM_FILE_TOTAL ) {
				$result['not_checked_plugin_count']++;
				continue;
			}
			$plugin_root = realpath( $directories[ $slug ] );
			if ( false === $plugin_root || ! is_dir( $plugin_root ) ) {
				$result['unavailable_plugin_count']++;
				continue;
			}
			$plugin_modified = 0;
			$plugin_missing = 0;
			$plugin_modified_files = array();
			$plugin_missing_files = array();
			$valid = true;
			foreach ( $checksums as $relative => $expected ) {
				if ( ! is_string( $relative ) || '' === $relative || ! preg_match( '#\A[A-Za-z0-9._/-]+\z#', $relative ) || '/' === $relative[0] || preg_match( '#(?:^|/)\.\.(?:/|$)#', $relative ) || ! is_string( $expected ) || ! preg_match( '/\A[a-f0-9]{32}\z/i', $expected ) ) {
					$valid = false;
					break;
				}
				$path = trailingslashit( $plugin_root ) . $relative;
				if ( ! is_file( $path ) ) {
					$plugin_missing++;
					$plugin_missing_files[] = $slug . '/' . $relative;
					continue;
				}
				$real_file = realpath( $path );
				if ( false === $real_file || 0 !== strpos( wp_normalize_path( $real_file ), trailingslashit( wp_normalize_path( $plugin_root ) ) ) ) {
					$valid = false;
					break;
				}
				$actual = md5_file( $real_file );
				if ( false === $actual ) {
					$valid = false;
					break;
				}
				if ( ! hash_equals( strtolower( $expected ), strtolower( $actual ) ) ) {
					$plugin_modified++;
					$plugin_modified_files[] = $slug . '/' . $relative;
				}
			}
			if ( ! $valid ) {
				$result['unavailable_plugin_count']++;
				continue;
			}
			$result['checked_plugin_count']++;
			$result['checked_file_count'] += count( $checksums );
			$result['modified_file_count'] += $plugin_modified;
			$result['missing_file_count'] += $plugin_missing;
			$result['modified_files'] = array_merge( $result['modified_files'], array_slice( $plugin_modified_files, 0, max( 0, self::MAX_CORE_FINDINGS - count( $result['modified_files'] ) ) ) );
			$result['missing_files'] = array_merge( $result['missing_files'], array_slice( $plugin_missing_files, 0, max( 0, self::MAX_CORE_FINDINGS - count( $result['missing_files'] ) ) ) );
		}
		$checked_total = $result['checked_plugin_count'] + $result['unavailable_plugin_count'] + $result['not_checked_plugin_count'];
		$result['not_checked_plugin_count'] += max( 0, count( $plugins ) - $checked_total );
		if ( $result['checked_plugin_count'] > 0 ) {
			$result['source'] = 'wordpress_org_plugin_checksums';
			$result['checked_at'] = gmdate( 'Y-m-d\TH:i:s\Z' );
			$result['status'] = $result['unavailable_plugin_count'] || $result['not_checked_plugin_count'] ? 'partial' : 'complete';
		}
		$result['findings_truncated'] = $result['modified_file_count'] > count( $result['modified_files'] ) || $result['missing_file_count'] > count( $result['missing_files'] );
		return $result;
	}

	/** Fetch and strictly validate one public WordPress.org plugin checksum document. */
	private static function download_plugin_checksums( $slug, $version ) {
		$url = 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json';
		$response = wp_remote_get( $url, array( 'timeout' => 2, 'redirection' => 0, 'limit_response_size' => 2097152, 'headers' => array( 'Accept' => 'application/json' ) ) );
		if ( is_wp_error( $response ) ) {
			return false;
		}
		$status = wp_remote_retrieve_response_code( $response );
		if ( 404 === $status ) {
			return array( 'unsupported' => true );
		}
		if ( 200 !== $status ) {
			return false;
		}
		$body = wp_remote_retrieve_body( $response );
		if ( ! is_string( $body ) || '' === $body || strlen( $body ) >= 2097152 ) {
			return false;
		}
		$data = json_decode( $body, true );
		return is_array( $data ) && isset( $data['files'] ) && is_array( $data['files'] ) ? array( 'files' => $data['files'] ) : false;
	}

	/** Bounded heuristic inspection of PHP files; reads contents locally and reports only paths/rule names. */
	private static function scan_local_code() {
		$result = array( 'status' => 'unavailable', 'source' => 'monitor_connector_static_checks', 'coverage' => 'partial', 'checked_at' => null, 'checked_file_count' => 0, 'findings' => array(), 'findings_truncated' => false );
		if ( ! defined( 'WP_CONTENT_DIR' ) || ! is_dir( WP_CONTENT_DIR ) || ! is_readable( WP_CONTENT_DIR ) ) {
			return $result;
		}
		$content_root = realpath( WP_CONTENT_DIR );
		if ( false === $content_root ) {
			return $result;
		}
		$content_root = trailingslashit( wp_normalize_path( $content_root ) );
		$roots = array( 'plugins', 'themes', 'mu-plugins', 'uploads' );
		$rules = array(
			'obfuscated_dynamic_execution' => array( '/\beval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|convert_uudecode|hex2bin)\s*\(/i', 'high', 'Encoded content is passed directly to dynamic code execution.' ),
			'dynamic_request_include' => array( '/\b(?:include|require)(?:_once)?\s*(?:\(\s*)?\$_(?:GET|POST|REQUEST)\s*\[/i', 'high', 'A request parameter is used directly as an included file path.' ),
		);
		$total_bytes = 0;
		$partial = false;
		foreach ( $roots as $relative_root ) {
			$directory = trailingslashit( WP_CONTENT_DIR ) . $relative_root;
			if ( ! is_dir( $directory ) || ! is_readable( $directory ) ) {
				continue;
			}
			try {
				$iterator = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $directory, \FilesystemIterator::SKIP_DOTS ), \RecursiveIteratorIterator::LEAVES_ONLY );
				foreach ( $iterator as $entry ) {
					if ( $result['checked_file_count'] >= self::MAX_FILE_SCAN_FILES || $total_bytes >= self::MAX_FILE_SCAN_BYTES ) {
						$partial = true;
						break 2;
					}
					if ( ! $entry->isFile() || $entry->isLink() || ! preg_match( '/\.(?:php|phtml|php[0-9]|inc)\z/i', $entry->getFilename() ) ) {
						continue;
					}
					$path = realpath( $entry->getPathname() );
					if ( false === $path || 0 !== strpos( wp_normalize_path( $path ), $content_root ) || ! is_readable( $path ) ) {
						$partial = true;
						continue;
					}
					$size = filesize( $path );
					if ( false === $size || $size > 524288 || $total_bytes + $size > self::MAX_FILE_SCAN_BYTES ) {
						$partial = true;
						continue;
					}
					$contents = file_get_contents( $path );
					if ( false === $contents ) {
						$partial = true;
						continue;
					}
					$result['checked_file_count']++;
					$total_bytes += $size;
					$relative_path = 'wp-content/' . ltrim( substr( wp_normalize_path( $path ), strlen( $content_root ) ), '/' );
					foreach ( $rules as $rule => $definition ) {
						if ( preg_match( $definition[0], $contents ) ) {
							if ( count( $result['findings'] ) < self::MAX_FILE_SCAN_FINDINGS ) {
								$result['findings'][] = array( 'finding_id' => substr( hash( 'sha256', $rule . ':' . $relative_path ), 0, 32 ), 'category' => 'suspicious_activity', 'severity' => $definition[1], 'title' => $definition[2], 'path' => $relative_path, 'rule' => $rule );
							} else {
								$result['findings_truncated'] = true;
							}
						}
					}
					unset( $contents );
				}
			} catch ( \UnexpectedValueException $error ) {
				$partial = true;
			}
		}
		if ( 0 === $result['checked_file_count'] ) {
			return $result;
		}
		$result['status'] = 'complete';
		$result['coverage'] = $partial ? 'partial' : 'complete';
		$result['checked_at'] = gmdate( 'Y-m-d\TH:i:s\Z' );
		return $result;
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
