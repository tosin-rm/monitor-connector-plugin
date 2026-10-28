<?php
/** Read-only inventory collector. */

namespace MonitorConnector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Inventory {
	const MAX_PLUGINS = 500;
	const MAX_PAYLOAD_BYTES = 262144;

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
		$schema_version = apply_filters( 'monitor_connector_schema_version', '1.0' );
		if ( ! in_array( $schema_version, array( '1.0', '1.1' ), true ) ) {
			$schema_version = '1.0';
		}
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
	 * Security inputs remain unknown until a documented source or supported scanner
	 * integration is configured. Inventory collection is never represented as a scan.
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
				'note'         => 'No approved vulnerability source is configured on this site; Monitor should perform central lookups using plugin slug and installed version.',
			),
			'suspicious_activity' => array(
				'status'       => 'unsupported',
				'source'       => null,
				'findings'     => array(),
			),
			'last_successful_scan_at' => null,
			'scan_status'             => 'unsupported',
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
