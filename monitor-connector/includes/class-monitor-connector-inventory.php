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
		$payload = array(
			'schema_version' => MONITOR_CONNECTOR_SCHEMA_VERSION,
			'request_id'     => self::request_id(),
			'collected_at'   => gmdate( 'Y-m-d\TH:i:s\Z' ),
			'wordpress_version' => sanitize_text_field( get_bloginfo( 'version' ) ),
			'plugins'        => $plugins,
			'spam_comment_count' => absint( $spam->spam ),
		);
		$json = wp_json_encode( $payload, JSON_UNESCAPED_SLASHES );
		if ( false === $json || strlen( $json ) > self::MAX_PAYLOAD_BYTES ) {
			return new \WP_Error( 'inventory_payload_limit' );
		}
		return $payload;
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
