<?php
/** HTTPS transport and request signing. */

namespace MonitorConnector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Client {
	const TIMEOUT = 12;
	const MAX_RESPONSE_BYTES = 8192;

	/** @var array<string,mixed> */
	private $settings;

	/** @param array<string,mixed> $settings */
	public function __construct( $settings ) {
		$this->settings = $settings;
	}

	/** @param string $code @return array<string,string>|\WP_Error */
	public function pair( $code ) {
		if ( ! is_string( $code ) || '' === trim( $code ) || strlen( $code ) > 256 || ! $this->valid_base() ) {
			return new \WP_Error( 'pair_invalid_input' );
		}
		$body = array( 'pairing_code' => trim( $code ), 'plugin_version' => MONITOR_CONNECTOR_VERSION );
		$response = $this->post( $this->endpoint( 'pair_endpoint' ), $body );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) || empty( $data['connection_id'] ) || empty( $data['credential_id'] ) || empty( $data['secret'] ) || ! self::valid_identifier( $data['connection_id'] ) || ! self::valid_identifier( $data['credential_id'] ) || ! self::valid_secret( $data['secret'] ) ) {
			return new \WP_Error( 'pair_invalid_response' );
		}
		return array(
			'connection_id' => sanitize_text_field( $data['connection_id'] ),
			'credential_id' => sanitize_text_field( $data['credential_id'] ),
			'secret' => $data['secret'],
		);
	}

	/** @param array<string,mixed> $payload @return true|\WP_Error */
	public function report( $payload ) {
		if ( ! $this->valid_base() || ! self::valid_secret( $this->settings['secret'] ) ) {
			return new \WP_Error( 'report_not_configured' );
		}
		$raw = self::encode_payload( $payload );
		if ( false === $raw || strlen( $raw ) > Inventory::MAX_PAYLOAD_BYTES ) {
			return new \WP_Error( 'report_payload_limit' );
		}
		$time = (string) time();
		$request_id = isset( $payload['request_id'] ) ? $payload['request_id'] : Inventory::request_id();
		$signature = self::sign( $raw, $this->settings['secret'] );
		$headers = array(
			'Content-Type' => 'application/json; charset=utf-8',
			'Accept' => 'application/json',
			'X-Monitor-Connection-Id' => $this->settings['connection_id'],
			'X-Monitor-Key-Id' => $this->settings['credential_id'],
			'X-Monitor-Timestamp' => $time,
			'X-Monitor-Request-Id' => $request_id,
			'X-Monitor-Signature' => 'sha256=' . $signature,
		);
		$response = wp_remote_post( $this->endpoint( 'report_endpoint' ), array( 'timeout' => self::TIMEOUT, 'redirection' => 0, 'headers' => $headers, 'body' => $raw, 'data_format' => 'body', 'limit_response_size' => self::MAX_RESPONSE_BYTES, 'sslverify' => true ) );
		if ( is_wp_error( $response ) ) {
			return new \WP_Error( 'report_transport_error' );
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( $code < 200 || $code >= 300 ) {
			return new \WP_Error( 'report_http_error', '', array( 'status' => $code ) );
		}
		return true;
	}

	/** Encode once so signed bytes are the transmitted bytes. @param array<string,mixed> $payload @return string|false */
	public static function encode_payload( $payload ) {
		return wp_json_encode( $payload, JSON_UNESCAPED_SLASHES );
	}

	/** @param string $raw @param string $secret @return string */
	public static function sign( $raw, $secret ) {
		return hash_hmac( 'sha256', $raw, $secret );
	}

	/** @return true|\WP_Error */
	public function revoke() {
		if ( ! $this->valid_base() ) {
			return new \WP_Error( 'revoke_invalid_url' );
		}
		$raw = wp_json_encode( array( 'connection_id' => $this->settings['connection_id'] ), JSON_UNESCAPED_SLASHES );
		$time = (string) time();
		$request_id = Inventory::request_id();
		$headers = array(
			'Content-Type' => 'application/json; charset=utf-8',
			'X-Monitor-Connection-Id' => $this->settings['connection_id'],
			'X-Monitor-Key-Id' => $this->settings['credential_id'],
			'X-Monitor-Timestamp' => $time,
			'X-Monitor-Request-Id' => $request_id,
			'X-Monitor-Signature' => 'sha256=' . self::sign( $raw, $this->settings['secret'] ),
		);
		$response = wp_remote_post( $this->endpoint( 'revoke_endpoint' ), array( 'timeout' => self::TIMEOUT, 'redirection' => 0, 'headers' => $headers, 'body' => $raw, 'data_format' => 'body', 'limit_response_size' => self::MAX_RESPONSE_BYTES, 'sslverify' => true ) );
		if ( is_wp_error( $response ) || (int) wp_remote_retrieve_response_code( $response ) < 200 || (int) wp_remote_retrieve_response_code( $response ) >= 300 ) {
			return new \WP_Error( 'revoke_remote_failed' );
		}
		return true;
	}

	/** @param string $endpoint_key @return string */
	private function endpoint( $endpoint_key ) {
		$base = untrailingslashit( $this->settings['monitor_url'] );
		$path = '/' . ltrim( $this->settings[ $endpoint_key ], '/' );
		return $base . $path;
	}

	/** @return bool */
	private function valid_base() {
		return Plugin::valid_base_url( $this->settings['monitor_url'] );
	}

	/** @param array<string,mixed> $body @return array<string,mixed>|\WP_Error */
	private function post( $url, $body ) {
		$raw = wp_json_encode( $body, JSON_UNESCAPED_SLASHES );
		$response = wp_remote_post( $url, array( 'timeout' => self::TIMEOUT, 'redirection' => 0, 'headers' => array( 'Content-Type' => 'application/json; charset=utf-8', 'Accept' => 'application/json' ), 'body' => $raw, 'data_format' => 'body', 'limit_response_size' => self::MAX_RESPONSE_BYTES, 'sslverify' => true ) );
		if ( is_wp_error( $response ) ) {
			return new \WP_Error( 'pair_transport_error' );
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( $code < 200 || $code >= 300 ) {
			return new \WP_Error( 'pair_http_error' );
		}
		return $response;
	}

	/** @param mixed $value @return bool */
	private static function valid_identifier( $value ) {
		return is_string( $value ) && (bool) preg_match( '/\A[a-zA-Z0-9_-]{1,128}\z/', $value );
	}

	/** @param mixed $value @return bool */
	private static function valid_secret( $value ) {
		return is_string( $value ) && strlen( $value ) >= 32 && strlen( $value ) <= 512 && ! preg_match( '/[\r\n]/', $value );
	}
}
