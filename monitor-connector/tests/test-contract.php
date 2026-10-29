<?php
/** Lightweight contract tests; run with `php tests/test-contract.php` in the plugin directory. */

define( 'ABSPATH', __DIR__ . '/' );
define( 'MONITOR_CONNECTOR_SCHEMA_VERSION', '1.1' );

function sanitize_key( $value ) { return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( $value ) ); }
function sanitize_text_field( $value ) { return (string) $value; }
function absint( $value ) { return abs( (int) $value ); }
function wp_generate_uuid4() { return 'a9c73ac7-4af0-4d8d-87c4-136474eb837f'; }
function wp_json_encode( $value, $flags = 0 ) { return json_encode( $value, $flags ); }
function wp_parse_url( $url ) { return parse_url( $url ); }
function wp_normalize_path( $path ) { return str_replace( '\\', '/', $path ); }
function get_bloginfo( $field ) { return '6.7'; }
function get_locale() { return 'en_US'; }
function get_core_checksums( $version, $locale ) {
	if ( 'unavailable' === ( $GLOBALS['checksum_mode'] ?? '' ) ) { return false; }
	$expected = 'modified' === ( $GLOBALS['checksum_mode'] ?? '' ) ? str_repeat( '0', 32 ) : md5_file( __FILE__ );
	return array( 'test-contract.php' => $expected );
}
function apply_filters( $hook, $value ) { return 'monitor_connector_schema_version' === $hook && isset( $GLOBALS['test_schema'] ) ? $GLOBALS['test_schema'] : $value; }

require_once __DIR__ . '/../includes/class-monitor-connector-inventory.php';
require_once __DIR__ . '/../includes/class-monitor-connector-client.php';
require_once __DIR__ . '/../includes/class-monitor-connector.php';

function assert_same( $expected, $actual, $label ) {
	if ( $expected !== $actual ) { fwrite( STDERR, "FAIL: $label\n" ); exit( 1 ); }
}

assert_same( 'custom-plugin', \MonitorConnector\Inventory::plugin_slug( 'custom-plugin/main.php', array() ), 'directory slug' );
assert_same( 'single', \MonitorConnector\Inventory::plugin_slug( 'single.php', array() ), 'single file slug' );
$security = \MonitorConnector\Inventory::security_status( array() );
assert_same( 'unavailable', $security['vulnerability_data']['status'], 'vulnerability source unavailable' );
assert_same( null, $security['vulnerability_data']['checked_at'], 'no false vulnerability check timestamp' );
assert_same( 'unsupported', $security['suspicious_activity']['status'], 'scanner integration unsupported' );
assert_same( 'complete', $security['core_integrity']['status'], 'core integrity check completes against official checksum values' );
assert_same( 1, $security['core_integrity']['checked_file_count'], 'core integrity reports the checked file count' );
assert_same( 0, $security['core_integrity']['modified_file_count'], 'matching core file checksum produces no finding' );
assert_same( null, $security['last_successful_scan_at'], 'core integrity does not claim a malware scan' );
$GLOBALS['checksum_mode'] = 'modified';
$modified_integrity = \MonitorConnector\Inventory::security_status( array() )['core_integrity'];
assert_same( 1, $modified_integrity['modified_file_count'], 'changed checksum produces a core integrity finding' );
assert_same( array( 'test-contract.php' ), $modified_integrity['modified_files'], 'only the relative core file path is reported' );
$GLOBALS['checksum_mode'] = 'unavailable';
$unavailable_integrity = \MonitorConnector\Inventory::security_status( array() )['core_integrity'];
assert_same( 'unavailable', $unavailable_integrity['status'], 'failed checksum lookup remains unavailable' );
unset( $GLOBALS['checksum_mode'] );
assert_same( 'unsupported', $security['scan_status'], 'inventory is not a scan' );
assert_same( null, $security['last_successful_scan_at'], 'no false scan completion time' );
$is_valid_endpoint = new ReflectionMethod( \MonitorConnector\Client::class, 'valid_endpoint' );
foreach ( array( '/api/report', 'api/report', '/v1/report' ) as $safe_path ) {
	$client = new \MonitorConnector\Client( array( 'pair_endpoint' => $safe_path ) );
	assert_same( true, $is_valid_endpoint->invoke( $client, 'pair_endpoint' ), 'relative endpoint accepted: ' . $safe_path );
}
foreach ( array( '//attacker.example/x', 'https://attacker.example/x', '/x?next=y', '/x#frag', '/x\\\\attacker', "/x\nheader" ) as $unsafe_path ) {
	$client = new \MonitorConnector\Client( array( 'pair_endpoint' => $unsafe_path ) );
	assert_same( false, $is_valid_endpoint->invoke( $client, 'pair_endpoint' ), 'unsafe endpoint rejected' );
}
$GLOBALS['test_schema'] = '1.0';
$legacy = \MonitorConnector\Inventory::report_payload( array(), 0, '6.7' );
assert_same( 1.0, $legacy['schema_version'], 'schema 1.0 compatibility override is numeric' );
assert_same( false, array_key_exists( 'security', $legacy ), 'legacy schema omits new fields' );
$unknown_update = \MonitorConnector\Inventory::report_payload( array( array( 'slug' => 'hello-dolly', 'name' => 'Hello Dolly', 'version' => '1.7.2', 'active' => true, 'update_available' => null, 'update_version' => null ) ), 0, '6.7' );
assert_same( 'unknown', $unknown_update['plugins'][0]['update_status'], 'unknown plugin update state uses the report contract enum' );
assert_same( false, array_key_exists( 'update_available', $unknown_update['plugins'][0] ), 'report omits nullable legacy update flag' );
$available_update = \MonitorConnector\Inventory::report_payload( array( array( 'slug' => 'hello-dolly', 'name' => 'Hello Dolly', 'version' => '1.7.2', 'active' => true, 'update_available' => true ) ), 0, '6.7' );
assert_same( 'available', $available_update['plugins'][0]['update_status'], 'available plugin update state uses the report contract enum' );
$GLOBALS['test_schema'] = '1.1';
$modern = \MonitorConnector\Inventory::report_payload( array(), 0, '6.7' );
assert_same( 1.1, $modern['schema_version'], 'security schema version is numeric' );
assert_same( 'unsupported', $modern['security']['scan_status'], 'security report does not claim a malware scan' );
assert_same( 'complete', $modern['security']['core_integrity']['status'], 'core integrity result is included in the report' );
unset( $GLOBALS['test_schema'] );
$default = \MonitorConnector\Inventory::report_payload( array(), 0, '6.7' );
assert_same( 1.1, $default['schema_version'], 'schema 1.1 security reporting is enabled by default' );
$payload = array( 'schema_version' => 1, 'request_id' => 'a9c73ac7-4af0-4d8d-87c4-136474eb837f', 'plugins' => array(), 'spam_comment_count' => 0 );
$raw = wp_json_encode( $payload, JSON_UNESCAPED_SLASHES );
$sig = hash_hmac( 'sha256', $raw, str_repeat( 's', 32 ) );
assert_same( hash_hmac( 'sha256', $raw, str_repeat( 's', 32 ) ), $sig, 'HMAC uses exact raw JSON body' );
assert_same( $sig, \MonitorConnector\Client::sign( $raw, str_repeat( 's', 32 ) ), 'client signer matches HMAC' );
$signed_request = '1234567890.' . $payload['request_id'] . '.' . $raw;
assert_same( hash_hmac( 'sha256', $signed_request, str_repeat( 's', 32 ) ), \MonitorConnector\Client::sign( $signed_request, str_repeat( 's', 32 ) ), 'client signer matches Monitor timestamp and request ID contract' );
assert_same( $raw, \MonitorConnector\Client::encode_payload( $payload ), 'client preserves exact serialized body' );
fwrite( STDOUT, "All contract tests passed.\n" );
