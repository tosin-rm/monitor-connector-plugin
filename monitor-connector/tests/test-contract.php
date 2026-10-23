<?php
/** Lightweight contract tests; run with `php tests/test-contract.php` in the plugin directory. */

define( 'ABSPATH', __DIR__ . '/' );
define( 'MONITOR_CONNECTOR_SCHEMA_VERSION', '1.0' );

function sanitize_key( $value ) { return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( $value ) ); }
function sanitize_text_field( $value ) { return (string) $value; }
function absint( $value ) { return abs( (int) $value ); }
function wp_generate_uuid4() { return 'a9c73ac7-4af0-4d8d-87c4-136474eb837f'; }
function wp_json_encode( $value, $flags = 0 ) { return json_encode( $value, $flags ); }
function wp_parse_url( $url ) { return parse_url( $url ); }
function apply_filters( $hook, $value ) { return '1.1' === $GLOBALS['test_schema'] && 'monitor_connector_schema_version' === $hook ? '1.1' : $value; }

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
assert_same( '1.0', $legacy['schema_version'], 'default schema is backward compatible' );
assert_same( false, array_key_exists( 'security', $legacy ), 'legacy schema omits new fields' );
$GLOBALS['test_schema'] = '1.1';
$modern = \MonitorConnector\Inventory::report_payload( array(), 0, '6.7' );
assert_same( '1.1', $modern['schema_version'], 'opt-in schema version' );
assert_same( 'unsupported', $modern['security']['scan_status'], 'opt-in security state' );
$payload = array( 'schema_version' => '1.0', 'request_id' => 'r1', 'plugins' => array(), 'spam_comment_count' => 0 );
$raw = wp_json_encode( $payload, JSON_UNESCAPED_SLASHES );
$sig = hash_hmac( 'sha256', $raw, str_repeat( 's', 32 ) );
assert_same( hash_hmac( 'sha256', $raw, str_repeat( 's', 32 ) ), $sig, 'HMAC uses exact raw JSON body' );
assert_same( $sig, \MonitorConnector\Client::sign( $raw, str_repeat( 's', 32 ) ), 'client signer matches HMAC' );
assert_same( $raw, \MonitorConnector\Client::encode_payload( $payload ), 'client preserves exact serialized body' );
fwrite( STDOUT, "All contract tests passed.\n" );
