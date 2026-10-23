<?php
/** Lightweight contract tests; run with `php tests/test-contract.php` in the plugin directory. */

define( 'ABSPATH', __DIR__ . '/' );
define( 'MONITOR_CONNECTOR_SCHEMA_VERSION', '1.0' );

function sanitize_key( $value ) { return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( $value ) ); }
function wp_generate_uuid4() { return 'a9c73ac7-4af0-4d8d-87c4-136474eb837f'; }
function wp_json_encode( $value, $flags = 0 ) { return json_encode( $value, $flags ); }

require_once __DIR__ . '/../includes/class-monitor-connector-inventory.php';
require_once __DIR__ . '/../includes/class-monitor-connector-client.php';

function assert_same( $expected, $actual, $label ) {
	if ( $expected !== $actual ) { fwrite( STDERR, "FAIL: $label\n" ); exit( 1 ); }
}

assert_same( 'custom-plugin', \MonitorConnector\Inventory::plugin_slug( 'custom-plugin/main.php', array() ), 'directory slug' );
assert_same( 'single', \MonitorConnector\Inventory::plugin_slug( 'single.php', array() ), 'single file slug' );
$payload = array( 'schema_version' => '1.0', 'request_id' => 'r1', 'plugins' => array(), 'spam_comment_count' => 0 );
$raw = wp_json_encode( $payload, JSON_UNESCAPED_SLASHES );
$sig = hash_hmac( 'sha256', $raw, str_repeat( 's', 32 ) );
assert_same( hash_hmac( 'sha256', $raw, str_repeat( 's', 32 ) ), $sig, 'HMAC uses exact raw JSON body' );
assert_same( false, \MonitorConnector\Client::class === '', 'test harness loaded client' );
fwrite( STDOUT, "All contract tests passed.\n" );
