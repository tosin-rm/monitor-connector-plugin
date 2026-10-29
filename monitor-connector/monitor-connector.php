<?php
/**
 * Plugin Name: Monitor Connector
 * Description: Sends a read-only WordPress health inventory to a paired Monitor website.
 * Version: 1.3.0
 * Requires at least: 6.2
 * Requires PHP: 7.4
 * Author: Monitor Connector
 * License: GPL-2.0-or-later
 * Text Domain: monitor-connector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'MONITOR_CONNECTOR_VERSION', '1.3.0' );
// The paired Monitor receiver validates and stores schema 1.1 security results.
define( 'MONITOR_CONNECTOR_SCHEMA_VERSION', '1.1' );
define( 'MONITOR_CONNECTOR_OPTION', 'monitor_connector_settings' );
define( 'MONITOR_CONNECTOR_CRON_HOOK', 'monitor_connector_send_report' );

require_once __DIR__ . '/includes/class-monitor-connector.php';

register_activation_hook( __FILE__, array( 'MonitorConnector\\Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'MonitorConnector\\Plugin', 'deactivate' ) );

add_action( 'plugins_loaded', array( 'MonitorConnector\\Plugin', 'instance' ) );
