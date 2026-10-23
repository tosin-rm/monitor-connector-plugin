<?php
/** Main plugin orchestration. */

namespace MonitorConnector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once __DIR__ . '/class-monitor-connector-inventory.php';
require_once __DIR__ . '/class-monitor-connector-client.php';

final class Plugin {
	const OPTION = 'monitor_connector_settings';
	const CRON_HOOK = 'monitor_connector_send_report';
	const DEFAULT_INTERVAL = 6;
	const MAX_INTERVAL = 24;

	/** @var Plugin|null */
	private static $instance = null;

	/** @return Plugin */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public static function activate() {
		if ( ! get_option( self::OPTION ) ) {
			add_option( self::OPTION, self::defaults(), '', false );
		}
		self::schedule();
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	/** @return array<string,mixed> */
	public static function defaults() {
		return array(
			'monitor_url'       => '',
			'pair_endpoint'     => '/api/monitor-connector/pair',
			'report_endpoint'   => '/api/monitor-connector/report',
			'revoke_endpoint'   => '/api/monitor-connector/revoke',
			'interval_hours'    => self::DEFAULT_INTERVAL,
			'connection_id'     => '',
			'credential_id'     => '',
			'secret'            => '',
			'last_success_gmt'  => '',
			'last_error'        => '',
		);
	}

	private function __construct() {
		add_action( 'admin_menu', array( $this, 'add_settings_page' ) );
		add_action( 'admin_post_monitor_connector_save', array( $this, 'save_settings' ) );
		add_action( 'admin_post_monitor_connector_pair', array( $this, 'pair' ) );
		add_action( 'admin_post_monitor_connector_test', array( $this, 'send_test' ) );
		add_action( 'admin_post_monitor_connector_disconnect', array( $this, 'disconnect' ) );
		add_action( self::CRON_HOOK, array( $this, 'send_scheduled' ) );
		add_filter( 'cron_schedules', array( $this, 'cron_schedules' ) );
		add_action( 'init', array( __CLASS__, 'ensure_schedule' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_init', array( $this, 'register_privacy_text' ) );
	}

	/** @param array<string,int> $schedules @return array<string,array<string,mixed>> */
	public function cron_schedules( $schedules ) {
		$settings = self::settings();
		$hours    = self::interval_hours( $settings['interval_hours'] );
		$key      = 'monitor_connector_' . $hours . '_hours';
		$schedules[ $key ] = array(
			'interval' => $hours * HOUR_IN_SECONDS,
			'display'  => sprintf( __( 'Every %d hours (Monitor Connector)', 'monitor-connector' ), $hours ),
		);
		return $schedules;
	}

	public static function ensure_schedule() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			self::schedule();
		}
	}

	private static function schedule() {
		$settings = self::settings();
		$hours    = self::interval_hours( $settings['interval_hours'] );
		$key      = 'monitor_connector_' . $hours . '_hours';
		wp_clear_scheduled_hook( self::CRON_HOOK );
		$max_jitter = min( 900, ( $hours * HOUR_IN_SECONDS ) / 20 );
		wp_schedule_event( time() + HOUR_IN_SECONDS + wp_rand( 0, (int) $max_jitter ), $key, self::CRON_HOOK );
	}

	/** @param mixed $value @return int */
	private static function interval_hours( $value ) {
		$hours = absint( $value );
		return max( 1, min( self::MAX_INTERVAL, $hours ? $hours : self::DEFAULT_INTERVAL ) );
	}

	/** @return array<string,mixed> */
	public static function settings() {
		return wp_parse_args( get_option( self::OPTION, array() ), self::defaults() );
	}

	public function register_settings() {
		register_setting( 'monitor_connector', self::OPTION, array( $this, 'sanitize_settings' ) );
	}

	/** @param mixed $input @return array<string,mixed> */
	public function sanitize_settings( $input ) {
		$current = self::settings();
		$input   = is_array( $input ) ? $input : array();
		$url     = isset( $input['monitor_url'] ) ? esc_url_raw( trim( $input['monitor_url'] ) ) : $current['monitor_url'];
		if ( ! self::valid_base_url( $url ) ) {
			$url = $current['monitor_url'];
		}
		$hours = isset( $input['interval_hours'] ) ? self::interval_hours( $input['interval_hours'] ) : self::interval_hours( $current['interval_hours'] );
		$changed = ( $url !== $current['monitor_url'] || $hours !== (int) $current['interval_hours'] );
		$current['monitor_url']    = $url;
		$current['interval_hours'] = $hours;
		if ( $changed ) {
			self::schedule();
		}
		return $current;
	}

	/** @param string $url @return bool */
	public static function valid_base_url( $url ) {
		$parts = wp_parse_url( $url );
		if ( ! is_array( $parts ) || empty( $parts['host'] ) || isset( $parts['user'] ) || isset( $parts['pass'] ) || isset( $parts['query'] ) || isset( $parts['fragment'] ) ) {
			return false;
		}
		$host = strtolower( $parts['host'] );
		$local = in_array( $host, array( 'localhost', '127.0.0.1', '::1' ), true );
		return ( isset( $parts['scheme'] ) && 'https' === strtolower( $parts['scheme'] ) ) || ( $local && isset( $parts['scheme'] ) && 'http' === strtolower( $parts['scheme'] ) );
	}

	public function add_settings_page() {
		add_options_page( __( 'Monitor Connector', 'monitor-connector' ), __( 'Monitor Connector', 'monitor-connector' ), 'manage_options', 'monitor-connector', array( $this, 'render_settings_page' ) );
	}

	public function render_settings_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$settings = self::settings();
		$paired = ! empty( $settings['secret'] ) && ! empty( $settings['connection_id'] );
		$notice = isset( $_GET['mc_notice'] ) ? sanitize_key( wp_unslash( $_GET['mc_notice'] ) ) : '';
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Monitor Connector', 'monitor-connector' ); ?></h1>
			<?php if ( $notice ) : ?><div class="notice notice-info is-dismissible"><p><?php echo esc_html( self::notice_text( $notice ) ); ?></p></div><?php endif; ?>
			<p><?php echo $paired ? esc_html__( 'Paired with Monitor.', 'monitor-connector' ) : esc_html__( 'Not paired. Configure the Monitor server and enter a one-time pairing code.', 'monitor-connector' ); ?></p>
			<?php if ( $paired ) : ?>
				<p><?php esc_html_e( 'Connection ID:', 'monitor-connector' ); ?> <code><?php echo esc_html( $settings['connection_id'] ); ?></code></p>
				<p><?php esc_html_e( 'Last successful sync (UTC):', 'monitor-connector' ); ?> <?php echo $settings['last_success_gmt'] ? esc_html( $settings['last_success_gmt'] ) : esc_html__( 'Never', 'monitor-connector' ); ?></p>
			<?php endif; ?>
			<form method="post" action="options.php">
				<?php settings_fields( 'monitor_connector' ); ?>
				<table class="form-table" role="presentation">
					<tr><th><label for="mc-monitor-url"><?php esc_html_e( 'Monitor base URL', 'monitor-connector' ); ?></label></th><td><input class="regular-text" id="mc-monitor-url" name="<?php echo esc_attr( self::OPTION ); ?>[monitor_url]" type="url" value="<?php echo esc_attr( $settings['monitor_url'] ); ?>" required /><p class="description"><?php esc_html_e( 'HTTPS required. HTTP is allowed only for localhost development.', 'monitor-connector' ); ?></p></td></tr>
					<tr><th><label for="mc-interval"><?php esc_html_e( 'Report interval (hours)', 'monitor-connector' ); ?></label></th><td><input id="mc-interval" name="<?php echo esc_attr( self::OPTION ); ?>[interval_hours]" type="number" min="1" max="24" value="<?php echo esc_attr( (string) $settings['interval_hours'] ); ?>" /></td></tr>
				</table>
				<?php submit_button( __( 'Save settings', 'monitor-connector' ) ); ?>
			</form>
			<?php if ( ! $paired ) : ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="monitor_connector_pair" /><?php wp_nonce_field( 'monitor_connector_pair' ); ?>
				<table class="form-table" role="presentation"><tr><th><label for="mc-code"><?php esc_html_e( 'Pairing code', 'monitor-connector' ); ?></label></th><td><input id="mc-code" class="regular-text" name="pairing_code" type="password" autocomplete="off" required maxlength="256" /></td></tr></table>
				<?php submit_button( __( 'Pair with Monitor', 'monitor-connector' ) ); ?>
			</form>
			<?php else : ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block;margin-right:1em"><input type="hidden" name="action" value="monitor_connector_test" /><?php wp_nonce_field( 'monitor_connector_test' ); ?><?php submit_button( __( 'Send test report', 'monitor-connector' ), 'secondary', 'submit', false ); ?></form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block" onsubmit="return window.confirm('<?php echo esc_js( __( 'Disconnect this website from Monitor? The remote credential will be revoked when possible.', 'monitor-connector' ) ); ?>');"><input type="hidden" name="action" value="monitor_connector_disconnect" /><?php wp_nonce_field( 'monitor_connector_disconnect' ); ?><?php submit_button( __( 'Disconnect and revoke', 'monitor-connector' ), 'delete', 'submit', false ); ?></form>
			<?php endif; ?>
		</div>
		<?php
	}

	/** @param string $notice @return string */
	private static function notice_text( $notice ) {
		$messages = array(
			'saved' => __( 'Settings saved.', 'monitor-connector' ),
			'paired' => __( 'Pairing completed.', 'monitor-connector' ),
			'pair_failed' => __( 'Pairing failed. Check the Monitor URL and pairing code, then try again.', 'monitor-connector' ),
			'sent' => __( 'Test report sent successfully.', 'monitor-connector' ),
			'send_failed' => __( 'Report failed. The stored credentials were retained; check the Monitor endpoint and try later.', 'monitor-connector' ),
			'disconnected' => __( 'Disconnected. Monitor confirmed revocation.', 'monitor-connector' ),
			'disconnect_local' => __( 'Local credentials were removed, but Monitor could not confirm revocation.', 'monitor-connector' ),
		);
		return isset( $messages[ $notice ] ) ? $messages[ $notice ] : '';
	}

	private function authorize_post( $action ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to manage Monitor Connector.', 'monitor-connector' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $action );
	}

	public function save_settings() {
		check_admin_referer( 'monitor_connector-options' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to manage Monitor Connector.', 'monitor-connector' ), '', array( 'response' => 403 ) );
		}
		$input = isset( $_POST[ self::OPTION ] ) ? wp_unslash( $_POST[ self::OPTION ] ) : array();
		$sanitized = $this->sanitize_settings( $input );
		self::save_settings_data( $sanitized );
		self::redirect( 'saved' );
	}

	public function pair() {
		$this->authorize_post( 'monitor_connector_pair' );
		$code = isset( $_POST['pairing_code'] ) ? sanitize_text_field( wp_unslash( $_POST['pairing_code'] ) ) : '';
		$settings = self::settings();
		$client = new Client( $settings );
		$result = $client->pair( $code );
		if ( is_wp_error( $result ) ) {
			self::set_error( $result->get_error_code() );
			self::redirect( 'pair_failed' );
		}
		$settings['connection_id'] = $result['connection_id'];
		$settings['credential_id'] = $result['credential_id'];
		$settings['secret'] = $result['secret'];
		$settings['last_error'] = '';
		self::save_settings_data( $settings );
		self::redirect( 'paired' );
	}

	public function send_test() {
		$this->authorize_post( 'monitor_connector_test' );
		$result = $this->send_report();
		self::redirect( is_wp_error( $result ) ? 'send_failed' : 'sent' );
	}

	public function send_scheduled() {
		$this->send_report();
	}

	/** @return true|\WP_Error */
	private function send_report() {
		$settings = self::settings();
		if ( empty( $settings['secret'] ) || empty( $settings['connection_id'] ) ) {
			return new \WP_Error( 'not_paired' );
		}
		$inventory = Inventory::collect();
		if ( is_wp_error( $inventory ) ) {
			self::set_error( $inventory->get_error_code() );
			return $inventory;
		}
		$client = new Client( $settings );
		$result = $client->report( $inventory );
		if ( is_wp_error( $result ) ) {
			self::set_error( $result->get_error_code() );
			return $result;
		}
		$settings['last_success_gmt'] = gmdate( 'c' );
		$settings['last_error'] = '';
		self::save_settings_data( $settings );
		return true;
	}

	public function disconnect() {
		$this->authorize_post( 'monitor_connector_disconnect' );
		$settings = self::settings();
		$client = new Client( $settings );
		$revoked = empty( $settings['secret'] ) ? true : $client->revoke();
		$settings['connection_id'] = '';
		$settings['credential_id'] = '';
		$settings['secret'] = '';
		$settings['last_success_gmt'] = '';
		$settings['last_error'] = is_wp_error( $revoked ) ? $revoked->get_error_code() : '';
		self::save_settings_data( $settings );
		self::redirect( is_wp_error( $revoked ) ? 'disconnect_local' : 'disconnected' );
	}

	/** @param array<string,mixed> $settings */
	private static function save_settings_data( $settings ) {
		update_option( self::OPTION, $settings, false );
	}

	/** @param string $code */
	private static function set_error( $code ) {
		$settings = self::settings();
		$settings['last_error'] = sanitize_key( $code );
		self::save_settings_data( $settings );
	}

	/** @param string $notice */
	private static function redirect( $notice ) {
		wp_safe_redirect( add_query_arg( 'mc_notice', $notice, admin_url( 'options-general.php?page=monitor-connector' ) ) );
		exit;
	}

	public function register_privacy_text() {
		if ( function_exists( 'wp_add_privacy_policy_content' ) ) {
			$content = '<p>' . esc_html__( 'Monitor Connector sends the WordPress core version, installed plugin slugs, display names and versions, active status, update availability and known update versions, the spam comment count, a UTC collection timestamp, request ID and schema version to the paired Monitor website. Reports also include security source status: this plugin currently marks vulnerability data unavailable for central lookup, marks scanner and suspicious-activity data unsupported, and sends no security findings or scan completion time. This data is used to provide a read-only site health inventory. Monitor controls its retention. Administrators can disconnect and request credential revocation from Settings → Monitor Connector; local credentials are removed even if remote revocation is unavailable.', 'monitor-connector' ) . '</p>';
			wp_add_privacy_policy_content( __( 'Monitor Connector', 'monitor-connector' ), $content );
		}
	}
}
