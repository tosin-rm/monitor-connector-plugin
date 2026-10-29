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
	const CREDENTIAL_OPTION = 'monitor_connector_credentials';
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
			'pair_endpoint'     => '/api/connectors/wordpress/pair',
			'report_endpoint'   => '/api/connectors/wordpress/report',
			'revoke_endpoint'   => '/api/connectors/wordpress/revoke',
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
		$settings = wp_parse_args( get_option( self::OPTION, array() ), self::defaults() );
		$credentials = get_option( self::CREDENTIAL_OPTION, array() );
		if ( is_array( $credentials ) ) {
			foreach ( array( 'connection_id', 'credential_id', 'secret' ) as $key ) {
				if ( array_key_exists( $key, $credentials ) ) {
					$settings[ $key ] = $credentials[ $key ];
				}
			}
		}
		$defaults = self::defaults();
		$legacy = array(
			'pair_endpoint' => '/api/monitor-connector/pair',
			'report_endpoint' => '/api/monitor-connector/report',
			'revoke_endpoint' => '/api/monitor-connector/revoke',
		);
		foreach ( $legacy as $key => $path ) {
			if ( $settings[ $key ] === $path ) {
				$settings[ $key ] = $defaults[ $key ];
			}
		}
		return $settings;
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
		$report_error = isset( $_GET['mc_error'] ) ? sanitize_key( wp_unslash( $_GET['mc_error'] ) ) : '';
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Monitor Connector', 'monitor-connector' ); ?></h1>
			<?php if ( 'paired' === $notice && ! $paired ) : ?>
				<div class="notice notice-error"><p><?php esc_html_e( 'Monitor accepted the pairing, but WordPress does not have the connection credentials saved. The site cannot send reports yet. Check that WordPress can write to its database, then revoke the connector in Monitor and pair again.', 'monitor-connector' ); ?></p></div>
			<?php elseif ( $notice ) : ?><div class="notice notice-info is-dismissible"><p><?php echo esc_html( self::notice_text( $notice ) ); ?></p></div><?php endif; ?>
			<?php if ( 'pair_failed' === $notice && ! empty( $settings['last_error'] ) ) : ?><div class="notice notice-warning"><p><?php echo esc_html( self::pair_diagnostic_text( $settings['last_error'] ) ); ?></p></div><?php endif; ?>
			<?php if ( 'send_failed' === $notice ) : ?><div class="notice notice-warning"><p><?php echo esc_html( self::report_diagnostic_text( $report_error ? $report_error : ( isset( $settings['last_error'] ) ? $settings['last_error'] : '' ) ) ); ?></p></div><?php endif; ?>
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
			'pair_storage_failed' => __( 'Monitor accepted the pairing, but WordPress could not save and verify the connection credentials. Revoke the connector in Monitor before retrying.', 'monitor-connector' ),
			'sent' => __( 'Test report sent successfully.', 'monitor-connector' ),
			'send_failed' => __( 'Report failed. The stored credentials were retained; check the Monitor endpoint and try later.', 'monitor-connector' ),
			'disconnected' => __( 'Disconnected. Monitor confirmed revocation.', 'monitor-connector' ),
			'disconnect_local' => __( 'Local credentials were removed, but Monitor could not confirm revocation.', 'monitor-connector' ),
		);
		return isset( $messages[ $notice ] ) ? $messages[ $notice ] : '';
	}

	/** Show a safe, actionable pairing diagnosis without exposing response bodies or credentials. @param string $error @return string */
	private static function pair_diagnostic_text( $error ) {
		$messages = array(
			'pair_invalid_input'     => __( 'The saved Monitor URL or pairing code is not in an accepted format. Check the URL and use a fresh code.', 'monitor-connector' ),
			'pair_transport_error'   => __( 'WordPress could not connect to Monitor over HTTPS. The request may be blocked by DNS, TLS validation, a timeout, or outbound network rules.', 'monitor-connector' ),
			'pair_invalid_response'  => __( 'Monitor responded, but did not return the expected pairing credentials. Check the Monitor deployment logs.', 'monitor-connector' ),
			'pair_http_400'          => __( 'Monitor received the request but rejected its format. Create a fresh pairing code and enter it exactly as shown.', 'monitor-connector' ),
			'pair_http_401'          => __( 'Monitor rejected the pairing code. It may be expired, already used, or entered incorrectly. Create a fresh code and try once.', 'monitor-connector' ),
			'pair_http_409'          => __( 'Monitor could not pair this website. Confirm it is active and set to WordPress, then create a fresh code.', 'monitor-connector' ),
			'pair_http_413'          => __( 'Monitor rejected the request because it was too large. Check that the pairing code field contains only the code.', 'monitor-connector' ),
			'pair_http_500'          => __( 'Monitor encountered a server or database error while pairing. Check the Monitor deployment logs.', 'monitor-connector' ),
			'pair_http_503'          => __( 'Monitor pairing is temporarily unavailable. Check its encryption key and database configuration, then try with a fresh code.', 'monitor-connector' ),
		);
		if ( isset( $messages[ $error ] ) ) {
			return $messages[ $error ];
		}
		if ( preg_match( '/\\Apair_http_([1-5][0-9]{2})\\z/', $error, $matches ) ) {
			return sprintf( __( 'Monitor responded with HTTP %s. Check the Monitor deployment logs and create a fresh pairing code before retrying.', 'monitor-connector' ), $matches[1] );
		}
		return __( 'Pairing did not complete. Check the Monitor URL and try with a fresh pairing code.', 'monitor-connector' );
	}

	/** Show a safe report diagnosis; never expose response bodies or signatures. @param string $error @return string */
	private static function report_diagnostic_text( $error ) {
		$messages = array(
			'report_transport_error' => __( 'WordPress could not connect to the Monitor report endpoint. This usually means an outbound HTTPS, DNS, TLS, or timeout problem on the WordPress host.', 'monitor-connector' ),
			'report_not_configured' => __( 'The saved Monitor URL or connection credentials are missing or invalid. Check the settings and reconnect if needed.', 'monitor-connector' ),
			'report_payload_limit' => __( 'The WordPress inventory report is too large or could not be encoded, so it was not sent.', 'monitor-connector' ),
			'report_http_400' => __( 'Monitor received the report but rejected its format. Check that the Monitor deployment is up to date.', 'monitor-connector' ),
			'report_http_401' => __( 'Monitor rejected the connection signature. The saved connector credentials may not match; disconnect and pair again with a fresh code.', 'monitor-connector' ),
			'report_http_409' => __( 'Monitor rejected this report because the connection or website is unavailable, or the request was already received. Check the connector status in Monitor.', 'monitor-connector' ),
			'report_http_413' => __( 'Monitor rejected the report because it was too large.', 'monitor-connector' ),
			'report_http_429' => __( 'Monitor rate-limited the report. Wait a minute, then try once more.', 'monitor-connector' ),
			'report_http_503' => __( 'Monitor received the report but could not process or save it. Check the Vercel runtime logs and Supabase database logs.', 'monitor-connector' ),
		);
		if ( isset( $messages[ $error ] ) ) {
			return $messages[ $error ];
		}
		if ( preg_match( '/\\Areport_http_([1-5][0-9]{2})\\z/', $error, $matches ) ) {
			return sprintf( __( 'Monitor responded with HTTP %s to the report request. Check the Vercel runtime logs at the time of the test.', 'monitor-connector' ), $matches[1] );
		}
		return __( 'The report did not complete. Check the Monitor deployment logs at the time of the test.', 'monitor-connector' );
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
		if ( ! self::save_settings_data( $settings ) ) {
			self::redirect( 'pair_storage_failed' );
		}
		$verified = self::settings();
		if ( empty( $verified['connection_id'] ) || empty( $verified['secret'] ) ) {
			self::redirect( 'pair_storage_failed' );
		}
		self::redirect( 'paired' );
	}

	public function send_test() {
		$this->authorize_post( 'monitor_connector_test' );
		$result = $this->send_report();
		self::redirect( is_wp_error( $result ) ? 'send_failed' : 'sent', is_wp_error( $result ) ? self::report_error_code( $result ) : '' );
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
			self::set_error( self::report_error_code( $result ) );
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

	/** @param array<string,mixed> $settings @return bool */
	private static function save_settings_data( $settings ) {
		$credentials = array(
			'connection_id' => isset( $settings['connection_id'] ) ? $settings['connection_id'] : '',
			'credential_id' => isset( $settings['credential_id'] ) ? $settings['credential_id'] : '',
			'secret'        => isset( $settings['secret'] ) ? $settings['secret'] : '',
		);
		update_option( self::CREDENTIAL_OPTION, $credentials, false );
		$saved_credentials = get_option( self::CREDENTIAL_OPTION, array() );
		$credentials_saved = is_array( $saved_credentials )
			&& isset( $saved_credentials['connection_id'], $saved_credentials['credential_id'], $saved_credentials['secret'] )
			&& $saved_credentials['connection_id'] === $credentials['connection_id']
			&& $saved_credentials['credential_id'] === $credentials['credential_id']
			&& $saved_credentials['secret'] === $credentials['secret'];
		unset( $settings['connection_id'], $settings['credential_id'], $settings['secret'] );
		$settings_saved = update_option( self::OPTION, $settings, false );
		if ( ! $settings_saved ) {
			$stored_settings = get_option( self::OPTION, array() );
			$settings_saved = is_array( $stored_settings )
				&& isset( $stored_settings['monitor_url'] )
				&& $stored_settings['monitor_url'] === ( isset( $settings['monitor_url'] ) ? $settings['monitor_url'] : '' );
		}
		return $credentials_saved && $settings_saved;
	}

	/** @param string $code */
	private static function set_error( $code ) {
		$settings = self::settings();
		$settings['last_error'] = sanitize_key( $code );
		self::save_settings_data( $settings );
	}

	/** @param \WP_Error $error @return string */
	private static function report_error_code( $error ) {
		$code = $error->get_error_code();
		if ( 'report_http_error' === $code ) {
			$data = $error->get_error_data();
			$status = is_array( $data ) && isset( $data['status'] ) ? absint( $data['status'] ) : 0;
			return $status ? 'report_http_' . $status : $code;
		}
		return sanitize_key( $code );
	}

	/** @param string $notice @param string $detail */
	private static function redirect( $notice, $detail = '' ) {
		$args = array( 'mc_notice' => $notice );
		if ( '' !== $detail ) {
			$args['mc_error'] = sanitize_key( $detail );
		}
		wp_safe_redirect( add_query_arg( $args, admin_url( 'options-general.php?page=monitor-connector' ) ) );
		exit;
	}

	public function register_privacy_text() {
		if ( function_exists( 'wp_add_privacy_policy_content' ) ) {
			$content = '<p>' . esc_html__( 'Monitor Connector sends the WordPress core version, installed plugin slugs, display names and versions, active status, update availability and known update versions, the spam comment count, a UTC collection timestamp, request ID and schema version to the paired Monitor website. Reports also include a read-only WordPress core file integrity result with file counts and up to 100 relative paths for files that differ from or are missing from the official checksums. File contents are not sent. Core checksums are retrieved from the official WordPress checksum service. Vulnerability matching is performed centrally by Monitor when configured; this connector does not scan plugins, themes, uploads, activity logs, or malware. No malware scan completion time is claimed. Monitor controls report retention. Administrators can disconnect and request credential revocation from Settings → Monitor Connector; local credentials are removed even if remote revocation is unavailable.', 'monitor-connector' ) . '</p>';
			wp_add_privacy_policy_content( __( 'Monitor Connector', 'monitor-connector' ), $content );
		}
	}
}
