<?php
/**
 * Interactive primary authentication and terminal MFA coordination.
 *
 * @package Cloudbridge 2FA
 * @license GPL-2.0-or-later
 */
namespace cloudbridge2fa;

defined( 'ABSPATH' ) || die( '-1' );

trait Cloudbridge_2FA_Interactive_Login {
    private string $cb2fa_form_browser = '';
    private bool $cb2fa_retry_fields = false;

    private function cb2fa_native( array $context ) : bool {
        return( ( $context['provider_id'] ?? '' ) === 'cb2fa-password' );
    }

    private function cb2fa_available() : bool {
        wp_cache_delete( 'alloptions', 'options' );
        wp_cache_delete( 'active_plugins', 'options' );
        return( is_plugin_active( plugin_basename( dirname( __DIR__ ) . '/cloudbridge-2fa.php' ) ) );
    }

    private function cb2fa_form_cookie() : string {
        return( 'cb2fa_form_v2_' . substr( hash( 'sha256', (string)get_option( 'siteurl' ) . ':' . get_current_blog_id() ), 0, 20 ) );
    }

    /** Prepare independent browser binding before templates start output. */
    public function cb2fa_prepare_form_browser() : void {
        if ( ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
            || ( defined( 'DOING_CRON' ) && DOING_CRON ) || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
            return;
        }
        $value = $_COOKIE[$this->cb2fa_form_cookie()] ?? '';
        if ( is_string( $value ) && preg_match( '/\A[a-f0-9]{64}\z/', $value ) ) {
            $this->cb2fa_form_browser = $value;
        } elseif ( ! headers_sent() ) {
            $value = bin2hex( random_bytes( 32 ) );
            if ( Cloudbridge_2FA_State::set_cookie( $this->cb2fa_form_cookie(), $value, 0 ) ) {
                $this->cb2fa_form_browser = $value;
            }
        }
    }

    /** Same producer for wp-login and standard wp_login_form (including echo=false). */
    public function cb2fa_login_fields( string $markup = '', array $args = [] ) : string {
        if ( $this->cb2fa_retry_fields && current_filter() === 'login_form_bottom' ) { return( $markup ); }
        if ( $this->cb2fa_form_browser === '' ) {
            $this->cb2fa_prepare_form_browser();
        }
        if ( $this->cb2fa_form_browser === '' ) {
            return( $markup ); // Submission rejects with a fresh, usable core form.
        }
        $issued = time();
        $life = max( 1, min( DAY_IN_SECONDS, (int)apply_filters( 'nonce_life', DAY_IN_SECONDS, 'cb2fa-native-form-v2' ) ) );
        $payload = '2:' . get_current_blog_id() . ':' . $issued . ':' . ( $issued + $life ) . ':' . bin2hex( random_bytes( 16 ) );
        $mac = hash_hmac( 'sha256', 'native-post:' . site_url( 'wp-login.php', 'login_post' ) . ':' . $payload . ':' . $this->cb2fa_form_browser, wp_salt( 'nonce' ) );
        return( $markup . '<input type="hidden" name="cb2fa_request" value="' . esc_attr( $payload . ':' . $mac ) . '" />' );
    }

    private function cb2fa_form_request_valid() : bool {
        $value = $_POST['cb2fa_request'] ?? '';
        $browser = $_COOKIE[$this->cb2fa_form_cookie()] ?? '';
        if ( ! is_string( $value ) || ! is_string( $browser ) || ! preg_match( '/\A[a-f0-9]{64}\z/', $browser )
            || ! preg_match( '/\A2:([1-9][0-9]*):([0-9]{1,12}):([0-9]{1,12}):([a-f0-9]{32}):([a-f0-9]{64})\z/', $value, $matches ) ) {
            return( false );
        }
        $issued = (int)$matches[2];
        $deadline = (int)$matches[3];
        $payload = substr( $value, 0, -65 );
        $mac = hash_hmac( 'sha256', 'native-post:' . site_url( 'wp-login.php', 'login_post' ) . ':' . $payload . ':' . $browser, wp_salt( 'nonce' ) );
        return( (int)$matches[1] === get_current_blog_id() && $issued <= time() && time() < $deadline
            && $deadline > $issued && $deadline - $issued <= DAY_IN_SECONDS && hash_equals( $mac, $matches[5] ) );
    }

    private function cb2fa_core_route( string $action ) : bool {
        if ( ( $GLOBALS['pagenow'] ?? '' ) !== 'wp-login.php' || ! did_action( 'login_init' ) || doing_action( 'login_init' )
            || current_filter() !== 'login_form_' . $action
            || realpath( (string)( $_SERVER['SCRIPT_FILENAME'] ?? '' ) ) !== realpath( ABSPATH . 'wp-login.php' ) ) {
            return( false );
        }
        foreach ( [$_GET, $_POST] as $input ) {
            if ( isset( $input['action'] ) && ( ! is_string( $input['action'] ) || $input['action'] !== $action ) ) {
                return( false );
            }
        }
        return( ! isset( $_REQUEST['action'] ) || $_REQUEST['action'] === $action );
    }

    /** Inspect original material before a normalized unknown action can sign on. */
    public function cb2fa_completion_route_guard() : void {
        $completion = isset( $_GET['cb2fa_challenge'] ) || isset( $_POST['cb2fa_challenge'] )
            || ( $_GET['action'] ?? null ) === 'cb2fa_complete' || ( $_POST['action'] ?? null ) === 'cb2fa_complete';
        if ( ! $completion ) { return; }
        if ( ( $_SERVER['REQUEST_METHOD'] ?? '' ) !== 'POST' ) { $this->cb2fa_reject_completion( 405 ); }
        foreach ( [$_GET, $_POST] as $input ) {
            if ( isset( $input['action'] ) && ( ! is_string( $input['action'] ) || $input['action'] !== 'cb2fa_complete' ) ) { $this->cb2fa_reject_completion(); }
        }
        if ( ( $_REQUEST['action'] ?? null ) !== 'cb2fa_complete' ) { $this->cb2fa_reject_completion(); }
    }

    private function cb2fa_native_context_valid( array $context ) : bool {
        $response = $context['response'] ?? null;
        return( $this->cb2fa_native( $context ) && ( $context['schema_version'] ?? null ) === 2
            && is_int( $context['user_id'] ?? null ) && $context['user_id'] > 0
            && ( $context['blog_id'] ?? null ) === get_current_blog_id()
            && is_int( $context['deadline'] ?? null ) && time() < $context['deadline']
            && is_int( $context['verified_at'] ?? null ) && $context['verified_at'] <= time()
            && $context['deadline'] <= $context['verified_at'] + HOUR_IN_SECONDS
            && is_bool( $context['rememberme'] ?? null ) && is_string( $context['wp_login'] ?? null )
            && is_string( $context['wp_email'] ?? null ) && is_string( $context['password_hash'] ?? null )
            && is_int( $context['source_id'] ?? null ) && $context['source_id'] >= 0
            && is_array( $response ) && is_bool( $response['interim'] ?? null ) && is_bool( $response['customize'] ?? null )
            && is_bool( $response['secure'] ?? null ) && is_string( $response['requested'] ?? null )
            && is_string( $context['redirect_to'] ?? null ) && strlen( $context['redirect_to'] ) <= 2048 );
    }

    /** Local only; no provider or authentication callbacks under the account lock. */
    private function cb2fa_local_identity( array $context ) {
        if ( ! $this->cb2fa_available() || ! $this->cb2fa_external_preflight()
            || ( $this->cb2fa_native( $context ) && ! empty( $context['response']['secure'] ) && ! is_ssl() )
            || ( $this->cb2fa_native( $context ) ? ! $this->cb2fa_native_context_valid( $context ) : ! $this->cb2fa_external_context_valid( $context ) ) ) {
            return( $this->cb2fa_external_error( 'context' ) );
        }
        $user = $this->cb2fa_external_fresh_user( $context['user_id'] );
        $current = get_current_user_id();
        $source = $context['source_id'] ?? 0;
        $switch = $this->cb2fa_native( $context ) && $source && $source !== $context['user_id'];
        if ( ! $user instanceof \WP_User || $user->user_login !== $context['wp_login'] || $user->user_email !== $context['wp_email']
            || ! hash_equals( $context['password_hash'], $this->cb2fa_password_fingerprint( $user ) )
            || ( $switch ? $current !== $source : ( $current && $current !== $context['user_id'] ) ) ) {
            return( $this->cb2fa_external_error( 'account' ) );
        }
        return( $user );
    }

    private function cb2fa_final_identity( array $context, array $challenge ) {
        $user = $this->cb2fa_external_policy( $context, 'complete' );
        if ( is_wp_error( $user ) ) { return( $user ); }
        $this->cb2fa_external_refresh();
        if ( ! $challenge && $this->cb2fa_external_factor_policy( $user )['required'] ) { return( $this->cb2fa_external_error( 'factor_required' ) ); }
        if ( $challenge ) {
            $active = $challenge['active_factor'];
            $available = $this->cb2fa_get_user_available_factors( $user );
            $recovery = $active === 'recovery' && $this->cb2fa_totp_factor_enabled() && $this->TOTP->cb2fa_get_active_secret( $user->ID ) !== '';
            if ( ! $recovery && ! in_array( $active, $available, true ) ) { return( $this->cb2fa_external_error( 'factor' ) ); }
        }
        return( $user );
    }

    /** Native credential pass is owned by its caller, never by an exiting filter. */
    private function cb2fa_native_authenticate( string $login, string $password, bool $remember, bool $secure ) {
        $this->cb2fa_external_invocation = ['context' => ['user_id' => 0], 'stage' => 'prefix', 'depth' => count( $GLOBALS['wp_current_filter'] ?? [] ) + 1];
        $had = array_key_exists( 'auth_secure_cookie', $GLOBALS );
        $old = $GLOBALS['auth_secure_cookie'] ?? null;
        try {
            do_action_ref_array( 'wp_authenticate', [&$login, &$password] );
            $secure = apply_filters( 'secure_signon_cookie', $secure, ['user_login' => $login, 'user_password' => $password, 'remember' => $remember] );
            if ( ! is_bool( $secure ) ) {
                return( $this->cb2fa_external_error( 'cookie_policy' ) );
            }
            $GLOBALS['auth_secure_cookie'] = $secure;
            add_filter( 'authenticate', 'wp_authenticate_cookie', 30, 3 );
            $this->cb2fa_external_invocation['stage'] = 'core';
            $user = wp_authenticate( $login, $password );
            $this->cb2fa_external_invocation['stage'] = 'post_core';
            return( is_wp_error( $user ) ? $user : ( $user instanceof \WP_User ? ['user' => $user, 'secure' => $secure] : $this->cb2fa_external_error( 'identity' ) ) );
        } finally {
            if ( $had ) { $GLOBALS['auth_secure_cookie'] = $old; } else { unset( $GLOBALS['auth_secure_cookie'] ); }
            $this->cb2fa_external_invocation = null;
        }
    }

    public function cb2fa_native_login_controller() : void {
        if ( ( $_SERVER['REQUEST_METHOD'] ?? '' ) !== 'POST' ) { return; }
        $response = ['interim' => isset( $_REQUEST['interim-login'] ), 'customize' => isset( $_REQUEST['customize-login'] ), 'requested' => '', 'secure' => is_ssl()];
        $requested = $_REQUEST['redirect_to'] ?? '';
        if ( is_string( $requested ) && strlen( $requested ) <= 2048 ) { $response['requested'] = wp_unslash( $requested ); }
        if ( ! $this->cb2fa_core_route( 'login' ) || ! $this->cb2fa_form_request_valid() ) {
            $this->cb2fa_native_error_form( new \WP_Error( 'cb2fa_request', __( 'Invalid form token, please try again', 'cloudbridge-2fa' ) ), $response );
        }
        if ( headers_sent() || ( empty( $_COOKIE[LOGGED_IN_COOKIE] ) && isset( $_POST['testcookie'] ) && empty( $_COOKIE[TEST_COOKIE] ) ) ) {
            $message = sprintf(
                /* translators: %s: URL to the WordPress documentation on enabling cookies. */
                __( '<strong>Error:</strong> Cookies are blocked or not supported by your browser. You must <a href="%s">enable cookies</a> to use WordPress.', 'default' ),
                __( 'https://developer.wordpress.org/advanced-administration/wordpress/cookies/#enable-cookies-in-your-browser', 'default' )
            );
            $this->cb2fa_native_error_form( new \WP_Error( 'test_cookie', $message ), $response );
        }
        if ( ! $this->cb2fa_external_preflight() ) { $this->cb2fa_native_error_form( $this->cb2fa_external_error( 'preflight' ), $response ); }
        if ( ! empty( $_REQUEST['reauth'] ) ) {
            wp_clear_auth_cookie();
            $url = wp_login_url( wp_validate_redirect( $response['requested'], admin_url() ), true );
            if ( $response['interim'] ) { $url = add_query_arg( 'interim-login', '1', $url ); }
            if ( $response['customize'] ) { $url = add_query_arg( 'customize-login', '1', $url ); }
            wp_safe_redirect( $url ); exit;
        }
        $login = is_string( $_POST['log'] ?? null ) ? wp_unslash( $_POST['log'] ) : '';
        $password = is_string( $_POST['pwd'] ?? null ) ? $_POST['pwd'] : '';
        $remember = ! empty( $_POST['rememberme'] );
        if ( ! force_ssl_admin() ) {
            $lookup = get_user_by( 'login', sanitize_user( $login ) );
            if ( ! $lookup && strpos( $login, '@' ) ) { $lookup = get_user_by( 'email', $login ); }
            if ( $lookup && get_user_option( 'use_ssl', $lookup->ID ) ) { $response['secure'] = true; force_ssl_admin( true ); }
        }
        if ( $response['secure'] && strpos( $response['requested'], 'wp-admin' ) !== false ) {
            $response['requested'] = preg_replace( '|^http://|', 'https://', $response['requested'] );
        }
        $source = get_current_user_id();
        $this->cb2fa_external_busy = true;
        try {
            $authenticated = $this->cb2fa_native_authenticate( $login, $password, $remember, $response['secure'] );
            unset( $password );
            if ( is_wp_error( $authenticated ) ) { $this->cb2fa_native_error_form( $authenticated, $response ); }
            $user = $this->cb2fa_external_fresh_user( $authenticated['user']->ID );
            if ( ! $user instanceof \WP_User ) { $this->cb2fa_native_error_form( $this->cb2fa_external_error( 'account' ), $response ); }
            $response['secure'] = $authenticated['secure'];
            $this->cb2fa_external_refresh();
            $verified = time();
            $context = ['schema_version' => 2, 'provider_id' => 'cb2fa-password', 'user_id' => (int)$user->ID, 'blog_id' => get_current_blog_id(),
                'verified_at' => $verified, 'deadline' => $verified + $this->cb2fa_code_lifetime * MINUTE_IN_SECONDS,
                'wp_login' => $user->user_login, 'wp_email' => $user->user_email, 'password_hash' => $this->cb2fa_password_fingerprint( $user ),
                'rememberme' => $remember, 'redirect_to' => wp_validate_redirect( $response['requested'], admin_url() ), 'source_id' => $source, 'response' => $response];
            $result = $this->cb2fa_begin_interactive( $context, $authenticated['secure'] );
            $this->cb2fa_native_error_form( is_wp_error( $result ) ? $result : $this->cb2fa_external_error( 'completion' ), $response );
        } catch ( \Throwable $error ) {
            $this->cb2fa_native_error_form( $this->cb2fa_external_error( 'exception' ), $response );
        } finally { $this->cb2fa_external_busy = false; }
    }

    private function cb2fa_native_error_form( \WP_Error $error, array $response ) : void {
        $target = wp_validate_redirect( $response['requested'], admin_url() );
        $target = apply_filters( 'login_redirect', $target, $response['requested'], $error );
        $error = apply_filters( 'wp_login_errors', $error, $target );
        $GLOBALS['interim_login'] = $response['interim'];
        if ( function_exists( 'login_header' ) ) { login_header( __( 'Log In', 'default' ), '', $error ); }
        else { status_header( 409 ); echo '<!doctype html><html><body><p>' . esc_html( $error->get_error_message() ) . '</p>'; }
        // This is an actual retry form: preserve wp-login form contributors as
        // well as the standard generator hooks, without duplicate CB2FA fields.
        $fields = function( $markup ) use ( $response ) {
            ob_start(); do_action( 'login_form' ); $markup .= ob_get_clean();
            if ( $response['interim'] ) { $markup .= '<input type="hidden" name="interim-login" value="1" />'; }
            if ( $response['customize'] ) { $markup .= '<input type="hidden" name="customize-login" value="1" />'; }
            return( $markup );
        };
        $this->cb2fa_retry_fields = true;
        add_filter( 'login_form_bottom', $fields, 20 );
        try {
            $username = in_array( $error->get_error_code(), ['incorrect_password', 'empty_password'], true ) && is_string( $_POST['log'] ?? null ) ? wp_unslash( $_POST['log'] ) : '';
            echo wp_login_form( ['echo' => false, 'redirect' => wp_validate_redirect( $target, admin_url() ), 'value_username' => $username, 'value_remember' => ! empty( $_POST['rememberme'] )] );
        } finally {
            remove_filter( 'login_form_bottom', $fields, 20 ); $this->cb2fa_retry_fields = false;
        }
        if ( ! $response['interim'] ) {
            echo '<p id="nav">';
            if ( get_option( 'users_can_register' ) ) {
                // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core's register filter supplies trusted link HTML after the URL and label have been escaped.
                echo apply_filters( 'register', '<a href="' . esc_url( wp_registration_url() ) . '">' . esc_html__( 'Register', 'default' ) . '</a>' ) . ' | ';
            }
            // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Core's lost password filter supplies trusted link HTML after the URL and label have been escaped.
            echo apply_filters( 'lost_password_html_link', '<a href="' . esc_url( wp_lostpassword_url() ) . '">' . esc_html__( 'Lost your password?', 'default' ) . '</a>' );
            echo '</p>';
        }
        if ( $response['interim'] || $response['customize'] ) {
            // Preserve modal context on a fresh retry without retaining credentials.
            echo '<p><a href="' . esc_url( add_query_arg( ['interim-login' => '1', 'customize-login' => $response['customize'] ? '1' : null], wp_login_url() ) ) . '">' . esc_html__( 'Log In', 'default' ) . '</a></p>';
        }
        if ( function_exists( 'login_footer' ) ) { login_footer(); } else { echo '</body></html>'; }
        exit;
    }

    private function cb2fa_begin_interactive( array $context, bool $secure ) {
        $user = $this->cb2fa_external_policy( $context, 'begin' );
        if ( is_wp_error( $user ) ) { return( $user ); }
        $this->cb2fa_external_refresh();
        $policy = $this->cb2fa_external_factor_policy( $user );
        if ( ! $policy['required'] ) { return( $this->cb2fa_external_finalize( $context, $secure ) ); }
        if ( ! Cloudbridge_2FA_State::lock( $user->ID ) ) { return( $this->cb2fa_external_error( 'busy' ) ); }
        try {
            $fresh = $this->cb2fa_local_identity( $context );
            $challenge = is_wp_error( $fresh ) ? $fresh : $this->cb2fa_issue_login_challenge( $fresh, $policy['allow_cookie'], $context );
        } finally { Cloudbridge_2FA_State::unlock( $user->ID ); }
        if ( is_wp_error( $challenge ) ) { return( $challenge ); }
        if ( $challenge['active_factor'] === 'email' && ! $this->cb2fa_send_challenge_email( $fresh, $challenge ) ) {
            delete_transient( $this->cb2fa_get_challenge_key( $challenge['token'] ) );
            return( $this->cb2fa_external_error( 'mail' ) );
        }
        if ( is_wp_error( $this->cb2fa_external_policy( $context, 'begin' ) ) ) {
            delete_transient( $this->cb2fa_get_challenge_key( $challenge['token'] ) );
            return( $this->cb2fa_external_error( 'policy' ) );
        }
        if ( ! $this->cb2fa_native( $context ) ) { $this->cb2fa_external_event( 'pending', $context ); }
        nocache_headers();
        $this->cb2fa_auth_form( $fresh, $fresh->user_login, $challenge, $policy['allow_cookie'] ); exit;
    }

    /** Terminal response; no automatic redirect into stock authentication. */
    public function cb2fa_reject_completion( int $status = 409 ) : void {
        status_header( $status ); nocache_headers();
        if ( $status === 405 ) { header( 'Allow: POST' ); }
        echo '<!doctype html><html><body><p>' . esc_html__( 'Your login verification expired. Please sign in again.', 'cloudbridge-2fa' ) . '</p><a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Log In', 'default' ) . '</a></body></html>';
        exit;
    }

    /** Called only by the surviving provider dispatcher on its registered real core action. */
    public function cb2fa_complete_external_request( string $provider_id ) : void {
        $provider = $this->cb2fa_external_providers[$provider_id] ?? [];
        if ( ! $provider || ! $this->cb2fa_core_route( $provider['completion_action'] ) ) { $this->cb2fa_reject_completion(); }
        $this->cb2fa_verify_interactive_request( $provider_id );
    }

    /** Stable even when a primary plugin was removed between requests. */
    public function cb2fa_external_completion_controller() : void {
        $token = $_POST['cb2fa_challenge'] ?? '';
        $challenge = is_string( $token ) ? $this->cb2fa_get_challenge( $token ) : false;
        $id = is_array( $challenge ) ? ( $challenge['interactive_login']['context']['provider_id'] ?? '' ) : '';
        if ( ! is_string( $id ) || $id === 'cb2fa-password' || ! isset( $this->cb2fa_external_providers[$id] ) ) { $this->cb2fa_reject_completion(); }
        $this->cb2fa_complete_external_request( $id );
    }

    public function cb2fa_verify_interactive_request( string $provider_id = 'cb2fa-password' ) : void {
        try { $this->cb2fa_run_interactive_request( $provider_id ); }
        catch ( \Throwable $error ) { $this->cb2fa_reject_completion(); }
    }

    private function cb2fa_run_interactive_request( string $provider_id ) : void {
        if ( ! $this->cb2fa_available() ) { $this->cb2fa_reject_completion( 503 ); }
        if ( ( $_SERVER['REQUEST_METHOD'] ?? '' ) !== 'POST' ) { $this->cb2fa_reject_completion( 405 ); }
        if ( $provider_id !== 'cb2fa-password' ) {
            $provider = $this->cb2fa_external_providers[$provider_id] ?? [];
            if ( ! $provider || ! $this->cb2fa_core_route( $provider['completion_action'] ) ) { $this->cb2fa_reject_completion(); }
        } elseif ( realpath( (string)( $_SERVER['SCRIPT_FILENAME'] ?? '' ) ) !== realpath( dirname( __DIR__ ) . '/cb2fa-passthru.php' ) ) {
            $this->cb2fa_reject_completion();
        }
        $token = $_POST['cb2fa_challenge'] ?? '';
        $request = $_POST['cb2fa_request'] ?? '';
        $challenge = is_string( $token ) ? $this->cb2fa_get_challenge( $token ) : false;
        if ( ! is_array( $challenge ) || $challenge['status'] !== 'pending' || ( $challenge['interactive_login']['schema_version'] ?? null ) !== 2
            || ! is_string( $request ) || ! preg_match( '/\A[a-f0-9]{64}\z/', $request )
            || ! hash_equals( $challenge['request_hash'] ?? '', hash( 'sha256', $request ) )
            || ! $this->cb2fa_challenge_matches_browser( $token, $challenge )
            || ( $challenge['interactive_login']['context']['provider_id'] ?? '' ) !== $provider_id ) { $this->cb2fa_reject_completion(); }
        $context = $challenge['interactive_login']['context'];
        // Provider/additional policy callbacks execute before, never inside, the short lock.
        if ( is_wp_error( $this->cb2fa_external_policy( $context, 'complete' ) ) ) { $this->cb2fa_reject_completion(); }
        $this->cb2fa_external_refresh();
        $error = '';
        $mail = false;
        $consumed = false;
        $exhausted = false;
        if ( ! Cloudbridge_2FA_State::lock( $challenge['user_id'] ) ) { $this->cb2fa_reject_completion(); }
        try {
            $challenge = $this->cb2fa_get_challenge( $token );
            $user = $this->cb2fa_local_identity( $context );
            if ( ! is_array( $challenge ) || $challenge['status'] !== 'pending' || is_wp_error( $user )
                || $challenge['interactive_login']['context'] !== $context || ! $this->cb2fa_challenge_matches_browser( $token, $challenge )
                || ! hash_equals( $challenge['request_hash'] ?? '', hash( 'sha256', $request ) )
                || $challenge['attempts'] >= $challenge['max_attempts']
                || ! in_array( $challenge['active_factor'], $this->cb2fa_get_user_available_factors( $user ), true ) ) {
                $error = 'restart';
                $exhausted = is_array( $challenge ) && $challenge['attempts'] >= $challenge['max_attempts'];
            } elseif ( isset( $_POST['cb2fa_switch_factor'] ) ) {
                $factor = $_POST['cb2fa_switch_factor'];
                if ( ! is_string( $factor ) || ! in_array( $factor, $this->cb2fa_get_user_available_factors( $user ), true ) ) { $error = 'restart'; }
                elseif ( $factor !== $challenge['active_factor'] ) {
                    $previous = $challenge;
                    $challenge = $this->cb2fa_prepare_challenge_factor( $challenge, $factor );
                    if ( ! $this->cb2fa_store_challenge( $token, $challenge ) ) { $error = 'restart'; }
                    $mail = $factor === 'email';
                }
            } else {
                $code = is_string( $_POST['cb2fa_pincode'] ?? null ) ? trim( $_POST['cb2fa_pincode'] ) : '';
                $active = $challenge['active_factor'];
                $valid = $active === 'email' ? ( $code !== '' && hash_equals( $challenge['email_code_hash'], wp_hash( $code, 'auth' ) ) )
                    : ( $active === 'totp' ? $this->TOTP->cb2fa_verify_totp_for_user( $user->ID, $this->TOTP->cb2fa_get_active_secret( $user->ID ), $code )
                    : $this->TOTP->cb2fa_consume_recovery_code( $user->ID, $code ) );
                if ( ! $valid ) {
                    if ( $code !== '' ) { $challenge['attempts']++; }
                    $error = $this->cb2fa_store_challenge( $token, $challenge ) ? 'factor' : 'restart';
                } else {
                    $consumed = $this->cb2fa_mark_challenge_consumed( $token, $challenge );
                    if ( ! $consumed ) { $error = 'restart'; }
                }
            }
        } finally { Cloudbridge_2FA_State::unlock( $context['user_id'] ); }
        if ( $error === 'restart' ) {
            if ( $exhausted ) { $this->cb2fa_external_challenge_event( 'exhausted', $challenge ); }
            $this->cb2fa_reject_completion();
        }
        if ( $mail && ! $this->cb2fa_send_challenge_email( $user, $challenge ) ) {
            $error = 'restart';
            if ( Cloudbridge_2FA_State::lock( $user->ID, 1 ) ) {
                try {
                    $live = $this->cb2fa_get_challenge( $token );
                    if ( is_array( $live ) && $live['status'] === 'pending' && $live['active_factor'] === $challenge['active_factor']
                        && $live['interactive_login']['context'] === $context && $live['email_code_hash'] === $challenge['email_code_hash']
                        && $live['attempts'] < $live['max_attempts'] && $this->cb2fa_challenge_matches_browser( $token, $live )
                        && hash_equals( $live['request_hash'] ?? '', hash( 'sha256', $request ) ) ) {
                        // Mail runs outside the lock: retain concurrent attempts and
                        // the live deadline, and never resurrect consumed state.
                        $live['active_factor'] = $previous['active_factor'];
                        $live['email_code_hash'] = $previous['email_code_hash'];
                        if ( $this->cb2fa_store_challenge( $token, $live ) ) {
                            $challenge = $live;
                            $error = 'factor';
                        }
                    }
                } finally { Cloudbridge_2FA_State::unlock( $user->ID ); }
            }
            if ( $error === 'restart' ) { $this->cb2fa_reject_completion(); }
        }
        if ( $consumed ) {
            delete_transient( 'cb2fa_mail_' . $user->ID );
            $result = $this->cb2fa_complete_external_login( $challenge, isset( $_POST['cb2fa_cookie'] ) && $_POST['cb2fa_cookie'] === 'cb2fa_cookie' );
            $this->cb2fa_reject_completion();
        }
        if ( ! $this->cb2fa_native( $context ) ) {
            if ( $error === 'factor' ) { $this->cb2fa_external_challenge_event( 'factor_invalid', $challenge ); }
            elseif ( isset( $previous ) && $previous['active_factor'] !== $challenge['active_factor'] ) { $this->cb2fa_external_challenge_event( 'switch', $challenge ); }
        }
        $challenge['request_token'] = $request;
        $login = Cloudbridge_2FA_Login::getInstance( $this->cb2fa_nonce );
        if ( $error ) { $login->setErrorMessage( __( 'Incorrect code, or code has expired', 'cloudbridge-2fa' ) ); }
        $login->setAllowCookie( $challenge['allow_cookie'] === 'Y' );
        $login->setUser( $user, $user->user_login ); $login->setChallenge( $challenge );
        nocache_headers(); $login->drawForm(); exit;
    }

    private function cb2fa_native_success_response( \WP_User $user, array $context ) : void {
        $r = $context['response'];
        $redirect = apply_filters( 'login_redirect', $context['redirect_to'], $r['requested'], $user );
        if ( $r['interim'] ) {
            $GLOBALS['interim_login'] = 'success';
            $classes = apply_filters( 'login_body_class', ['login', 'login-action-login', 'wp-core-ui', 'interim-login', 'interim-login-success'], 'login' );
            echo '<!doctype html><html><head><meta charset="utf-8">';
            if ( $r['customize'] ) { wp_enqueue_script( 'customize-base' ); wp_print_scripts( 'customize-base' ); }
            echo '</head><body class="' . esc_attr( implode( ' ', $classes ) ) . '"><p>' . esc_html__( 'You have logged in successfully.', 'default' ) . '</p>';
            if ( $r['customize'] ) {
                echo '<script>setTimeout(function(){new wp.customize.Messenger({url:' . wp_json_encode( wp_customize_url() ) . ',channel:"login"}).send("login")},1000);</script>';
            }
            do_action( 'login_footer' ); echo '</body></html>'; exit;
        }
        $interval = (int)apply_filters( 'admin_email_check_interval', 6 * MONTH_IN_SECONDS );
        if ( $user->has_cap( 'manage_options' ) && $interval > 0 && time() > (int)get_option( 'admin_email_lifespan' ) ) {
            $redirect = add_query_arg( ['action' => 'confirm_admin_email', 'wp_lang' => get_user_locale( $user )], wp_login_url( wp_validate_redirect( $redirect, admin_url() ) ) );
        }
        if ( empty( $redirect ) || $redirect === 'wp-admin/' || $redirect === admin_url() ) {
            if ( is_multisite() && ! get_active_blog_for_user( $user->ID ) && ! is_super_admin( $user->ID ) ) { $redirect = user_admin_url(); }
            elseif ( is_multisite() && ! $user->has_cap( 'read' ) ) { $redirect = get_dashboard_url( $user->ID ); }
            elseif ( ! $user->has_cap( 'edit_posts' ) ) { $redirect = $user->has_cap( 'read' ) ? admin_url( 'profile.php' ) : home_url(); }
        }
        wp_safe_redirect( $redirect ); exit;
    }
}
