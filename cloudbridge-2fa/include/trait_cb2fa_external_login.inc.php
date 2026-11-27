<?php
/**
 * Trusted PHP external-primary login coordination.
 *
 * @package Cloudbridge 2FA
 * @license GPL-2.0-or-later
 */
namespace cloudbridge2fa;

defined( 'ABSPATH' ) || die( '-1' );

trait Cloudbridge_2FA_External_Login {
    private array $cb2fa_external_providers = [];
    private bool $cb2fa_external_busy = false;
    private ?array $cb2fa_external_invocation = null;
    private array $cb2fa_external_verified = [];
    private array $cb2fa_external_used_proofs = [];

    public function cb2fa_external_login_api_version() : int {
        return( 2 );
    }

    private function cb2fa_external_error( string $reason ) : \WP_Error {
        $this->cb2fa_external_event( 'rejected' );
        return( new \WP_Error( 'cb2fa_external_' . $reason, __( 'Your login verification expired. Please sign in again.', 'cloudbridge-2fa' ) ) );
    }

    /** Register installed PHP callbacks, never an HTTP-supplied definition. */
    public function cb2fa_register_external_login_provider( string $provider_id, array $definition ) {
        if ( $this->cb2fa_external_busy || ! preg_match( '/\A[a-z][a-z0-9-]{0,63}\z/', $provider_id )
            || $provider_id === 'cb2fa-password' || isset( $this->cb2fa_external_providers[$provider_id] )
            || array_diff( array_keys( $definition ), ['api_version', 'consume_primary_proof', 'revalidate', 'primary_action', 'completion_action'] )
            || ( $definition['api_version'] ?? null ) !== 2
            || ! is_string( $definition['primary_action'] ?? null ) || ! preg_match( '/\Acb[a-z0-9_-]{1,60}\z/', $definition['primary_action'] )
            || ( $definition['completion_action'] ?? null ) !== 'cb2fa_complete'
            || $definition['primary_action'] === $definition['completion_action']
            || ! is_callable( $definition['consume_primary_proof'] ?? null )
            || ! is_callable( $definition['revalidate'] ?? null ) ) {
            return( $this->cb2fa_external_error( 'registration' ) );
        }
        $this->cb2fa_external_providers[$provider_id] = $definition;
        return( true );
    }

    private function cb2fa_external_event( string $event, array $context = [] ) : void {
        // No proof, redirect, identity profile, factor or cookie data in events.
        try {
            do_action( 'cb2fa_external_login_event', $event, [
                'provider_id' => $context['provider_id'] ?? '',
                'user_id' => $context['user_id'] ?? 0,
                'blog_id' => $context['blog_id'] ?? get_current_blog_id(),
            ] );
        } catch ( \Throwable $error ) {
            error_log( '[CB2FA] External login event observer failed.' );
        }
    }

    /** @internal Observational endpoint events never include challenge material. */
    public function cb2fa_external_challenge_event( string $event, array $challenge ) : void {
        if ( isset( $challenge['interactive_login']['context'] )
            && in_array( $event, ['factor_invalid', 'exhausted', 'switch', 'rejected'], true ) ) {
            $this->cb2fa_external_event( $event, $challenge['interactive_login']['context'] );
        }
    }

    private function cb2fa_external_fresh_user( int $id ) {
        clean_user_cache( $id );
        wp_cache_delete( $id, 'user_meta' );
        return( get_user_by( 'id', $id ) );
    }

    /** Refresh security settings independently of constructor snapshots. */
    private function cb2fa_external_refresh() : void {
        wp_cache_delete( 'alloptions', 'options' );
        foreach ( ['roles-config', 'cookies-config', 'cookie-lifetime', 'code-lifetime', 'email-otp-enabled', 'totp-enabled'] as $key ) {
            wp_cache_delete( 'cloudbridge2fa-' . $key, 'options' );
        }
        $roles = json_decode( (string)get_option( 'cloudbridge2fa-roles-config', '[]' ), true );
        $cookies = json_decode( (string)get_option( 'cloudbridge2fa-cookies-config', '[]' ), true );
        $this->cb2fa_roles_configuration = is_array( $roles ) ? $roles : [];
        $this->cb2fa_cookies_configuration = is_array( $cookies ) ? $cookies : [];
        $this->cb2fa_cookie_lifetime = max( 0, min( 365, (int)get_option( 'cloudbridge2fa-cookie-lifetime', 0 ) ) );
        $minutes = (int)get_option( 'cloudbridge2fa-code-lifetime', CB2FA_TRANSIENT_EXPIRE_DEFAULT );
        $this->cb2fa_code_lifetime = $minutes >= 1 && $minutes <= 60 ? $minutes : CB2FA_TRANSIENT_EXPIRE_DEFAULT;
        $this->cb2fa_email_otp_enabled = (bool)get_option( 'cloudbridge2fa-email-otp-enabled', true );
        $this->cb2fa_totp_enabled = (bool)get_option( 'cloudbridge2fa-totp-enabled', false );
    }

    private function cb2fa_external_binding_valid( $value, int $depth, int &$leaves ) : bool {
        if ( is_array( $value ) ) {
            if ( $depth > 3 || count( $value ) > 32 ) {
                return( false );
            }
            foreach ( $value as $key => $item ) {
                if ( ( is_string( $key ) && ( strlen( $key ) > 64 || ! preg_match( '//u', $key ) ) )
                    || ! $this->cb2fa_external_binding_valid( $item, $depth + 1, $leaves ) ) {
                    return( false );
                }
            }
            return( true );
        }
        $leaves++;
        return( $leaves <= 32 && ( is_null( $value ) || is_bool( $value ) || is_int( $value )
            || ( is_string( $value ) && strlen( $value ) <= 512 && preg_match( '//u', $value ) ) ) );
    }

    private function cb2fa_external_destination_valid( $url ) : bool {
        if ( ! is_string( $url ) || strlen( $url ) > 2048 || preg_match( '/[\x00-\x20\x7f\\\\]/', $url ) ) {
            return( false );
        }
        $parts = wp_parse_url( $url );
        $home = wp_parse_url( home_url( '/' ) );
        if ( ! is_array( $parts ) || ! is_array( $home ) || isset( $parts['user'] ) || isset( $parts['pass'] )
            || empty( $parts['host'] ) || ! in_array( $parts['scheme'] ?? '', ['http', 'https'], true )
            || strtolower( $parts['host'] ) !== strtolower( $home['host'] ?? '' )
            || $parts['scheme'] !== ( $home['scheme'] ?? '' )
            || ( $parts['port'] ?? ( $parts['scheme'] === 'https' ? 443 : 80 ) ) !== ( $home['port'] ?? ( ( $home['scheme'] ?? '' ) === 'https' ? 443 : 80 ) ) ) {
            return( false );
        }
        return( wp_validate_redirect( $url, '' ) === $url );
    }

    private function cb2fa_external_context_valid( array $context, bool $entry = false ) : bool {
        $now = time();
        if ( ! $entry ) {
            foreach ( ['wp_login', 'wp_email', 'password_hash'] as $key ) {
                if ( ! is_string( $context[$key] ?? null ) || ( $key !== 'wp_email' && $context[$key] === '' ) ) {
                    return( false );
                }
            }
        }
        foreach ( ['user_id', 'blog_id', 'verified_at', 'valid_until', 'deadline'] as $key ) {
            if ( ! isset( $context[$key] ) || ! is_int( $context[$key] ) || $context[$key] < 1 ) {
                return( false );
            }
        }
        $requirement = $context['requirement'] ?? null;
        $leaves = 0;
        $binding = $context['account_binding'] ?? null;
        $encoded = is_array( $binding ) ? json_encode( $binding ) : false;
        return( $context['blog_id'] === get_current_blog_id()
            && isset( $this->cb2fa_external_providers[$context['provider_id'] ?? ''] )
            && $context['verified_at'] <= $now && $context['verified_at'] <= PHP_INT_MAX - 900
            && $now < $context['valid_until'] && $now < $context['deadline']
            && $context['valid_until'] <= $context['verified_at'] + 900
            && $context['deadline'] <= $context['valid_until']
            && ( ! $entry || $now - $context['verified_at'] <= 60 )
            && is_bool( $context['rememberme'] ?? null )
            && $this->cb2fa_external_destination_valid( $context['redirect_to'] ?? null )
            && is_array( $requirement ) && count( $requirement ) === 5
            && ( $requirement['schema_version'] ?? null ) === 1
            && ( $requirement['mode'] ?? null ) === 'required'
            && ( $requirement['mfa_plugin'] ?? null ) === 'cloudbridge-2fa'
            && ( $requirement['api_version'] ?? null ) === 2
            && is_string( $requirement['revision'] ?? null )
            && preg_match( '/\A[A-Za-z0-9_.:-]{1,128}\z/', $requirement['revision'] )
            && is_string( $encoded ) && strlen( $encoded ) <= 4096
            && $this->cb2fa_external_binding_valid( $binding, 1, $leaves ) );
    }

    /** Core implementations only; this gate runs before a token can be created. */
    private function cb2fa_external_preflight() : bool {
        // Core login routes and the physical verifier require a complete bootstrap.
        if ( ! did_action( 'wp_loaded' ) || doing_action( 'wp_loaded' ) || doing_action( 'init' ) ) {
            return( false );
        }
        $core = realpath( ABSPATH . WPINC . '/pluggable.php' );
        foreach ( ['wp_authenticate', 'wp_set_auth_cookie', 'wp_generate_auth_cookie', 'wp_validate_auth_cookie'] as $function ) {
            $reflection = new \ReflectionFunction( $function );
            if ( ! $core || realpath( (string)$reflection->getFileName() ) !== $core ) {
                return( false );
            }
        }
        return( ! headers_sent() );
    }

    private function cb2fa_external_policy( array $context, string $phase ) {
        if ( ! in_array( $phase, ['begin', 'complete'], true ) ) { return( $this->cb2fa_external_error( 'context' ) ); }
        $this->cb2fa_external_refresh();
        $user = $this->cb2fa_local_identity( $context );
        if ( is_wp_error( $user ) ) { return( $user ); }
        $native = $this->cb2fa_native( $context );
        if ( ! $native ) {
            $result = call_user_func( $this->cb2fa_external_providers[$context['provider_id']]['revalidate'], $user, $context, $phase );
            if ( $result !== true ) { return( is_wp_error( $result ) ? $result : $this->cb2fa_external_error( 'policy_result' ) ); }
        }
        $policy_context = $context; $policy_context['phase'] = $phase;
        $result = apply_filters( 'cb2fa_login_account_policy', true, $user, $policy_context );
        if ( $result !== true ) { return( is_wp_error( $result ) ? $result : $this->cb2fa_external_error( 'policy_result' ) ); }
        if ( ! $native ) {
            $result = apply_filters( 'cb2fa_external_login_account_policy', true, $user, $policy_context );
            if ( $result !== true ) { return( is_wp_error( $result ) ? $result : $this->cb2fa_external_error( 'policy_result' ) ); }
        }
        $fresh = $this->cb2fa_local_identity( $context );
        if ( is_wp_error( $fresh ) || $fresh->roles !== $user->roles || $fresh->user_pass !== $user->user_pass ) { return( $this->cb2fa_external_error( 'account_changed' ) ); }
        if ( ! $native && call_user_func( $this->cb2fa_external_providers[$context['provider_id']]['revalidate'], $fresh, $context, $phase ) !== true ) { return( $this->cb2fa_external_error( 'account_changed' ) ); }
        return( $this->cb2fa_local_identity( $context ) );
    }

    private function cb2fa_external_in_scope() : bool {
        return( $this->cb2fa_external_invocation !== null
            && $this->cb2fa_external_invocation['stage'] === 'core'
            && current_filter() === 'authenticate'
            && count( $GLOBALS['wp_current_filter'] ?? [] ) === $this->cb2fa_external_invocation['depth'] );
    }

    private function cb2fa_external_filter_result( $user ) {
        if ( is_wp_error( $user ) ) {
            return( $user );
        }
        return( $user instanceof \WP_User && (int)$user->ID === $this->cb2fa_external_invocation['context']['user_id']
            ? $user : $this->cb2fa_external_error( 'identity' ) );
    }

    /** Invoked by the existing terminal filter only in the exact owned call. */
    private function cb2fa_external_defer( $user ) {
        $this->cb2fa_external_invocation['terminal_seen'] = true;
        return( empty( $this->cb2fa_external_invocation['context']['user_id'] ) ? $user : $this->cb2fa_external_filter_result( $user ) );
    }

    private function cb2fa_external_authenticate( array $context, string $phase ) {
        $this->cb2fa_external_invocation = [
            'context' => $context, 'stage' => 'prefix', 'depth' => count( $GLOBALS['wp_current_filter'] ?? [] ) + 1,
            'provider_seen' => false, 'terminal_seen' => false,
        ];
        $provider = function( $user, $login, $password ) use ( $context ) {
            if ( ! $this->cb2fa_external_in_scope() ) {
                return( $user );
            }
            $this->cb2fa_external_invocation['provider_seen'] = true;
            if ( $login !== $context['wp_login'] || $password !== '' ) {
                return( $this->cb2fa_external_error( 'credentials' ) );
            }
            if ( $user !== null ) {
                return( $this->cb2fa_external_filter_result( $user ) );
            }
            return( $this->cb2fa_external_fresh_user( $context['user_id'] ) );
        };
        $terminal = [$this, 'cb2fa_post_wp_authenticate'];
        $added_terminal = has_filter( 'authenticate', $terminal ) === false;
        $had_secure = array_key_exists( 'auth_secure_cookie', $GLOBALS );
        $old_secure = $GLOBALS['auth_secure_cookie'] ?? null;
        add_filter( 'authenticate', $provider, 19, 3 );
        if ( $added_terminal ) {
            add_filter( 'authenticate', $terminal, PHP_INT_MAX, 3 );
        }
        try {
            $login = $context['wp_login'];
            $password = '';
            do_action_ref_array( 'wp_authenticate', [&$login, &$password] );
            if ( $login !== $context['wp_login'] || $password !== '' ) {
                return( $this->cb2fa_external_error( 'credentials' ) );
            }
            $secure = apply_filters( 'secure_signon_cookie', $context['response']['secure'] ?? is_ssl(), ['user_login' => $login, 'user_password' => '', 'remember' => $context['rememberme']] );
            if ( ! is_bool( $secure ) ) {
                return( $this->cb2fa_external_error( 'cookie_policy' ) );
            }
            $GLOBALS['auth_secure_cookie'] = $secure;
            $this->cb2fa_external_invocation['stage'] = 'core';
            $checked = wp_authenticate( $login, '' );
            // Policy callbacks run outside the owned hook invocation; nested
            // authentication there must not inherit the already verified proof.
            $this->cb2fa_external_invocation['stage'] = 'post_core';
            if ( is_wp_error( $checked ) ) {
                return( $checked );
            }
            if ( ! $this->cb2fa_external_invocation['provider_seen'] || ! $this->cb2fa_external_invocation['terminal_seen']
                || ! $checked instanceof \WP_User || (int)$checked->ID !== $context['user_id'] ) {
                return( $this->cb2fa_external_error( 'identity' ) );
            }
            $user = $this->cb2fa_external_policy( $context, $phase );
            return( is_wp_error( $user ) ? $user : ['user' => $user, 'secure' => $secure] );
        } finally {
            remove_filter( 'authenticate', $provider, 19 );
            if ( $added_terminal ) {
                remove_filter( 'authenticate', $terminal, PHP_INT_MAX );
            }
            if ( $had_secure ) {
                $GLOBALS['auth_secure_cookie'] = $old_secure;
            } else {
                unset( $GLOBALS['auth_secure_cookie'] );
            }
            $this->cb2fa_external_invocation = null;
        }
    }

    private function cb2fa_external_factor_policy( \WP_User $user ) : array {
        $required = false;
        $allow = false;
        foreach ( $user->roles as $role ) {
            if ( in_array( $role, $this->cb2fa_roles_configuration, true ) ) {
                $required = true;
                $allow = $allow || in_array( $role, $this->cb2fa_cookies_configuration, true );
            }
        }
        $allow = $allow && $this->cb2fa_cookie_lifetime > 0;
        return( [
            'required' => $required && ! $this->cb2fa_user_has_bypass( $user->ID ) && ! ( $allow && $this->cb2fa_has_browser_trust( $user ) ),
            'allow_cookie' => $allow,
        ] );
    }

    /** Returns WP_Error on rejection; accepted pending/completed flows terminate. */
    public function cb2fa_external_login( string $provider_id, string $proof_handle ) {
        if ( $this->cb2fa_external_busy || ! isset( $this->cb2fa_external_providers[$provider_id] )
            || ( $_SERVER['REQUEST_METHOD'] ?? '' ) !== 'GET'
            || ! $this->cb2fa_core_route( $this->cb2fa_external_providers[$provider_id]['primary_action'] )
            || ! preg_match( '/\A[a-f0-9]{64}\z/', $proof_handle )
            || isset( $this->cb2fa_external_used_proofs[$provider_id . ':' . $proof_handle] ) ) {
            return( $this->cb2fa_external_error( 'entry' ) );
        }
        $this->cb2fa_external_busy = true;
        $this->cb2fa_external_used_proofs[$provider_id . ':' . $proof_handle] = true;
        $context = [];
        try {
            $proof = call_user_func( $this->cb2fa_external_providers[$provider_id]['consume_primary_proof'], $proof_handle );
            $keys = ['user_id', 'blog_id', 'verified_at', 'valid_until', 'redirect_to', 'rememberme', 'account_binding', 'requirement'];
            if ( is_wp_error( $proof ) ) {
                return( $proof );
            }
            if ( ! is_array( $proof ) || array_diff( array_keys( $proof ), $keys ) || array_diff( $keys, array_keys( $proof ) ) ) {
                return( $this->cb2fa_external_error( 'proof' ) );
            }
            $context = $proof;
            $context['provider_id'] = $provider_id;
            $this->cb2fa_external_refresh();
            // Until a challenge exists the primary deadline applies. The builder
            // freezes the shorter configured MFA window at its creation time.
            $context['deadline'] = is_int( $proof['valid_until'] ) ? $proof['valid_until'] : 0;
            if ( ! $this->cb2fa_external_context_valid( $context, true ) || ! $this->cb2fa_external_preflight() ) {
                return( $this->cb2fa_external_error( 'proof' ) );
            }
            $user = $this->cb2fa_external_fresh_user( $context['user_id'] );
            if ( ! $user instanceof \WP_User ) {
                return( $this->cb2fa_external_error( 'account' ) );
            }
            $context['wp_login'] = $user->user_login;
            $context['wp_email'] = $user->user_email;
            $context['password_hash'] = $this->cb2fa_password_fingerprint( $user );
            if ( ! $this->cb2fa_core_route( $this->cb2fa_external_providers[$provider_id]['primary_action'] ) ) {
                return( $this->cb2fa_external_error( 'route' ) );
            }
            $checked = $this->cb2fa_external_policy( $context, 'begin' );
            if ( is_wp_error( $checked ) ) { return( $checked ); }
            $authenticated = $this->cb2fa_external_authenticate( $context, 'begin' );
            if ( is_wp_error( $authenticated ) ) {
                return( $authenticated );
            }
            return( $this->cb2fa_begin_interactive( $context, $authenticated['secure'] ) );
        } catch ( \Throwable $error ) {
            return( $this->cb2fa_external_error( 'exception' ) );
        } finally {
            $this->cb2fa_external_busy = false;
        }
    }

    /** Endpoint policy gate; provider callbacks must run outside account locks. */
    public function cb2fa_check_external_challenge( array $challenge ) {
        try {
            $external = $challenge['interactive_login'] ?? null;
            if ( ! is_array( $external ) || ( $external['schema_version'] ?? null ) !== 2 || ! is_array( $external['context'] ?? null ) ) {
                return( $this->cb2fa_external_error( 'schema' ) );
            }
            $context = $external['context'];
            if ( ( $challenge['user_id'] ?? null ) !== ( $context['user_id'] ?? null )
                || ( $challenge['expires_at'] ?? null ) !== ( $context['deadline'] ?? null )
                || ( $challenge['redirect_to'] ?? null ) !== ( $context['redirect_to'] ?? null )
                || ( $challenge['rememberme'] ?? null ) !== ( $context['rememberme'] ?? null ) ) {
                return( $this->cb2fa_external_error( 'context' ) );
            }
            $user = $this->cb2fa_external_policy( $context, 'complete' );
            if ( is_wp_error( $user ) ) {
                return( $user );
            }
            if ( $challenge['status'] === 'consumed' ) {
                return( true );
            }
            $available = $this->cb2fa_get_user_available_factors( $user );
            return( ! array_diff( $challenge['available_factors'], $available ) && in_array( $challenge['active_factor'], $available, true )
                ? true : $this->cb2fa_external_error( 'factor' ) );
        } catch ( \Throwable $error ) {
            return( $this->cb2fa_external_error( 'exception' ) );
        }
    }

    /** Only a successful checked consumption in this request grants completion. */
    public function cb2fa_complete_external_login( array $challenge, bool $remember_browser ) {
        $token = $challenge['token'] ?? '';
        if ( $this->cb2fa_external_busy || ! isset( $this->cb2fa_external_verified[$token] ) ) {
            return( $this->cb2fa_external_error( 'completion' ) );
        }
        unset( $this->cb2fa_external_verified[$token] );
        $this->cb2fa_external_busy = true;
        try {
            $stored = $this->cb2fa_get_challenge( $token );
            if ( ! is_array( $stored ) || $stored['status'] !== 'consumed' || $this->cb2fa_check_external_challenge( $stored ) !== true ) {
                return( $this->cb2fa_external_error( 'completion' ) );
            }
            $context = $stored['interactive_login']['context'];
            if ( ! Cloudbridge_2FA_State::lock( $context['user_id'], 1 ) ) { return( $this->cb2fa_external_error( 'busy' ) ); }
            try {
                $live = $this->cb2fa_get_challenge( $token );
                if ( ! is_array( $live ) || $live['status'] !== 'consumed' || $live['interactive_login']['context'] !== $context
                    || is_wp_error( $this->cb2fa_local_identity( $context ) ) ) { return( $this->cb2fa_external_error( 'completion' ) ); }
            } finally { Cloudbridge_2FA_State::unlock( $context['user_id'] ); }
            $authenticated = $this->cb2fa_external_authenticate( $context, 'complete' );
            if ( is_wp_error( $authenticated ) ) {
                return( $authenticated );
            }
            return( $this->cb2fa_external_finalize( $context, $authenticated['secure'], $stored, $remember_browser ) );
        } catch ( \Throwable $error ) {
            return( $this->cb2fa_external_error( 'exception' ) );
        } finally {
            $this->cb2fa_external_busy = false;
        }
    }

    private function cb2fa_external_remove_owned_headers( array $before, array $cookies ) : void {
        if ( headers_sent() ) {
            return;
        }
        $preserve = [];
        foreach ( headers_list() as $header ) {
            if ( stripos( $header, 'Set-Cookie:' ) !== 0 ) {
                continue;
            }
            $owned = false;
            foreach ( $cookies as $cookie ) {
                if ( strpos( $header, 'Set-Cookie: ' . $cookie . ';' ) === 0 && ! in_array( $header, $before, true ) ) {
                    $owned = true;
                }
            }
            if ( ! $owned ) {
                $preserve[] = $header;
            }
        }
        header_remove( 'Set-Cookie' );
        foreach ( $preserve as $header ) {
            header( $header, false );
        }
    }

    /** Known-token ownership permits narrow cleanup even when a core hook throws. */
    private function cb2fa_external_finalize( array $context, bool $secure, array $challenge = [], bool $remember_browser = false ) {
        $user = $this->cb2fa_final_identity( $context, $challenge );
        if ( is_wp_error( $user ) ) {
            return( $user );
        }
        // Re-evaluate exemptions; a role/trust change cannot bypass a new factor requirement.
        $this->cb2fa_external_refresh();
        if ( ! $challenge && $this->cb2fa_external_factor_policy( $user )['required'] ) {
            return( $this->cb2fa_external_error( 'factor_required' ) );
        }
        if ( $challenge ) {
            $active = $challenge['active_factor'];
            $available = $this->cb2fa_get_user_available_factors( $user );
            // The last recovery code has already been consumed in this request.
            $recovery_allowed = $active === 'recovery' && $this->cb2fa_totp_factor_enabled()
                && $this->TOTP->cb2fa_get_active_secret( $user->ID ) !== '';
            if ( ! $recovery_allowed && ! in_array( $active, $available, true ) ) {
                return( $this->cb2fa_external_error( 'factor' ) );
            }
        }
        $manager = \WP_Session_Tokens::get_instance( $user->ID );
        if ( ! $manager instanceof \WP_Session_Tokens ) {
            return( $this->cb2fa_external_error( 'session_manager' ) );
        }
        $token = bin2hex( random_bytes( 32 ) );
        $before = headers_list();
        $cookies = [];
        $session = [];
        $observed = [];
        $observer = function( $cookie, $expire, $expiration, $id, $scheme, $emitted_token ) use ( $context, $token, $manager, &$cookies, &$session, &$observed ) {
            if ( (int)$id !== $context['user_id'] || $emitted_token !== $token || ! in_array( $scheme, ['auth', 'secure_auth', 'logged_in'], true ) ) {
                throw new \RuntimeException( 'Unexpected cookie identity' );
            }
            $name = $scheme === 'logged_in' ? LOGGED_IN_COOKIE : ( $scheme === 'secure_auth' ? SECURE_AUTH_COOKIE : AUTH_COOKIE );
            $cookies[] = $name . '=' . rawurlencode( $cookie );
            $observed[$scheme] = $cookie;
            $session['expiration'] = $expiration;
            $manager->update( $token, $session );
            if ( ! $manager->verify( $token ) || ( $manager->get( $token )['expiration'] ?? null ) !== $expiration ) {
                throw new \RuntimeException( 'Session storage failed' );
            }
        };
        $success = false;
        add_action( 'set_auth_cookie', $observer, PHP_INT_MAX, 6 );
        add_action( 'set_logged_in_cookie', $observer, PHP_INT_MAX, 6 );
        try {
            $session = apply_filters( 'attach_session_information', [], $user->ID );
            if ( ! is_array( $session ) ) {
                throw new \RuntimeException( 'Invalid session information' );
            }
            $session['expiration'] = time() + MINUTE_IN_SECONDS;
            $session['login'] = time();
            if ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
                $session['ip'] = $_SERVER['REMOTE_ADDR'];
            }
            if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
                $session['ua'] = wp_unslash( $_SERVER['HTTP_USER_AGENT'] );
            }
            // Preflight/policy callbacks may themselves have changed request state.
            $checked = $this->cb2fa_final_identity( $context, $challenge );
            if ( is_wp_error( $checked ) ) {
                return( $checked );
            }
            $manager->update( $token, $session );
            if ( ! $manager->verify( $token ) ) {
                throw new \RuntimeException( 'Session storage failed' );
            }
            wp_set_auth_cookie( $user->ID, $context['rememberme'], $secure, $token );
            $headers = headers_list();
            if ( ! isset( $observed['logged_in'] ) || count( $observed ) !== 2 || ! $manager->verify( $token ) || headers_sent() ) {
                throw new \RuntimeException( 'Cookie emission failed' );
            }
            foreach ( $cookies as $cookie ) {
                $found = false;
                foreach ( $headers as $header ) {
                    $found = $found || strpos( $header, 'Set-Cookie: ' . $cookie . ';' ) === 0;
                }
                if ( ! $found ) {
                    throw new \RuntimeException( 'Cookie emission vetoed' );
                }
            }
            foreach ( $observed as $scheme => $cookie ) {
                if ( wp_validate_auth_cookie( $cookie, $scheme ) !== $user->ID ) {
                    throw new \RuntimeException( 'Unusable cookie' );
                }
            }
            $checked = $this->cb2fa_final_identity( $context, $challenge );
            if ( is_wp_error( $checked ) ) {
                return( $checked );
            }
            global $wpdb;
            // Narrow core-style activation-key reset, without profile-update side effects.
            $updated = $wpdb->update( $wpdb->users, ['user_activation_key' => ''], ['ID' => $user->ID], ['%s'], ['%d'] );
            $fresh = $this->cb2fa_external_fresh_user( $user->ID );
            if ( $updated === false || ! $fresh instanceof \WP_User || $fresh->user_activation_key !== '' ) {
                throw new \RuntimeException( 'Activation reset failed' );
            }
            $success = true;
        } catch ( \Throwable $error ) {
            return( $this->cb2fa_external_error( 'session' ) );
        } finally {
            remove_action( 'set_auth_cookie', $observer, PHP_INT_MAX );
            remove_action( 'set_logged_in_cookie', $observer, PHP_INT_MAX );
            if ( ! $success ) {
                try {
                    $manager->destroy( $token );
                } finally {
                    $this->cb2fa_external_remove_owned_headers( $before, $cookies );
                }
            }
        }
        if ( $challenge ) {
            $allow = $this->cb2fa_external_factor_policy( $fresh )['allow_cookie'];
            $this->cb2fa_update_browser_trust( $fresh, $allow && $remember_browser );
            Cloudbridge_2FA_State::set_cookie( $this->cb2fa_challenge_cookie_name( $challenge['token'] ), '', time() - DAY_IN_SECONDS );
        }
        wp_set_current_user( $fresh->ID, $fresh->user_login );
        do_action( 'wp_login', $fresh->user_login, $fresh );
        if ( ! $this->cb2fa_native( $context ) ) { $this->cb2fa_external_event( 'completed', $context ); }
        nocache_headers();
        if ( $this->cb2fa_native( $context ) ) { $this->cb2fa_native_success_response( $fresh, $context ); }
        wp_safe_redirect( $context['redirect_to'] );
        exit;
    }
}
