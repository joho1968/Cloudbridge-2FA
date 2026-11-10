<?php
/**
 * Cloudbridge 2FA passthru
 *
 * @since      1.0.0
 * @package    Cloudbridge 2FA
 * @author     Joaquim Homrighausen <joho@webbplatsen.se>
 *
 * cb2fa-passthru.php
 * Copyright (C) 2024-2026 Joaquim Homrighausen; all rights reserved.
 * Development sponsored by WebbPlatsen i Sverige AB, www.webbplatsen.se
 *
 * This file is part of Cloudbridge 2FA. Cloudbridge 2FA is free software.
 *
 * You may redistribute it and/or modify it under the terms of the
 * GNU General Public License version 2, as published by the Free Software
 * Foundation.
 *
 * Cloudbridge 2FA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the Cloudbridge 2FA package. If not, write to:
 *  The Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor
 *  Boston, MA  02110-1301, USA.
 */
namespace cloudbridge2fa;

// This public endpoint loads WordPress before checking its constants.
$cb2fa_wp_load = cb2fa_find_wp_load();
if ( $cb2fa_wp_load !== '' ) {
    require_once( $cb2fa_wp_load );
}

if ( ! defined( 'WPINC' ) ) {
    die;
}
if ( ! defined( 'ABSPATH' ) ) {
    die( '-1' );
}
include_once( ABSPATH . 'wp-admin/includes/plugin.php' );

// Prefer DOCUMENT_ROOT when it points at the site root, otherwise walk upwards
// from this plugin directory until wp-load.php is found.
function cb2fa_find_wp_load() : string {
    if ( isset( $_SERVER['DOCUMENT_ROOT'] ) && is_string( $_SERVER['DOCUMENT_ROOT'] ) ) {
        $cb2fa_document_root = rtrim( $_SERVER['DOCUMENT_ROOT'], "/\\" );
        if ( $cb2fa_document_root !== '' ) {
            $cb2fa_candidate = $cb2fa_document_root . '/wp-load.php';
            if ( is_readable( $cb2fa_candidate ) ) {
                return( $cb2fa_candidate );
            }
        }
    }

    $cb2fa_search_dir = __DIR__;
    for ( $cb2fa_level = 0; $cb2fa_level < 6; $cb2fa_level++ ) {
        $cb2fa_candidate = $cb2fa_search_dir . '/wp-load.php';
        if ( is_readable( $cb2fa_candidate ) ) {
            return( $cb2fa_candidate );
        }
        $cb2fa_parent_dir = dirname( $cb2fa_search_dir );
        if ( $cb2fa_parent_dir === $cb2fa_search_dir ) {
            break;
        }
        $cb2fa_search_dir = $cb2fa_parent_dir;
    }

    return( '' );
}

function cb2fa_run_passthru() : void {
    $plugin = Cloudbridge_2FA::getInstance();
    $login = Cloudbridge_2FA_Login::getInstance( $plugin->cb2fa_getnonce() );
    $token = isset( $_POST['cb2fa_challenge'] ) && is_string( $_POST['cb2fa_challenge'] ) ? wp_unslash( $_POST['cb2fa_challenge'] ) : '';
    $nonce = isset( $_POST['cb2fa_nonce'] ) && is_string( $_POST['cb2fa_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['cb2fa_nonce'] ) ) : '';
    $challenge = $plugin->cb2fa_get_challenge( $token );
    if ( ( $_SERVER['REQUEST_METHOD'] ?? '' ) !== 'POST'
        || ! is_array( $challenge ) || $challenge['status'] !== 'pending'
        || ! $plugin->cb2fa_challenge_matches_browser( $token, $challenge )
        || ! wp_verify_nonce( $nonce, 'cb2fa-challenge-' . $token ) ) {
        nocache_headers();
        wp_safe_redirect( $plugin->cb2fa_get_login_restart_url() );
        exit;
    }
    $user_id = (int)$challenge['user_id'];
    $authenticated = false;
    if ( ! Cloudbridge_2FA_State::lock( $user_id ) ) {
        $login->setErrorMessage( __( 'Login verification is busy. Please try again.', 'cloudbridge-2fa' ) );
    } else {
        try {
            // Re-read under the lock; another worker may have consumed it.
            $current = $plugin->cb2fa_get_challenge( $token );
            $user = get_user_by( 'id', $user_id );
            if ( ! is_array( $current ) || $current['status'] !== 'pending'
                || ! $user instanceof \WP_User
                || ! hash_equals( $current['password_hash'], $plugin->cb2fa_password_fingerprint( $user ) ) ) {
                $login->setErrorMessage( __( 'Incorrect code, or code has expired', 'cloudbridge-2fa' ) );
            } else {
                $challenge = $current;
                $login->setUser( $user, $user->user_login );
                if ( $challenge['attempts'] >= $challenge['max_attempts'] ) {
                    $login->setErrorMessage( __( 'Too many incorrect codes, please start over from the WordPress login page', 'cloudbridge-2fa' ) );
                } elseif ( isset( $_POST['cb2fa_switch_factor'] ) ) {
                    $factor = is_string( $_POST['cb2fa_switch_factor'] ) ? sanitize_key( wp_unslash( $_POST['cb2fa_switch_factor'] ) ) : '';
                    if ( ! in_array( $factor, $challenge['available_factors'], true ) ) {
                        $login->setErrorMessage( __( 'An error occurred, please try again', 'cloudbridge-2fa' ) );
                    } elseif ( $factor !== $challenge['active_factor'] ) {
                        $next = $plugin->cb2fa_prepare_challenge_factor( $challenge, $factor );
                        if ( ! $plugin->cb2fa_store_challenge( $token, $next ) ) {
                            $login->setErrorMessage( __( 'Unable to save login verification. Please try again.', 'cloudbridge-2fa' ) );
                        } elseif ( ! empty( $next['email_code'] ) && ! $plugin->cb2fa_send_challenge_email( $user, $next ) ) {
                            // Keep the previous factor/code usable after failed mail.
                            $plugin->cb2fa_store_challenge( $token, $challenge );
                            $login->setErrorMessage( __( 'Unable to send a new code. Please wait one minute before trying again.', 'cloudbridge-2fa' ) );
                        } else {
                            $challenge = $next;
                        }
                    }
                } else {
                    $code = isset( $_POST['cb2fa_pincode'] ) && is_string( $_POST['cb2fa_pincode'] ) ? trim( wp_unslash( $_POST['cb2fa_pincode'] ) ) : '';
                    $valid = false;
                    $totp = $plugin->cb2fa_get_totp_helper();
                    switch ( $challenge['active_factor'] ) {
                        case 'totp':
                            $secret = $totp->cb2fa_get_active_secret( $user_id );
                            $valid = $secret !== '' && $totp->cb2fa_verify_totp_for_user( $user_id, $secret, $code );
                            break;
                        case 'recovery':
                            $valid = $totp->cb2fa_consume_recovery_code( $user_id, $code );
                            break;
                        case 'email':
                            $valid = preg_match( '/^[0-9]{6}$/D', $code ) && ! empty( $challenge['email_code_hash'] )
                                && hash_equals( $challenge['email_code_hash'], wp_hash( $code, 'auth' ) );
                            break;
                    }
                    if ( ! $valid ) {
                        if ( $code !== '' ) {
                            $challenge['attempts']++;
                        }
                        $saved = $plugin->cb2fa_store_challenge( $token, $challenge );
                        $login->setErrorMessage( $saved
                            ? __( 'Incorrect code, or code has expired', 'cloudbridge-2fa' )
                            : __( 'Unable to save login verification. Please try again.', 'cloudbridge-2fa' ) );
                    } elseif ( ! $plugin->cb2fa_mark_challenge_consumed( $token, $challenge ) ) {
                        $login->setErrorMessage( __( 'Unable to save login verification. Please try again.', 'cloudbridge-2fa' ) );
                    } else {
                        delete_transient( 'cb2fa_mail_' . $user_id );
                        $authenticated = true;
                    }
                }
            }
        } finally {
            Cloudbridge_2FA_State::unlock( $user_id );
        }
    }
    $login->setChallenge( $challenge );
    $login->setAllowCookie( $challenge['allow_cookie'] === 'Y' );
    if ( $authenticated ) {
        $remember_browser = $challenge['allow_cookie'] === 'Y' && isset( $_POST['cb2fa_cookie'] ) && $_POST['cb2fa_cookie'] === 'cb2fa_cookie';
        $plugin->cb2fa_update_browser_trust( $user, $remember_browser );
        Cloudbridge_2FA_State::set_cookie( $plugin->cb2fa_challenge_cookie_name( $token ), '', time() - DAY_IN_SECONDS );
        wp_set_current_user( $user_id, $user->user_login );
        wp_set_auth_cookie( $user_id, ! empty( $challenge['rememberme'] ) );
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core WordPress login hook.
        do_action( 'wp_login', $user->user_login, $user );
        nocache_headers();
        wp_safe_redirect( wp_validate_redirect( $challenge['redirect_to'], admin_url() ) );
        exit;
    }
    $login->setUser( isset( $user ) && $user instanceof \WP_User ? $user : null, 'login' );
    nocache_headers();
    $login->drawForm();
}

cb2fa_run_passthru();
