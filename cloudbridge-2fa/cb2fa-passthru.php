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

// WPINC and ABSPATH are not defined at this point. Prefer DOCUMENT_ROOT when it
// points at the site root, but fall back to walking upwards from this plugin
// directory until wp-load.php is found.
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

function cb2fa_run_passthru() : void {
    $cb2fa_plugin = Cloudbridge_2FA::getInstance();
    $cb2fa_login = Cloudbridge_2FA_Login::getInstance( $cb2fa_plugin->cb2fa_getnonce() );
    $cb2fa_totp = $cb2fa_plugin->cb2fa_get_totp_helper();

    if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
        error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': Start' );
    }

    $cb2fa_request_nonce = '';
    $cb2fa_request_user = '';
    $cb2fa_challenge = false;
    $cb2fa_wp_user = false;

    if ( ! empty( $_REQUEST['cb2fa_nonce'] ) ) {
        $cb2fa_request_nonce = sanitize_text_field( wp_unslash( $_REQUEST['cb2fa_nonce'] ) );
    }
    if ( ! empty( $_REQUEST['cb2fa_user'] ) ) {
        $cb2fa_request_user = sanitize_text_field( wp_unslash( $_REQUEST['cb2fa_user'] ) );
        $cb2fa_login->setUser( null, $cb2fa_request_user );
    }

    if ( empty( $cb2fa_request_nonce ) || wp_verify_nonce( $cb2fa_request_nonce, 'cloudbridge-2fa' . CB2FA_VERSION ) === false ) {
        $cb2fa_redirect_to = '';
        if ( ! empty( $_REQUEST['redirect_to'] ) ) {
            $cb2fa_redirect_to = sanitize_url( wp_unslash( $_REQUEST['redirect_to'] ), ['http', 'https'] );
        }
        nocache_headers();
        wp_safe_redirect( $cb2fa_plugin->cb2fa_get_login_restart_url( $cb2fa_redirect_to ) );
        die();
    } elseif ( empty( $cb2fa_request_user ) ) {
        $cb2fa_login->setErrorMessage( __( 'Unable to determine login user, please try again', 'cloudbridge-2fa' ) );
    } else {
        $cb2fa_challenge = $cb2fa_plugin->cb2fa_get_challenge( $cb2fa_request_user, $cb2fa_request_nonce );
        if ( ! is_array( $cb2fa_challenge ) || empty( $cb2fa_challenge['user_id'] ) || ( ! empty( $cb2fa_challenge['status'] ) && $cb2fa_challenge['status'] !== 'pending' ) ) {
            $cb2fa_login->setErrorMessage( __( 'Incorrect code, or code has expired', 'cloudbridge-2fa' ) );
            $cb2fa_challenge = false;
        } else {
            $cb2fa_login->setChallenge( $cb2fa_challenge );
            $cb2fa_login->setAllowCookie( ( ! empty( $cb2fa_challenge['allow_cookie'] ) && $cb2fa_challenge['allow_cookie'] === 'Y' ) );
            $cb2fa_wp_user = get_user_by( 'id', (int)$cb2fa_challenge['user_id'] );
            if ( ! $cb2fa_wp_user instanceof \WP_User ) {
                $cb2fa_login->setErrorMessage( __( 'Unable to fetch WordPress user', 'cloudbridge-2fa' ) );
            } else {
                $cb2fa_login->setUser( $cb2fa_wp_user, $cb2fa_request_user );
                if ( ! empty( $_REQUEST['cb2fa_switch_factor'] ) ) {
                    $cb2fa_switch_factor = sanitize_key( wp_unslash( $_REQUEST['cb2fa_switch_factor'] ) );
                    $cb2fa_challenge = $cb2fa_plugin->cb2fa_prepare_challenge_factor( $cb2fa_challenge, $cb2fa_switch_factor );
                    $cb2fa_plugin->cb2fa_store_challenge( $cb2fa_request_user, $cb2fa_request_nonce, $cb2fa_challenge );
                    $cb2fa_login->setChallenge( $cb2fa_challenge );
                    if ( ! empty( $cb2fa_challenge['active_factor'] ) && $cb2fa_challenge['active_factor'] === 'email' && ! empty( $cb2fa_challenge['email_code'] ) ) {
                        $cb2fa_login->send_2fa_code( $cb2fa_challenge['email_code'] );
                    }
                } elseif ( empty( $_REQUEST['cb2fa_timer'] ) || $_REQUEST['cb2fa_timer'] > time() ) {
                    $cb2fa_login->setErrorMessage( __( 'An error occurred, please try again', 'cloudbridge-2fa' ) );
                } elseif ( ! empty( $cb2fa_challenge['attempts'] ) && ! empty( $cb2fa_challenge['max_attempts'] ) && $cb2fa_challenge['attempts'] >= $cb2fa_challenge['max_attempts'] ) {
                    $cb2fa_login->setErrorMessage( __( 'Too many incorrect codes, please start over from the WordPress login page', 'cloudbridge-2fa' ) );
                } elseif ( empty( $_REQUEST['cb2fa_pincode'] ) ) {
                    switch ( $cb2fa_challenge['active_factor'] ) {
                        case 'totp':
                            $cb2fa_login->setErrorMessage( __( 'Please enter the code from your authenticator app', 'cloudbridge-2fa' ) );
                            break;
                        case 'recovery':
                            $cb2fa_login->setErrorMessage( __( 'Please enter one of your recovery codes', 'cloudbridge-2fa' ) );
                            break;
                        case 'email':
                        default:
                            $cb2fa_login->setErrorMessage( __( 'Please enter the code received by e-mail', 'cloudbridge-2fa' ) );
                            break;
                    }
                } else {
                    $submitted_code = sanitize_text_field( wp_unslash( $_REQUEST['cb2fa_pincode'] ) );
                    $submitted_numeric_code = preg_replace( '/[^0-9]/', '', $submitted_code );
                    $factor_valid = false;
                    switch ( $cb2fa_challenge['active_factor'] ) {
                        case 'totp':
                            $secret = $cb2fa_totp->cb2fa_get_active_secret( $cb2fa_wp_user->ID );
                            if ( ! empty( $secret ) ) {
                                $factor_valid = $cb2fa_totp->cb2fa_verify_totp_for_user( $cb2fa_wp_user->ID, $secret, $submitted_numeric_code );
                            }
                            break;
                        case 'recovery':
                            $factor_valid = $cb2fa_totp->cb2fa_consume_recovery_code( $cb2fa_wp_user->ID, $submitted_code );
                            break;
                        case 'email':
                        default:
                            $factor_valid = ( ! empty( $cb2fa_challenge['email_code'] ) && hash_equals( $cb2fa_challenge['email_code'], $submitted_numeric_code ) );
                            break;
                    }
                    if ( ! $factor_valid ) {
                        $cb2fa_challenge['attempts'] = ( empty( $cb2fa_challenge['attempts'] ) ? 1 : ( (int)$cb2fa_challenge['attempts'] + 1 ) );
                        $cb2fa_plugin->cb2fa_store_challenge( $cb2fa_request_user, $cb2fa_request_nonce, $cb2fa_challenge );
                        $cb2fa_login->setChallenge( $cb2fa_challenge );
                        $cb2fa_login->setErrorMessage( __( 'Incorrect code, or code has expired', 'cloudbridge-2fa' ) );
                    } else {
                        $cb2fa_plugin->cb2fa_mark_challenge_consumed( $cb2fa_request_user, $cb2fa_request_nonce );
                        $is_administrator = false;
                        if ( ! empty( $cb2fa_wp_user->roles ) ) {
                            foreach ( $cb2fa_wp_user->roles as $role ) {
                                if ( $role === 'administrator' ) {
                                    $is_administrator = true;
                                    break;
                                }
                            }
                        }
                        if ( empty( $_REQUEST['redirect_to'] ) ) {
                            $redirect_to = ( $is_administrator ? admin_url() : home_url() );
                        } else {
                            $redirect_to = wp_validate_redirect(
                                sanitize_url( wp_unslash( $_REQUEST['redirect_to'] ), ['http', 'https'] ),
                                ( $is_administrator ? admin_url() : home_url() )
                            );
                        }
                        $cookie_hash = $cb2fa_login->getCookieHash();
                        $clear_cookie = true;
                        $the_url = wp_parse_url( get_site_url(), PHP_URL_HOST );
                        if ( $cb2fa_login->getAllowCookie() ) {
                            if ( ! empty( $_POST['cb2fa_cookie'] ) && sanitize_text_field( wp_unslash( $_POST['cb2fa_cookie'] ) ) === 'cb2fa_cookie' ) {
                                $clear_cookie = false;
                                setcookie(
                                    'cb2fa_' . $cookie_hash,
                                    'cb2fa_cookie',
                                    $cb2fa_login->getCookieTime(),
                                    '/',
                                    $the_url,
                                    $cb2fa_login->isSSL(),
                                    true
                                );
                            }
                        }
                        if ( $clear_cookie && ! empty( $cookie_hash ) ) {
                            setcookie( 'cb2fa_' . $cookie_hash, '', time() - 86400, '', $the_url );
                        }
                        $remember_me = ( ! empty( $_REQUEST['rememberme'] ) && sanitize_text_field( wp_unslash( $_REQUEST['rememberme'] ) ) === 'forever' );
                        wp_set_current_user( $cb2fa_wp_user->ID, $cb2fa_wp_user->user_login );
                        wp_set_auth_cookie( $cb2fa_wp_user->ID, $remember_me );
                        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core WordPress login hook.
                        do_action( 'wp_login', $cb2fa_wp_user->user_login, $cb2fa_wp_user );
                        nocache_headers();
                        wp_safe_redirect( $redirect_to );
                        die();
                    }
                }
            }
        }
    }

    ob_end_clean();
    nocache_headers();
    $cb2fa_login->drawForm();

    if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
        error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': End' );
    }
}

cb2fa_run_passthru();
