<?php
/**
 * Cloudbridge 2FA passthru
 *
 * @since      1.0.0
 * @package    Cloudbridge 2FA
 * @author     Joaquim Homrighausen <joho@webbplatsen.se>
 *
 * cb2fa-passthru.php
 * Copyright (C) 2024 Joaquim Homrighausen; all rights reserved.
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

// WPINC and ABSPATH are not defined at this point. We'll use DOCUMENT_ROOT
// from $_SERVER, which is not reachable from the "outside"

@ include $_SERVER['DOCUMENT_ROOT'] . '/wp-load.php';

if ( ! defined( 'WPINC' ) ) {
    die;
}
if ( ! defined( 'ABSPATH' ) ) {
    die( '-1' );
}
include_once( ABSPATH . 'wp-admin/includes/plugin.php' );

// Get things going
$cb2fa = Cloudbridge_2FA::getInstance();
$cb2fa_login = Cloudbridge_2FA_Login::getInstance( $cb2fa->cb2fa_getnonce() );

if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
    error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': Start' );
}

// Validate PIN code
if ( ! empty ( $_REQUEST['cb2fa_pincode'] ) ) {
    if ( ! empty( $_REQUEST['cb2fa_nonce'] ) && $_REQUEST['cb2fa_nonce'] == $cb2fa->cb2fa_getnonce() ) {
        if ( ! empty( $_REQUEST['cb2fa_user'] ) ) {
            $cb2fa_login->setUser( null, sanitize_text_field( $_REQUEST['cb2fa_user'] ) );
            if ( ! empty( $_REQUEST['cb2fa_timer'] ) && $_REQUEST['cb2fa_timer'] < time() ) {
                $our_transient = get_transient( CB2FA_TRANSIENT_PREFIX . $cb2fa_login->getUsername() . sanitize_text_field( $_REQUEST['cb2fa_nonce'] ) );
                if ( $our_transient !== false ) {
                    if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                        error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': Transient is "' . $our_transient . '"' );
                    }
                    $transient_parts = explode( '_', $our_transient );
                    if ( is_array( $transient_parts ) && count( $transient_parts) == 3 ) {
                        $cb2fa_login->setAllowCookie( ( $transient_parts[2] === 'Y' ) );
                        if ( $transient_parts[1] == $_REQUEST['cb2fa_pincode'] ) {
                            /**
                             * PIN code match, mark transient as consumed and
                             * attempt to login user. Things may still not work
                             * out, but it's looking good.
                             */
                            if ( set_transient( CB2FA_TRANSIENT_PREFIX . $cb2fa_login->getUsername() . sanitize_text_field( $_REQUEST['cb2fa_nonce'] ), 'consumed', time() ) ) {
                                if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                                    error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': Transient updated' );
                                }
                            } else {
                                if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                                    error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': Unable to mark transient as "consumed"' );
                                }
                            }
                            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': PIN code match' );
                            }
                            // Try to figure out if it's an e-mail address for get_user_by()
                            $is_email = filter_var( $cb2fa_login->getUsername(), FILTER_VALIDATE_EMAIL, FILTER_FLAG_EMAIL_UNICODE );
                            if ( $is_email ) {
                                $get_user_by = 'email';
                            } else {
                                $get_user_by = 'login';
                            }
                            $wp_user = get_user_by( $get_user_by, $cb2fa_login->getUsername() );
                            if ( $wp_user === false || get_class( $wp_user ) !== 'WP_User' ) {
                                // Something went wrong, bail
                                if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                                    if ( $wp_user !== false ) {
                                        error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': get_user_by() returned "' . get_class( $wp_user ) . '"' );
                                    } else {
                                        error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': get_user_by() returned unexpected value' );
                                    }
                                    $cb2fa_login->setErrorMessage( __( 'Unable to fetch WordPress user', 'cloudbridge-2fa' ) );
                                }
                            } elseif ( empty( $wp_user->roles ) ) {
                                if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                                    error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': User "' . $cb2fa_login->getUsername() . '" has no active roles' );
                                }
                            } else {
                                $cb2fa_login->setUser( $wp_user );
                                // Figure out if this an administrator
                                $is_administrator = false;
                                foreach ( $wp_user->roles as $role ) {
                                    if ( $role == 'administrator' ) {
                                        $is_administrator = true;
                                        break;
                                    }
                                }// foreach
                                // Figure out where to re-direct user
                                if ( empty( $_REQUEST['redirect_to'] ) ) {
                                    $redirect_to = ( $is_administrator ? admin_url() : home_url() );
                                } else {
                                    $redirect_to = sanitize_url( $_REQUEST['redirect_to'], array( 'http', 'https' ) );
                                }
                                // Possibly set our cookie
                                $cookie_hash = $cb2fa_login->getCookieHash();
                                $clear_cookie = true;
                                $the_url = parse_url( get_site_url(), PHP_URL_HOST );
                                if ( $cb2fa_login->getAllowCookie() ) {
                                    if ( ! empty( $_POST['cb2fa_cookie'] ) && $_POST['cb2fa_cookie'] == 'cb2fa_cookie' ) {
                                        $clear_cookie = false;
                                        setcookie( 'cb2fa_' . $cookie_hash,
                                                   'cb2fa_cookie',
                                                   $cb2fa_login->getCookieTime(),
                                                   '/',
                                                   $the_url, $cb2fa_login->isSSL(), true );
                                        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                                            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': Setting cookie "cb2fa_' . $cookie_hash . '" for "' . $the_url . '" with time "' . date( 'Y-m-d, H:i:s', $cb2fa_login->getCookieTime() ) . '"' );
                                        }
                                    }
                                }
                                if ( $clear_cookie && ! empty( $cookie_hash ) ) {
                                    setcookie( 'cb2fa_' . $cookie_hash, '', time() - 86400, '', $the_url );
                                    if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                                        error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': Clearing cookie "cb2fa_' . $cookie_hash . '" for "' . $the_url . '"' );
                                    }
                                }
                                // Check WordPress "remember me"
                                $remember_me = ( ! empty( $_REQUEST['rememberme'] ) && $_REQUEST['rememberme'] == 'forever' );
                                // Setup WordPress session
                                wp_set_current_user( $wp_user->ID, $wp_user->user_login );
                                wp_set_auth_cookie( $wp_user->ID, $remember_me );
                                do_action( 'wp_login', $wp_user->user_login, $wp_user );
                                // Carry on, we're logged in
                                nocache_headers();
                                wp_redirect( $redirect_to );
                                die ();
                            }
                            /* PIN code match */
                        } else {
                            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': PIN code mismatch' );
                            }
                            $cb2fa_login->setErrorMessage( __( 'Incorrect code, or code has expired', 'cloudbridge-2fa' ) );
                        }
                    } else {
                        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': Invalid transient ' . print_r( $transient_parts, true ) );
                        }
                        $cb2fa_login->setErrorMessage( __( 'Incorrect code, or code has expired', 'cloudbridge-2fa' ) );
                    }
                } else {
                    if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                        error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': No transient found' );
                    }
                    $cb2fa_login->setErrorMessage( __( 'Incorrect code, or code has expired', 'cloudbridge-2fa' ) );
                }
            } else {
                if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                    error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': No timer or timer mismatch' );
                }
            }
        } else {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': No username' );
            }
        }
    } else {
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': No nonce or nonce mismatch' );
        }
    }
} else {
    if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
        error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': No PIN code' );
    }
    $cb2fa_login->setErrorMessage( __( 'Please enter the code received by e-mail', 'cloudbridge-2fa' ) );
}

// Draw form again

ob_end_clean();
nocache_headers();
$cb2fa_login->drawForm();

if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
    error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ': End' );
}
