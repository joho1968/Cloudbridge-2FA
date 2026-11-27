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

// This file survives deactivation; reject without redirecting to ordinary login.
if ( ! is_plugin_active( plugin_basename( __DIR__ . '/cloudbridge-2fa.php' ) )
    || ! class_exists( Cloudbridge_2FA::class, false )
    || ! class_exists( Cloudbridge_2FA_State::class, false )
    || ! class_exists( Cloudbridge_2FA_Login::class, false )
    || ! class_exists( Cloudbridge_2FA_TOTP::class, false )
    || ! method_exists( Cloudbridge_2FA::class, 'cb2fa_verify_interactive_request' )
    || Cloudbridge_2FA::getInstance()->cb2fa_external_login_api_version() !== 2 ) {
    status_header( 503 ); nocache_headers();
    echo '<!doctype html><html><body><p>' . esc_html__( 'Your login verification expired. Please sign in again.', 'cloudbridge-2fa' ) . '</p><a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Log In', 'default' ) . '</a></body></html>';
    exit;
}
Cloudbridge_2FA::getInstance()->cb2fa_verify_interactive_request();
