<?php
/**
 * Cloudbridge 2FA is uninstalled.
 *
 * @link    https://code.webbplatsen.net/wordpress/cloudbridge-2fa/
 * @since   1.0.0
 * @package Cloudbridge 2FA
 * @author  Joaquim Homrighausen <joho@webbplatsen.se>
 *
 * uninstall.php
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
// Don't load directly
defined( 'ABSPATH' ) || die( '-1' );
// If uninstall not called from WordPress, then exit
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    if ( defined( 'CB2FA_UNINSTALL_TRACE' ) ) {
        error_log( 'cb2fa-uninstall: init, WP_UNINSTALL_PLUGIN not defined' );
    }
    exit;
}

/**
 * We don't check these anymore.
 * https://developer.wordpress.org/plugins/plugin-basics/uninstall-methods/
 */
/*
// If action is not to uninstall, then exit
if ( empty( $_REQUEST['action'] ) || $_REQUEST['action'] !== 'delete-plugin' ) {
    if ( defined( 'CB2FA_UNINSTALL_TRACE' ) ) {
        error_log( 'cb2fa-uninstall: REQUEST["action"] is not delete-plugin' );
    }
    exit;
}
// If it's not us, then exit
if ( empty( $_REQUEST['slug'] ) || $_REQUEST['slug'] !== 'cloudbridge-2fa' ) {
    if ( defined( 'CB2FA_UNINSTALL_TRACE' ) ) {
        error_log( 'cb2fa-uninstall: REQUEST["slug"] is not cloudbridge-2fa' );
    }
    exit;
}
// If we shouldn't do this, then exit
if ( ! current_user_can( 'manage_options' ) || ! current_user_can( 'delete_plugins' ) ) {
    if ( defined( 'CB2FA_UNINSTALL_TRACE' ) ) {
        error_log( 'cb2fa-uninstall: User is not allowed to manage/uninstall plugins' );
    }
    exit;
}
*/


require_once( 'include/class_cb2fa_options.inc.php' );
require_once( 'include/class_cb2fa_totp.inc.php' );

//  define( 'CB2FA_UNINSTALL_TRACE', true );

function cb2fa_run_uninstall() : void {
    $cb2fa_remove_settings = get_option( 'cloudbridge2fa-settings-remove', '0' );

    if ( $cb2fa_remove_settings == '1' ) {
        if ( defined( 'CB2FA_UNINSTALL_TRACE' ) ) {
            error_log( 'cb2fa-uninstall: uninstalling' );
        }
        $cb2fa_all_options = \cloudbridge2fa\Cloudbridge_2FA_Options::cb2fa_our_options();
        foreach( $cb2fa_all_options as $cb2fa_option ) {
            delete_option( $cb2fa_option );
        }
        $cb2fa_all_user_meta = \cloudbridge2fa\Cloudbridge_2FA_TOTP::cb2fa_user_meta_keys();
        foreach ( $cb2fa_all_user_meta as $cb2fa_meta_key ) {
            delete_metadata( 'user', 0, $cb2fa_meta_key, '', true );
        }
        delete_metadata( 'user', 0, 'cloudbridge2fa_bypass', '', true );
        if ( defined( 'CB2FA_UNINSTALL_TRACE' ) ) {
            error_log( 'cb2fa-uninstall: ' . __FILE__ . ' end' );
        }
    } else {
        if ( defined( 'CB2FA_UNINSTALL_TRACE' ) ) {
            error_log( 'cb2fa-uninstall: $cb2fa_remove_settings = ' . var_export( $cb2fa_remove_settings, true ) );
        }
    }
}

cb2fa_run_uninstall();
