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
// Don't load directly
defined( 'ABSPATH' ) || die( '-1' );
// If uninstall not called from WordPress, then exit
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    if ( defined( 'CB2FA_UNINSTALL_TRACE' ) ) {
        error_log( 'cb2fa-uninstall: init' );
    }
    exit;
}
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


require_once( 'include/class_cb2fa_options.inc.php' );

//  define( 'CB2FA_UNINSTALL_TRACE', true );

// Figure out if an uninstall should remove plugin settings
$remove_settings = get_option( 'cloudbridge2fa-settings-remove', '0' );

if ( $remove_settings == '1' ) {
    if ( defined( 'CB2FA_UNINSTALL_TRACE' ) ) {
        error_log( 'cb2fa-uninstall: uninstalling' );
    }
    $cb2fa_all_options = \cloudbridge2fa\Cloudbridge_2FA_Options::cb2fa_our_options();
    foreach( $cb2fa_all_options as $option ) {
        delete_option( $option );
    }
    if ( defined( 'CB2FA_UNINSTALL_TRACE' ) ) {
        error_log( 'cb2fa-uninstall: ' . __FILE__ . ' end' );
    }
} else {
    if ( defined( 'CB2FA_UNINSTALL_TRACE' ) ) {
        error_log( 'cb2fa-uninstall: $remove_settings = ' . var_export( $remove_settings, true ) );
    }
}
