<?php
/**
 * Cloudbridge 2FA shared authentication state.
 *
 * @since      2.0.2
 * @package    Cloudbridge 2FA
 * @subpackage cloudbridge-2fa/include
 * @author     Joaquim Homrighausen <joho@webbplatsen.se>
 *
 * class_cb2fa_state.inc.php
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

defined( 'ABSPATH' ) || die( '-1' );

class Cloudbridge_2FA_State {
    private static array $locks = [];

    /** Serialize factor consumption across workers, including with Redis enabled. */
    public static function lock( int $user_id, int $wait_seconds = 0 ) : bool {
        global $wpdb;
        $name = 'cb2fa_' . hash( 'sha256', $wpdb->usermeta . ':' . $user_id );
        $name = substr( $name, 0, 64 );
        if ( isset( self::$locks[$name] ) ) {
            self::$locks[$name]++;
            return( true );
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- A database advisory lock must execute on this connection.
        if ( (string)$wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, %d)', $name, max( 0, min( 1, $wait_seconds ) ) ) ) !== '1' ) {
            return( false );
        }
        self::$locks[$name] = 1;
        // Another worker may have changed factor state before this lock.
        wp_cache_delete( $user_id, 'user_meta' );
        return( true );
    }

    public static function unlock( int $user_id ) : void {
        global $wpdb;
        $name = substr( 'cb2fa_' . hash( 'sha256', $wpdb->usermeta . ':' . $user_id ), 0, 64 );
        if ( ! isset( self::$locks[$name] ) ) {
            return;
        }
        self::$locks[$name]--;
        if ( self::$locks[$name] === 0 ) {
            unset( self::$locks[$name] );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Release this connection's advisory lock.
            $wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', $name ) );
        }
    }

    /** Avoid stale request-local caches after acquiring the shared lock. */
    public static function get( string $key ) {
        if ( wp_using_ext_object_cache() ) {
            return( wp_cache_get( $key, 'transient', true ) );
        }
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Fresh security state is required after acquiring the shared lock.
        $timeout = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", '_transient_timeout_' . $key ) );
        if ( ! is_numeric( $timeout ) || (int)$timeout <= time() ) {
            return( false );
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Option API request-local caches can retain state consumed by another worker.
        $value = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", '_transient_' . $key ) );
        return( $value === null ? false : maybe_unserialize( $value ) );
    }

    public static function set_cookie( string $name, string $value, int $expires ) : bool {
        return( setcookie( $name, $value, [
            'expires'  => $expires,
            'path'     => '/',
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ] ) );
    }
}
