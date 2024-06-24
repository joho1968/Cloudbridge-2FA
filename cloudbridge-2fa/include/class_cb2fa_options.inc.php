<?php
/**
 * Cloudbridge 2FA options in the WordPress database.
 *
 * @since      1.0.0
 * @package    Cloudbridge 2FA
 * @subpackage cloudbridge-2fa/include
 * @author     Joaquim Homrighausen <joho@webbplatsen.se>
 *
 * class_cb2fa_options.php
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

class Cloudbridge_2FA_Options {
    static $cb2fa_all_options = array(
        'cloudbridge2fa-form-tab',
        'cloudbridge2fa-roles-config',
        'cloudbridge2fa-cookies-config',
        'cloudbridge2fa-code-lifetime',
        'cloudbridge2fa-cookie-lifetime',
        'cloudbridge2fa-code-input-text-addon',
        'cloudbridge2fa-code-email-text-addon',
        'cloudbridge2fa-code-email-subject',
        'cloudbridge2fa-admin-users',
        'cloudbridge2fa-settings-remove',
        );

    /**
     * Determine if $option needs to be json encoded.
     *
     * @param string $option
     * @return bool
     */
    public static function cb2fa_is_option_json( string $option ) : bool {
        static $cb2fa_json_options = array(
            'cloudbridge2fa-roles-config',
            'cloudbridge2fa-cookies-config',
            'cloudbridge2fa-admin-users',
        );
        return( in_array( $option, $cb2fa_json_options ) );
    }

    /**
     * Determine if $option is one we recognize
     *
     * @param string $option
     * @return bool
     */
    public static function cb2fa_is_our_option( string $option ) : bool {
        return( in_array( $option, self::$cb2fa_all_options ) );

    }

    /**
     * Return all of our options as array.
     *
     * @return string[]
     */
    public static function cb2fa_our_options() : array {
        return( self::$cb2fa_all_options );
    }
}
