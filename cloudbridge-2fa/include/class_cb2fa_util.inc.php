<?php
/**
 * Cloudbridge 2FA utility functions.
 *
 * @since      1.0.0
 * @package    Cloudbridge 2FA
 * @subpackage cloudbridge-2fa/include
 * @author     Joaquim Homrighausen <joho@webbplatsen.se>
 *
 * class_2b2fa_util.inc.php
 * Copyright (C) 2024 Joaquim Homrighausen where applicable
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

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    error_log( basename(__FILE__) . ': WPINC not defined, exiting' );
    die;
}
if ( ! defined( 'ABSPATH' ) ) {
    error_log( basename(__FILE__) . ': ABSPATH not defined, exiting' );
    die( '-1' );
}
if ( ! defined( 'CB2FA_WORDPRESS_PLUGIN' ) ) {
    error_log( basename(__FILE__) . ': CB2FA_WORDPRESS_PLUGIN not defined, exiting' );
    die( '-1' );
}


if ( ! class_exists( 'cloudbridge2fa\Cloudbridge_2FA_Utility' ) ) {

class Cloudbridge_2FA_Utility {
    public static $instance = null;
    protected $cb2fa_have_mbstring;

    public static function getInstance() {
        null === self::$instance AND self::$instance = new self();
        return( self::$instance );
    }
    public function __construct() {
        if ( ! extension_loaded( 'mbstring' ) ) {
            $this->cb2fa_have_mbstring = false;
        } else {
            $this->cb2fa_have_mbstring = true;
        }
    }
    /**
     * Return status of mb_ extensions.
     *
     * @since 1.0.0
     */
    function x_have_mbstring() {
        return( $this->cb2fa_have_mbstring );
    }
    /**
     * Wrapper for mb_substr().
     *
     * @since 1.0.0
     */
    function x_substr( string $str, int $start, int $len = -1 ) {
        if ( $this->cb2fa_have_mbstring ) {
            if ( $len >= 0 ) {
                return( mb_substr( $str, $start, $len ) );
            }
            return( mb_substr( $str, $start ) );
        }
        if ( $len >= 0 ) {
            return( mb_substr( $str, $start, $len ) );
        }
        return( mb_substr( $str, $start ) );
    }
    /**
     * Wrapper for mb_strpos().
     *
     * @since 1.0.0
     */
    function x_strpos( string $haystack , string $needle , int $offset = 0 ) {
        if ( $this->cb2fa_have_mbstring ) {
            return( mb_strpos( $haystack, $needle, $offset ) );
        }
        return( strpos( $haystack, $needle, $offset ) );
    }
    /**
     * Wrapper for mb_stripos().
     *
     * @since 1.0.0
     */
    function x_stripos( string $haystack , string $needle , int $offset = 0 ) {
        if ( $this->cb2fa_have_mbstring ) {
            return( mb_stripos( $haystack, $needle, $offset ) );
        }
        return( stripos( $haystack, $needle, $offset ) );
    }
    /**
     * Wrapper for mb_strlen().
     *
     * @since 1.0.0
     */
    function x_strlen( string $str ) {
        if ( $this->cb2fa_have_mbstring ) {
            return( mb_strlen( $str ) );
        }
        return( strlen( $str ) );
    }
    /**
     * Wrapper for mb_strtolower().
     *
     * @since 1.0.0
     */
    function x_strtolower( string $str ) {
        if ( $this->cb2fa_have_mbstring ) {
            return( mb_strtolower( $str ) );
        }
        return( strtolower( $str ) );
    }
    /**
     * Wrapper for stripslashes()
     *
     * This will replace \' with ', and \" with "
     *
     * @since 1.0.0
     */
    function x_stripslashes( string $str ) {
        if ( $this->cb2fa_have_mbstring ) {
            return( mb_ereg_replace( '[\x{005c}][\x{0027}]', '\'', mb_ereg_replace( '[\x{005c}][\x{0022}]', '"', $str ) ) );
        }
        return( stripslashes( $str ) );
    }

} // class Cloudbridge_2FA_Utility


} // ! class_exists( 'Cloudbridge_2FA_Utility' )

// class_cb2fa_util.inc.php
