<?php
/**
 * Cloudbridge 2FA TOTP and recovery code helper.
 *
 * @since      2.0.0
 * @package    Cloudbridge 2FA
 * @subpackage cloudbridge-2fa/include
 * @author     Joaquim Homrighausen <joho@webbplatsen.se>
 *
 * class_cb2fa_totp.inc.php
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

if ( ! defined( 'WPINC' ) ) {
    error_log( basename( __FILE__ ) . ': WPINC not defined, exiting' );
    die;
}
if ( ! defined( 'ABSPATH' ) ) {
    error_log( basename( __FILE__ ) . ': ABSPATH not defined, exiting' );
    die( '-1' );
}
if ( ! defined( 'CB2FA_WORDPRESS_PLUGIN' ) ) {
    error_log( basename( __FILE__ ) . ': CB2FA_WORDPRESS_PLUGIN not defined, exiting' );
    die( '-1' );
}

if ( ! class_exists( 'cloudbridge2fa\Cloudbridge_2FA_TOTP' ) ) {

class Cloudbridge_2FA_TOTP {
    public static $instance = null;

    protected const META_TOTP_SECRET         = 'cloudbridge2fa_totp_secret';
    protected const META_TOTP_PENDING_SECRET = 'cloudbridge2fa_totp_pending_secret';
    protected const META_RECOVERY_CODES      = 'cloudbridge2fa_recovery_codes';
    protected const META_TOTP_LAST_TIMESLICE = 'cloudbridge2fa_totp_last_timeslice';
    protected const CIPHER_METHOD            = 'aes-256-cbc';
    protected const TOTP_DIGITS              = 6;
    protected const TOTP_PERIOD              = 30;
    protected const TOTP_ALGORITHM           = 'SHA1';

    protected string $issuer_name;

    public static function getInstance() {
        null === self::$instance AND self::$instance = new self();
        return( self::$instance );
    }

    public function __construct() {
        $issuer_name = get_bloginfo( 'name' );
        if ( empty( $issuer_name ) ) {
            $issuer_name = CB2FA_PLUGINNAME_HUMAN;
        }
        $this->issuer_name = $issuer_name;
    }

    public static function cb2fa_user_meta_keys() : array {
        return(
            [
                self::META_TOTP_SECRET,
                self::META_TOTP_PENDING_SECRET,
                self::META_RECOVERY_CODES,
                self::META_TOTP_LAST_TIMESLICE,
            ]
        );
    }

    public function cb2fa_is_available() : bool {
        return(
            function_exists( 'openssl_encrypt' )
            &&
            function_exists( 'openssl_decrypt' )
            &&
            function_exists( 'hash_hmac' )
        );
    }

    public function cb2fa_get_digits() : int {
        return( self::TOTP_DIGITS );
    }

    public function cb2fa_get_period() : int {
        return( self::TOTP_PERIOD );
    }

    public function cb2fa_get_algorithm() : string {
        return( self::TOTP_ALGORITHM );
    }

    protected function cb2fa_secret_key() : string {
        return( hash( 'sha256', wp_salt( 'auth' ) . '|' . wp_salt( 'secure_auth' ), true ) );
    }

    protected function cb2fa_encrypt_value( string $plaintext ) {
        if ( ! $this->cb2fa_is_available() ) {
            return( false );
        }
        $iv_length = openssl_cipher_iv_length( self::CIPHER_METHOD );
        if ( empty( $iv_length ) ) {
            return( false );
        }
        try {
            $iv = random_bytes( $iv_length );
        } catch ( \Exception $e ) {
            return( false );
        }
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER_METHOD,
            $this->cb2fa_secret_key(),
            OPENSSL_RAW_DATA,
            $iv
        );
        if ( $ciphertext === false ) {
            return( false );
        }
        $mac = hash_hmac( 'sha256', $iv . $ciphertext, $this->cb2fa_secret_key(), true );
        return( 'v1:' . base64_encode( $iv . $mac . $ciphertext ) );
    }

    protected function cb2fa_decrypt_value( string $encrypted_value ) {
        if ( ! $this->cb2fa_is_available() || empty( $encrypted_value ) ) {
            return( false );
        }
        if ( $encrypted_value === '!cleartext!' ) {
            return( false );
        }
        if ( strpos( $encrypted_value, 'v1:' ) !== 0 ) {
            return( false );
        }
        $payload = base64_decode( substr( $encrypted_value, 3 ), true );
        if ( $payload === false ) {
            return( false );
        }
        $iv_length = openssl_cipher_iv_length( self::CIPHER_METHOD );
        $mac_length = 32;
        if ( strlen( $payload ) <= ( $iv_length + $mac_length ) ) {
            return( false );
        }
        $iv = substr( $payload, 0, $iv_length );
        $mac = substr( $payload, $iv_length, $mac_length );
        $ciphertext = substr( $payload, $iv_length + $mac_length );
        $expected_mac = hash_hmac( 'sha256', $iv . $ciphertext, $this->cb2fa_secret_key(), true );
        if ( ! hash_equals( $expected_mac, $mac ) ) {
            return( false );
        }
        return(
            openssl_decrypt(
                $ciphertext,
                self::CIPHER_METHOD,
                $this->cb2fa_secret_key(),
                OPENSSL_RAW_DATA,
                $iv
            )
        );
    }

    public function cb2fa_generate_secret( int $length = 32 ) : string {
        static $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = '';
        for ( $i = 0; $i < $length; $i++ ) {
            try {
                $secret .= $alphabet[random_int( 0, 31 )];
            } catch ( \Exception $e ) {
                $secret .= $alphabet[wp_rand( 0, 31 )];
            }
        }
        return( $secret );
    }

    protected function cb2fa_base32_decode( string $secret ) {
        static $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = strtoupper( preg_replace( '/[^A-Z2-7]/', '', $secret ) );
        if ( empty( $secret ) ) {
            return( false );
        }
        $buffer = 0;
        $bits_left = 0;
        $decoded = '';
        $alphabet_map = array_flip( str_split( $alphabet ) );
        foreach ( str_split( $secret ) as $character ) {
            if ( ! isset( $alphabet_map[$character] ) ) {
                return( false );
            }
            $buffer = ( $buffer << 5 ) | $alphabet_map[$character];
            $bits_left += 5;
            if ( $bits_left >= 8 ) {
                $bits_left -= 8;
                $decoded .= chr( ( $buffer >> $bits_left ) & 0xFF );
            }
        }
        return( $decoded );
    }

    protected function cb2fa_calculate_totp_code( string $secret, int $timeslice ) {
        $binary_secret = $this->cb2fa_base32_decode( $secret );
        if ( $binary_secret === false ) {
            return( false );
        }
        $counter = pack( 'N*', 0 ) . pack( 'N*', $timeslice );
        $hash = hash_hmac( 'sha1', $counter, $binary_secret, true );
        if ( empty( $hash ) ) {
            return( false );
        }
        $offset = ord( substr( $hash, -1 ) ) & 0x0F;
        $chunk = substr( $hash, $offset, 4 );
        $value = unpack( 'N', $chunk );
        if ( ! is_array( $value ) || ! isset( $value[1] ) ) {
            return( false );
        }
        $code = $value[1] & 0x7FFFFFFF;
        return(
            str_pad(
                (string)( $code % ( 10 ** $this->cb2fa_get_digits() ) ),
                $this->cb2fa_get_digits(),
                '0',
                STR_PAD_LEFT
            )
        );
    }

    protected function cb2fa_get_matching_timeslice( string $secret, string $code, int $window = 1 ) {
        $code = preg_replace( '/[^0-9]/', '', $code );
        if ( strlen( $code ) !== $this->cb2fa_get_digits() ) {
            return( false );
        }
        $timeslice = (int)floor( time() / $this->cb2fa_get_period() );
        for ( $i = ( $timeslice - $window ); $i <= ( $timeslice + $window ); $i++ ) {
            $expected_code = $this->cb2fa_calculate_totp_code( $secret, $i );
            if ( ! empty( $expected_code ) && hash_equals( $expected_code, $code ) ) {
                return( $i );
            }
        }
        return( false );
    }

    public function cb2fa_verify_totp( string $secret, string $code, int $window = 1 ) : bool {
        return( $this->cb2fa_get_matching_timeslice( $secret, $code, $window ) !== false );
    }

    protected function cb2fa_get_last_verified_timeslice( int $user_id ) : int {
        $last_timeslice = get_user_meta( $user_id, self::META_TOTP_LAST_TIMESLICE, true );
        if ( $last_timeslice === '' || $last_timeslice === null ) {
            return( -1 );
        }
        return( (int)$last_timeslice );
    }

    public function cb2fa_verify_totp_for_user( int $user_id, string $secret, string $code, int $window = 1 ) : bool {
        $matching_timeslice = $this->cb2fa_get_matching_timeslice( $secret, $code, $window );
        if ( $matching_timeslice === false ) {
            return( false );
        }
        if ( $matching_timeslice <= $this->cb2fa_get_last_verified_timeslice( $user_id ) ) {
            return( false );
        }
        update_user_meta( $user_id, self::META_TOTP_LAST_TIMESLICE, (int)$matching_timeslice );
        return( true );
    }

    protected function cb2fa_save_user_secret( int $user_id, string $meta_key, string $secret ) : bool {
        $encrypted_secret = $this->cb2fa_encrypt_value( $secret );
        if ( $encrypted_secret === false ) {
            return( false );
        }
        return( (bool)update_user_meta( $user_id, $meta_key, $encrypted_secret ) );
    }

    protected function cb2fa_get_user_secret( int $user_id, string $meta_key ) : string {
        $encrypted_secret = get_user_meta( $user_id, $meta_key, true );
        if ( empty( $encrypted_secret ) || ! is_string( $encrypted_secret ) ) {
            return( '' );
        }
        $secret = $this->cb2fa_decrypt_value( $encrypted_secret );
        if ( ! is_string( $secret ) ) {
            return( '' );
        }
        return( $secret );
    }

    public function cb2fa_user_has_totp( int $user_id ) : bool {
        return( ! empty( $this->cb2fa_get_active_secret( $user_id ) ) );
    }

    public function cb2fa_get_active_secret( int $user_id ) : string {
        return( $this->cb2fa_get_user_secret( $user_id, self::META_TOTP_SECRET ) );
    }

    public function cb2fa_get_pending_secret( int $user_id ) : string {
        return( $this->cb2fa_get_user_secret( $user_id, self::META_TOTP_PENDING_SECRET ) );
    }

    public function cb2fa_ensure_pending_secret( int $user_id ) : string {
        $secret = $this->cb2fa_get_pending_secret( $user_id );
        if ( ! empty( $secret ) ) {
            return( $secret );
        }
        $secret = $this->cb2fa_generate_secret();
        if ( ! $this->cb2fa_save_user_secret( $user_id, self::META_TOTP_PENDING_SECRET, $secret ) ) {
            return( '' );
        }
        return( $secret );
    }

    public function cb2fa_enable_secret( int $user_id, string $secret ) : bool {
        if ( empty( $secret ) ) {
            return( false );
        }
        if ( ! $this->cb2fa_save_user_secret( $user_id, self::META_TOTP_SECRET, $secret ) ) {
            return( false );
        }
        delete_user_meta( $user_id, self::META_TOTP_PENDING_SECRET );
        return( true );
    }

    public function cb2fa_disable_totp( int $user_id ) : void {
        delete_user_meta( $user_id, self::META_TOTP_SECRET );
        delete_user_meta( $user_id, self::META_TOTP_PENDING_SECRET );
        delete_user_meta( $user_id, self::META_RECOVERY_CODES );
        delete_user_meta( $user_id, self::META_TOTP_LAST_TIMESLICE );
    }

    public function cb2fa_get_issuer_name() : string {
        return( $this->issuer_name );
    }

    public function cb2fa_get_account_name( $user ) : string {
        if ( ! empty( $user->data->user_email ) ) {
            return( $user->data->user_email );
        }
        if ( ! empty( $user->data->user_login ) ) {
            return( $user->data->user_login );
        }
        return( 'wordpress-user' );
    }

    public function cb2fa_get_otpauth_uri( $user, string $secret ) : string {
        $issuer = rawurlencode( $this->cb2fa_get_issuer_name() );
        $account = rawurlencode( $this->cb2fa_get_account_name( $user ) );
        return(
            'otpauth://totp/' .
            $issuer .
            ':' .
            $account .
            '?secret=' .
            rawurlencode( $secret ) .
            '&issuer=' .
            $issuer .
            '&algorithm=' .
            rawurlencode( $this->cb2fa_get_algorithm() ) .
            '&digits=' .
            rawurlencode( (string)$this->cb2fa_get_digits() ) .
            '&period=' .
            rawurlencode( (string)$this->cb2fa_get_period() )
        );
    }

    protected function cb2fa_generate_recovery_code_value( int $length = 12 ) : string {
        static $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $code = '';
        for ( $i = 0; $i < $length; $i++ ) {
            try {
                $code .= $alphabet[random_int( 0, strlen( $alphabet ) - 1 )];
            } catch ( \Exception $e ) {
                $code .= $alphabet[wp_rand( 0, strlen( $alphabet ) - 1 )];
            }
        }
        return( $code );
    }

    public function cb2fa_format_recovery_code( string $code ) : string {
        $code = strtoupper( preg_replace( '/[^A-Z0-9]/', '', $code ) );
        if ( empty( $code ) ) {
            return( '' );
        }
        return( trim( chunk_split( $code, 4, '-' ), '-' ) );
    }

    protected function cb2fa_normalize_recovery_code( string $code ) : string {
        return( strtoupper( preg_replace( '/[^A-Z0-9]/', '', $code ) ) );
    }

    public function cb2fa_regenerate_recovery_codes( int $user_id, int $count = 8 ) : array {
        $codes = [];
        for ( $i = 0; $i < $count; $i++ ) {
            $codes[] = $this->cb2fa_generate_recovery_code_value();
        }
        $encrypted_codes = $this->cb2fa_encrypt_value( wp_json_encode( $codes ) );
        if ( $encrypted_codes === false ) {
            return( [] );
        }
        update_user_meta( $user_id, self::META_RECOVERY_CODES, $encrypted_codes );
        return( $codes );
    }

    public function cb2fa_get_recovery_codes( int $user_id ) : array {
        $encrypted_codes = get_user_meta( $user_id, self::META_RECOVERY_CODES, true );
        if ( empty( $encrypted_codes ) || ! is_string( $encrypted_codes ) ) {
            return( [] );
        }
        $json_codes = $this->cb2fa_decrypt_value( $encrypted_codes );
        if ( empty( $json_codes ) ) {
            return( [] );
        }
        $codes = json_decode( $json_codes, true, 2 );
        if ( ! is_array( $codes ) ) {
            return( [] );
        }
        return( $codes );
    }

    public function cb2fa_user_has_recovery_codes( int $user_id ) : bool {
        return( ! empty( $this->cb2fa_get_recovery_codes( $user_id ) ) );
    }

    public function cb2fa_consume_recovery_code( int $user_id, string $code ) : bool {
        $normalized_code = $this->cb2fa_normalize_recovery_code( $code );
        if ( empty( $normalized_code ) ) {
            return( false );
        }
        $codes = $this->cb2fa_get_recovery_codes( $user_id );
        if ( empty( $codes ) ) {
            return( false );
        }
        foreach ( $codes as $index => $stored_code ) {
            if ( hash_equals( $this->cb2fa_normalize_recovery_code( $stored_code ), $normalized_code ) ) {
                unset( $codes[$index] );
                $encrypted_codes = $this->cb2fa_encrypt_value( wp_json_encode( array_values( $codes ) ) );
                if ( $encrypted_codes === false ) {
                    return( false );
                }
                update_user_meta( $user_id, self::META_RECOVERY_CODES, $encrypted_codes );
                return( true );
            }
        }
        return( false );
    }
}

} // ! class_exists( 'Cloudbridge_2FA_TOTP' )
