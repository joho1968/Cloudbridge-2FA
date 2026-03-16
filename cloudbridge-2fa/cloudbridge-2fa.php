<?php
/**
 * Cloudbridge 2FA
 *
 * @link    https://code.webbplatsen.net/wordpress/cloudbridge-2fa/
 * @since   1.0.0
 * @package Cloudbridge 2FA
 * @author  Joaquim Homrighausen <joho@webbplatsen.se>
 *
 * @wordpress-plugin
 * Plugin Name:       Cloudbridge 2FA
 * Plugin URI:        https://code.webbplatsen.net/wordpress/cloudbridge-2fa/
 * Description:       Uncomplicated 2FA plugin for WordPress
 * Version:           2.0.1
 * Author:            WebbPlatsen, Joaquim Homrighausen <joho@webbplatsen.se>
 * Author URI:        https://webbplatsen.se/
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       cloudbridge-2fa
 * Domain Path:       /languages
 *
 * cloudbridge-2fa.php
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

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    die;
}
if ( ! defined( 'ABSPATH' ) ) {
    die( '-1' );
}

define( 'CB2FA_WORDPRESS_PLUGIN',         true                    );
define( 'CB2FA_VERSION',                  '2.0.1'                 );
define( 'CB2FA_REV',                      2                       );
define( 'CB2FA_PLUGINNAME_HUMAN',         'Cloudbridge 2FA'       );
define( 'CB2FA_DEFAULT_PREFIX',           'cloudbridge2fa'        );
define( 'CB2FA_TRANSIENT_PREFIX',         'cloudbridge2fa'        );
define( 'CB2FA_TRANSIENT_EXPIRE_DEFAULT', 15                      );
define( 'CB2FA_COOKIE_EXPIRE_DEFAULT',    0                       );
define( 'CB2FA_DB_VERSION',               1                       );
define( 'CB2FA_ICONSTYLE_DASHICONS',      0 /* default */         );
define( 'CB2FA_ICONSTYLE_FA',             1                       );
define( 'CB2FA_DEBUG',                    false                   );
define( 'CB2FA_DEBUG_INIT',               false                   );
define( 'CB2FA_DEBUG_OPTIONS',            false                   );

include_once( ABSPATH . 'wp-admin/includes/plugin.php' );
require_once( plugin_dir_path( __FILE__ ) . 'include/class_cb2fa_util.inc.php' );
require_once( plugin_dir_path( __FILE__ ) . 'include/class_cb2fa_login.inc.php' );
require_once( plugin_dir_path( __FILE__ ) . 'include/class_cb2fa_options.inc.php' );
require_once( plugin_dir_path( __FILE__ ) . 'include/class_cb2fa_totp.inc.php' );

/**
 * Always require 2FA
 * (if not set ... then do roles)
 * Roles + required
 * Limit 2FA configuration to these roles
 * Limit 2FA configuration to these users
 */
class Cloudbridge_2FA {
    public static $instance = null;
    protected static array $cb2fa_admin_caps = ['update_plugins', 'install_plugins', 'delete_plugins', 'edit_plugins'];
    protected const USER_META_BYPASS = 'cloudbridge2fa_bypass'; // @since 2.0.0
    protected $cb2fa_wordpress_admin_users = null;
    protected $_cb2fa_is_plugin_admin = null;
    protected $Utility;                                      // @since 1.0.0
    protected $TOTP;                                         // @since 2.0.0
    protected bool $cb2fa_have_scfa;                         // @since 1.0.0
    protected int $cb2fa_icon_style;                         // @since 1.0.0
    protected $cb2fa_locale;                                 // @since 1.0.0
    protected $cb2fa_tz_string;                              // @since 1.0.0
    protected string $cb2fa_nonce;                           // @since 1.0.0
    protected string $cb2fa_form_tab;                        // @since 1.0.0
    protected bool $cb2fa_doing_import = false;              // @since 1.0.0
    protected $cb2fa_wp_roles = null;                        // @since 1.0.0
    protected $cb2fa_wp_roles_enus = null;                   // @since 1.0.0

    protected $cb2fa_roles_configuration;                    // @since 1.0.0
    protected $cb2fa_cookies_configuration;                  // @since 1.0.0
    protected bool $cb2fa_email_otp_enabled;                // @since 2.0.0
    protected bool $cb2fa_totp_enabled;                     // @since 2.0.0
    protected $cb2fa_code_lifetime;                          // @since 1.0.0
    protected $cb2fa_cookie_lifetime;                        // @since 1.0.0
    protected string $cb2fa_code_input_text_addon;           // @since 1.0.0
    protected string $cb2fa_code_email_text_addon;           // @since 1.0.0
    protected string $cb2fa_code_email_subject;              // @since 1.0.0
    protected $cb2fa_admin_users;                            // @since 1.0.0
    protected $cb2fa_settings_remove;                        // @since 1.0.0

    public static function getInstance()
    {
        null === self::$instance AND self::$instance = new self();
        return( self::$instance );
    }
    /**
     * Start me up ...
     */
    public function __construct() {
        if ( defined( 'CB2FA_DEBUG_INIT' ) && CB2FA_DEBUG_INIT ) {
            error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): init' );
        }
        // Utilities
        $this->Utility = Cloudbridge_2FA_Utility::getInstance();
        if ( ! is_object( $this->Utility ) ) {
            error_log( '[CB2FA] ' . basename(__FILE__) . ' (' . __FUNCTION__ . '): Unable to create $Utility instance (?)' );
        }
        $this->TOTP = Cloudbridge_2FA_TOTP::getInstance();
        if ( ! is_object( $this->TOTP ) ) {
            error_log( '[CB2FA] ' . basename(__FILE__) . ' (' . __FUNCTION__ . '): Unable to create $TOTP instance (?)' );
        }
        $this->cb2fa_form_tab = get_option( 'cloudbridge2fa-form-tab', '' );
        // Figure out our locale
        $this->cb2fa_tz_string = get_option( 'timezone_string', '!*!' );
        $wp_charset = get_bloginfo( 'charset' );
        if ( empty( $wp_charset ) ) {
            $wp_charset = 'UTF-8';
        }
        $wp_lang = get_bloginfo( 'language' );
        if ( empty( $wp_lang ) ) {
            $wp_lang = 'en_US';
        }
        $this->cb2fa_locale = $wp_lang . '.' . $wp_charset;

        // Make sure we notify about missing mbstring
        if ( ! $this->Utility->x_have_mbstring() ) {
            add_action( 'admin_notices', [$this, 'cb2fa_admin_alert_missing_mbstring'] );
        }
        // Should we display activation notice?
        if  ( get_option( 'cloudbridge2fa-activated', null ) !== null ) {
            add_action( 'admin_notices', [$this, 'cb2fa_admin_alert_plugin_activated'] );
            delete_option( 'cloudbridge2fa-form-tab' );
            delete_option( 'cloudbridge2fa-activated' );
            $this->cb2fa_form_tab = '';
        }
        // See if Shortcodes for Font Awesome (SCFA) is present
        if ( is_plugin_active( 'shortcodes-for-font-awesome/scfa.php' ) ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): Using FontAwesome (SCFA)' );
            }
            $this->cb2fa_have_scfa = true;
            $this->cb2fa_icon_style = (int)CB2FA_ICONSTYLE_FA;
        } else {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): Using DashIcons' );
            }
            $this->cb2fa_have_scfa = false;
            $this->cb2fa_icon_style = (int)CB2FA_ICONSTYLE_DASHICONS;
        }
        /*
        $this->cb2fa_have_scfa = false;
        $this->cb2fa_icon_style = (int)CB2FA_ICONSTYLE_DASHICONS;
        */
        // Configuration
        // Fetch options and setup defaults
        $this->cb2fa_roles_configuration = @ json_decode( get_option( 'cloudbridge2fa-roles-config', null ), true, 2 );
        if ( ! is_array( $this->cb2fa_roles_configuration ) ) {
            $this->cb2fa_roles_configuration = array();
        }
        $this->cb2fa_cookies_configuration = @ json_decode( get_option( 'cloudbridge2fa-cookies-config', null ), true, 2 );
        if ( ! is_array( $this->cb2fa_cookies_configuration ) ) {
            $this->cb2fa_cookies_configuration = array();
        }
        // Preserve legacy behavior for upgraded installs: e-mail OTP stays enabled unless explicitly turned off.
        $this->cb2fa_email_otp_enabled = get_option( 'cloudbridge2fa-email-otp-enabled', true ) ? true : false;
        $this->cb2fa_totp_enabled = get_option( 'cloudbridge2fa-totp-enabled', false ) ? true : false;
        $this->cb2fa_code_lifetime = get_option( 'cloudbridge2fa-code-lifetime', null );
        if ( $this->cb2fa_code_lifetime === null || $this->cb2fa_code_lifetime < 1 || $this->cb2fa_code_lifetime > 60 ) {
            $this->cb2fa_code_lifetime = CB2FA_TRANSIENT_EXPIRE_DEFAULT;
        }
        $this->cb2fa_cookie_lifetime = get_option( 'cloudbridge2fa-cookie-lifetime', null );
        if ( $this->cb2fa_cookie_lifetime === null || $this->cb2fa_cookie_lifetime < 0 || $this->cb2fa_cookie_lifetime > 365 ) {
            $this->cb2fa_cookie_lifetime = CB2FA_COOKIE_EXPIRE_DEFAULT;
        }
        $this->cb2fa_code_input_text_addon = get_option( 'cloudbridge2fa-code-input-text-addon', '' );
        if ( ! empty( $this->cb2fa_code_input_text_addon ) ) {
            $this->cb2fa_code_input_text_addon = $this->Utility->x_substr( $this->cb2fa_code_input_text_addon, 0, 200 );
        }
        $this->cb2fa_code_email_text_addon = get_option( 'cloudbridge2fa-code-email-text-addon', '' );
        if ( ! empty( $this->cb2fa_code_email_text_addon ) ) {
            $this->cb2fa_code_email_text_addon = $this->Utility->x_substr( $this->cb2fa_code_email_text_addon, 0, 500 );
        }
        $this->cb2fa_code_email_subject = get_option( 'cloudbridge2fa-code-email-subject', false );
        if ( ! empty( $this->cb2fa_code_email_subject ) ) {
            $this->cb2fa_code_email_subject = true;
        }
        $this->cb2fa_admin_users = @ json_decode( get_option( 'cloudbridge2fa-admin-users', null ), true, 2 );
        if ( ! is_array( $this->cb2fa_admin_users ) ) {
            $this->cb2fa_admin_users = array();
        }
        $this->cb2fa_settings_remove = get_option( 'cloudbridge2fa-settings-remove', false );
        if ( ! empty( $this->cb2fa_settings_remove ) ) {
            $this->cb2fa_settings_remove = true;
        }
        if ( $this->cb2fa_totp_enabled && ( ! is_object( $this->TOTP ) || ! $this->TOTP->cb2fa_is_available() ) ) {
            add_action( 'admin_notices', [$this, 'cb2fa_admin_alert_missing_openssl'] );
        }
    }
    /**
     * Check if we have actively configured 2FA roles.
     *
     * @return bool
     * @since 1.0.0
     */
    protected function cb2fa_active_roles() : bool {
        return( ! empty( $this->cb2fa_roles_configuration ) );

    }
    /**
     * Fetch our generated nonce.
     *
     * @return string
     * @since 1.0.0
     */
    public function cb2fa_getnonce() : string {
        return( $this->cb2fa_nonce );
    }

    protected function cb2fa_verify_runtime_nonce( string $nonce ) : bool {
        if ( empty( $nonce ) ) {
            return( false );
        }
        return( wp_verify_nonce( $nonce, 'cloudbridge-2fa' . CB2FA_VERSION ) !== false );
    }

    /**
     * Validate redirect targets and keep them on this site.
     *
     * @param string $redirect_to
     * @param string $fallback_url
     * @return string
     * @since 1.0.5
     */
    protected function cb2fa_validate_redirect_url( string $redirect_to = '', string $fallback_url = '' ) : string {
        if ( empty( $fallback_url ) ) {
            $fallback_url = home_url();
        }
        if ( empty( $redirect_to ) ) {
            return( $fallback_url );
        }
        $redirect_to = sanitize_url( $redirect_to, ['http', 'https'] );
        $redirect_to = wp_validate_redirect( $redirect_to, $fallback_url );
        if ( empty( $redirect_to ) ) {
            return( $fallback_url );
        }
        return( $redirect_to );
    }

    public function cb2fa_get_login_restart_url( string $redirect_to = '' ) : string {
        $safe_redirect = '';
        if ( ! empty( $redirect_to ) ) {
            $safe_redirect = $this->cb2fa_validate_redirect_url( $redirect_to, '' );
        }
        $login_url = wp_login_url( $safe_redirect );
        return( add_query_arg( 'cb2fa_notice', 'restart', $login_url ) );
    }

    public function cb2fa_get_totp_helper() {
        return( $this->TOTP );
    }

    protected function cb2fa_email_factor_enabled() : bool {
        return( $this->cb2fa_email_otp_enabled );
    }

    protected function cb2fa_totp_factor_enabled() : bool {
        return(
            $this->cb2fa_totp_enabled
            &&
            is_object( $this->TOTP )
            &&
            $this->TOTP->cb2fa_is_available()
        );
    }

    protected function cb2fa_can_manage_user_bypass() : bool {
        return(
            is_admin()
            &&
            current_user_can( 'manage_options' )
            &&
            $this->cb2fa_is_plugin_admin()
        );
    }

    protected function cb2fa_user_has_bypass( int $user_id ) : bool {
        return( get_user_meta( $user_id, self::USER_META_BYPASS, true ) === '1' );
    }

    protected function cb2fa_set_user_bypass( int $user_id, bool $enabled ) : bool {
        if ( $enabled ) {
            return( (bool)update_user_meta( $user_id, self::USER_META_BYPASS, '1' ) );
        }
        delete_user_meta( $user_id, self::USER_META_BYPASS );
        return( true );
    }

    protected function cb2fa_get_all_users() : array {
        if ( $this->cb2fa_wordpress_admin_users === null ) {
            $this->cb2fa_wordpress_admin_users = get_users( [
                'orderby' => 'login',
                'order'   => 'ASC',
            ] );
        }
        if ( ! is_array( $this->cb2fa_wordpress_admin_users ) ) {
            return( [] );
        }
        return( $this->cb2fa_wordpress_admin_users );
    }

    protected function cb2fa_get_bypass_users() : array {
        $bypass_users = get_users( [
            'meta_key'   => self::USER_META_BYPASS,
            'meta_value' => '1',
            'orderby'    => 'login',
            'order'      => 'ASC',
        ] );
        if ( ! is_array( $bypass_users ) ) {
            return( [] );
        }
        return( $bypass_users );
    }

    protected function cb2fa_get_translated_role_list( \WP_User $user ) : string {
        $translated_roles = [];
        $available_roles = $this->cb2fa_get_wp_roles();

        if ( ! empty( $user->roles ) && is_array( $user->roles ) ) {
            foreach ( $user->roles as $role_name ) {
                if ( ! empty( $available_roles[$role_name] ) ) {
                    $translated_roles[] = $available_roles[$role_name];
                } else {
                    $translated_roles[] = $role_name;
                }
            }
        }

        if ( empty( $translated_roles ) ) {
            return( __( 'No role', 'cloudbridge-2fa' ) );
        }

        return( implode( ', ', $translated_roles ) );
    }

    protected function cb2fa_get_bypass_warning_html( array $bypass_users ) : string {
        if ( empty( $bypass_users ) ) {
            return( '' );
        }

        $bypass_usernames = [];
        foreach ( $bypass_users as $bypass_user ) {
            if ( $bypass_user instanceof \WP_User && ! empty( $bypass_user->user_login ) ) {
                $bypass_usernames[] = $bypass_user->user_login;
            }
        }
        $bypass_label = implode( ', ', $bypass_usernames );
        if ( empty( $bypass_label ) ) {
            $bypass_label = __( 'unknown users', 'cloudbridge-2fa' );
        }

        $warning  = '<div class="notice notice-warning inline cb2fa-inline-warning"><p><strong>';
        $warning .= esc_html(
            sprintf(
                _n(
                    'Emergency bypass is currently enabled for %1$d account: %2$s.',
                    'Emergency bypass is currently enabled for %1$d accounts: %2$s.',
                    count( $bypass_users ),
                    'cloudbridge-2fa'
                ),
                count( $bypass_users ),
                $bypass_label
            )
        );
        $warning .= '</strong> ';
        $warning .= esc_html__( 'Review this on the Bypass 2FA tab.', 'cloudbridge-2fa' );
        $warning .= '</p></div>';

        return( $warning );
    }

    protected function cb2fa_handle_bypass_form() : void {
        if ( ! $this->cb2fa_can_manage_user_bypass() ) {
            return;
        }
        if ( empty( $_GET['page'] ) || sanitize_key( wp_unslash( $_GET['page'] ) ) !== 'cloudbridge-2fa' ) {
            return;
        }
        if ( empty( $_POST['cb2fa_bypass_form'] ) ) {
            return;
        }
        if ( empty( $_POST['cb2fa_bypass_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['cb2fa_bypass_nonce'] ) ), 'cb2fa-save-bypass' ) ) {
            add_settings_error( 'cloudbridge-2fa', 'cb2fa-bypass-nonce', __( 'Unable to save bypass settings because the security check failed. Please try again.', 'cloudbridge-2fa' ), 'error' );
            return;
        }

        $requested_bypass_ids = [];
        if ( ! empty( $_POST['cb2fa_bypass_users'] ) && is_array( $_POST['cb2fa_bypass_users'] ) ) {
            foreach ( $_POST['cb2fa_bypass_users'] as $cb2fa_posted_user_id ) {
                $cb2fa_user_id = (int)sanitize_text_field( wp_unslash( $cb2fa_posted_user_id ) );
                if ( $cb2fa_user_id > 0 ) {
                    $requested_bypass_ids[] = $cb2fa_user_id;
                }
            }
        }
        $requested_bypass_ids = array_values( array_unique( $requested_bypass_ids ) );

        $updated_count = 0;
        foreach ( $this->cb2fa_get_all_users() as $cb2fa_user ) {
            if ( ! $cb2fa_user instanceof \WP_User ) {
                continue;
            }
            $requested_bypass = in_array( (int)$cb2fa_user->ID, $requested_bypass_ids, true );
            $current_bypass = $this->cb2fa_user_has_bypass( (int)$cb2fa_user->ID );
            if ( $requested_bypass === $current_bypass ) {
                continue;
            }
            $this->cb2fa_set_user_bypass( (int)$cb2fa_user->ID, $requested_bypass );
            $updated_count++;
        }

        $this->cb2fa_form_tab = 'bypass-2fa';
        if ( $updated_count === 0 ) {
            add_settings_error( 'cloudbridge-2fa', 'cb2fa-bypass-unchanged', __( 'No bypass settings needed to be changed.', 'cloudbridge-2fa' ), 'info' );
        } else {
            add_settings_error(
                'cloudbridge-2fa',
                'cb2fa-bypass-updated',
                sprintf(
                    _n(
                        'Saved bypass settings for %d account.',
                        'Saved bypass settings for %d accounts.',
                        $updated_count,
                        'cloudbridge-2fa'
                    ),
                    $updated_count
                ),
                'updated'
            );
        }
    }

    public function cb2fa_setting_sanitize_checkbox( $input ) {
        if ( ! $this->cb2fa_is_plugin_admin() && ! $this->cb2fa_doing_import )  {
            return;
        }
        return( empty( $input ) ? 0 : 1 );
    }

    protected function cb2fa_get_challenge_key( string $username, string $nonce ) : string {
        return( CB2FA_TRANSIENT_PREFIX . $username . $nonce );
    }

    protected function cb2fa_get_user_available_factors( \WP_User $user ) : array {
        $factors = [];
        if ( $this->cb2fa_totp_factor_enabled() && $this->TOTP->cb2fa_user_has_totp( $user->ID ) ) {
            $factors[] = 'totp';
            if ( $this->TOTP->cb2fa_user_has_recovery_codes( $user->ID ) ) {
                $factors[] = 'recovery';
            }
        }
        if ( $this->cb2fa_email_factor_enabled() && ! empty( $user->data->user_email ) ) {
            $factors[] = 'email';
        }
        return( array_values( array_unique( $factors ) ) );
    }

    protected function cb2fa_get_primary_factor( array $available_factors ) : string {
        if ( in_array( 'totp', $available_factors, true ) ) {
            return( 'totp' );
        }
        if ( in_array( 'email', $available_factors, true ) ) {
            return( 'email' );
        }
        return( 'recovery' );
    }

    protected function cb2fa_generate_email_code() : string {
        $code = '......';
        try {
            for ( $i = 0; $i < 6; $i++ ) {
                $code[$i] = random_int( 0, 9 );
            }
        } catch ( \Exception $e ) {
            for ( $i = 0; $i < 6; $i++ ) {
                $code[$i] = wp_rand( 0, 9 );
            }
        }
        return( $code );
    }

    public function cb2fa_get_challenge( string $username, string $nonce ) {
        $challenge = get_transient( $this->cb2fa_get_challenge_key( $username, $nonce ) );
        if ( ! is_array( $challenge ) ) {
            return( false );
        }
        return( $challenge );
    }

    public function cb2fa_store_challenge( string $username, string $nonce, array $challenge ) : bool {
        return(
            set_transient(
                $this->cb2fa_get_challenge_key( $username, $nonce ),
                $challenge,
                ( $this->cb2fa_code_lifetime * 60 )
            )
        );
    }

    public function cb2fa_mark_challenge_consumed( string $username, string $nonce ) : bool {
        return(
            set_transient(
                $this->cb2fa_get_challenge_key( $username, $nonce ),
                ['status' => 'consumed'],
                MINUTE_IN_SECONDS
            )
        );
    }

    public function cb2fa_prepare_challenge_factor( array $challenge, string $factor ) : array {
        if ( empty( $challenge['available_factors'] ) || ! in_array( $factor, $challenge['available_factors'], true ) ) {
            return( $challenge );
        }
        $challenge['active_factor'] = $factor;
        if ( $factor === 'email' ) {
            $challenge['email_code'] = $this->cb2fa_generate_email_code();
        } else {
            $challenge['email_code'] = '';
        }
        return( $challenge );
    }

    protected function cb2fa_create_login_challenge( \WP_User $user, string $username, bool $allow_cookie = false ) {
        $available_factors = $this->cb2fa_get_user_available_factors( $user );
        if ( empty( $available_factors ) ) {
            return(
                new \WP_Error(
                    'CB2FA',
                    __( 'This account is required to use two-factor authentication, but no login factor is available. Contact the site administrator.', 'cloudbridge-2fa' ),
                    'This is CB2FA data'
                )
            );
        }
        $challenge = [
            'status'            => 'pending',
            'created_at'        => time(),
            'user_id'           => (int)$user->ID,
            'allow_cookie'      => ( $allow_cookie ? 'Y' : 'N' ),
            'available_factors' => $available_factors,
            'active_factor'     => '',
            'email_code'        => '',
            'attempts'          => 0,
            'max_attempts'      => 5,
        ];
        return( $this->cb2fa_prepare_challenge_factor( $challenge, $this->cb2fa_get_primary_factor( $available_factors ) ) );
    }

    protected function cb2fa_profile_notice_key( int $user_id ) : string {
        return( 'cb2fa_profile_notice_' . $user_id );
    }

    protected function cb2fa_set_profile_notice( int $user_id, string $type, string $message ) : void {
        set_transient(
            $this->cb2fa_profile_notice_key( $user_id ),
            ['type' => $type, 'message' => $message],
            300
        );
    }

    protected function cb2fa_get_profile_notice( int $user_id ) {
        $notice = get_transient( $this->cb2fa_profile_notice_key( $user_id ) );
        if ( $notice !== false ) {
            delete_transient( $this->cb2fa_profile_notice_key( $user_id ) );
        }
        return( $notice );
    }
    /**
     * Add link to CB2FA settings in plugin list.
     *
     * @since 1.0.0
     */
    public function cb2fa_settings_link( array $links ) : array {
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . ')' );
        }
        if ( $this->_cb2fa_is_plugin_admin === true ) {
            $our_link = '<a href ="' . esc_url( admin_url( 'admin.php' ) . '?page=' . 'cloudbridge-2fa' ) . '">' .
                esc_html__( 'Settings ', 'cloudbridge-2fa' ) . '</a>';
            array_unshift( $links, $our_link );
            return ( $links );
        }
        // User is not allowed to manage this plugin, deactivate links
        unset( $links['deactivate'] );
        unset( $links['delete'] );
        unset( $links['activate'] );
        return( $links );
    }
    /**
     * Hide ourselves if user has no access to this plugin.
     *
     * @param $plugins
     * @return mixed
     */
    public function cb2fa_hide_plugin( $plugins ) {
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . ')' );
        }
        if ( $this->_cb2fa_is_plugin_admin === false ) {
            unset( $plugins['cloudbridge-2fa/' . basename(__FILE__ )] );
        }
        unset( $_GET );
        return( $plugins );
    }
    /**
     * Display admin alerts.
     *
     * Display various admin alerts like missing configuration options, etc.
     *
     * @since 1.0.0
     */
    public function cb2fa_admin_alert_missing_mbstring() : void {
        echo '<div class="notice notice-error cb2fa-admin-notice"><br/>'.
             '<p>' . esc_html( CB2FA_PLUGINNAME_HUMAN ) . ': ' .
             esc_html__( 'mbstring-extensions are missing, contact server administrator to enable them', 'cloudbridge-2fa' ) .
             '!' .
             '<br/><br/></p>';
        echo '</div>';
    }
    public function cb2fa_admin_alert_missing_openssl() : void {
        echo '<div class="notice notice-error cb2fa-admin-notice"><br/>'.
             '<p>' . esc_html( CB2FA_PLUGINNAME_HUMAN ) . ': ' .
             esc_html__( 'Authenticator app support requires the PHP extension openssl. Contact the server administrator to enable it.', 'cloudbridge-2fa' ) .
             '<br/><br/></p>';
        echo '</div>';
    }
    public function cb2fa_admin_alert_plugin_activated() : void {
        $plugin_settings_url = add_query_arg( 'page', 'cloudbridge-2fa', get_admin_url() . 'admin.php');
        echo '<div class="notice notice-success cb2fa-admin-notice"><br/>'.
            '<p>' . esc_html( CB2FA_PLUGINNAME_HUMAN ) . ': ' .
            esc_html__( 'Plugin activated, please take a moment and go through the', 'cloudbridge-2fa' ) . '&nbsp;' .
            '<a href="' . esc_url( $plugin_settings_url ) . '#general">' .
            esc_html__( 'settings', 'cloudbridge-2fa' ) . '</a>' . '<br/><br/></p>';
        echo '</div>';
    }
    /**
     * Fetch filemtime() of file and return it.
     *
     * Fetch filemtime() of $filename and return it, upon error, plugin version
     * is returned instead. This could possibly simply return plugin_version in
     * production.
     *
     * @param  string $filename The file for which we want filemtime()
     * @return string
     * @since  1.0.0
     */
    protected function cb2fa_resource_mtime( string $filename ) : string {
        $filetime = @ filemtime( $filename );
        if ( $filetime === false ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename(__FILE__) . ' (' . __FUNCTION__ . '): Failed to get mtime for "' . $filename . '"' );
            }
            $filetime = str_replace( '.', '', CB2FA_VERSION );
        }
        return ( $filetime );
    }
    /**
     * Setup admin CSS
     *
     * @since 1.0.0
     */
    public function cb2fa_setup_admin_css() : void {
        wp_enqueue_style( 'cloudbridge-2fa', plugin_dir_url( __FILE__ ) . 'css/cb2fa-admin.css',
                          array(),
                          $this->cb2fa_resource_mtime( dirname(__FILE__) . '/css/cb2fa-admin.css' ), 'all' );
        wp_enqueue_script( 'cloudbridge-2fa-qrcode',
                           plugin_dir_url( __FILE__ ) . 'js/vendor/qrcode-generator.js',
                           array(),
                           $this->cb2fa_resource_mtime( dirname( __FILE__ ) . '/js/vendor/qrcode-generator.js' ),
                           false );
        wp_enqueue_script( 'cloudbridge-2fa',
                           plugin_dir_url( __FILE__ ) . 'js/cb2fa-admin.js',
                           array( 'cloudbridge-2fa-qrcode' ),
                           $this->cb2fa_resource_mtime( dirname( __FILE__ ) . '/js/cb2fa-admin.js' ),
                           false );
    }
    /**
     * Setup public CSS
     *
     * @since 1.0.0
     */
    public function cb2fa_setup_public_css() : void {
        wp_enqueue_style( 'cloudbridge-2fa', plugin_dir_url( __FILE__ ) . 'css/cb2fa-public.css',
                          array(),
                          $this->cb2fa_resource_mtime( dirname(__FILE__).'/css/cb2fa-public.css' ),
                          'all' );
        if ( @ filesize( dirname( __FILE__ ) . '/css/cb2fa-public-custom.css' ) !== false ) {
            // Enqueue custom CSS for front-end if it exists and size >0
            wp_enqueue_style( 'cloudbridge-2fa' . '-Custom', plugin_dir_url( __FILE__ ) . 'css/cb2fa-public-custom.css',
                              array( 'cloudbridge-2fa' ),
                              $this->cb2fa_resource_mtime( dirname( __FILE__ ) . '/css/cb2fa-public-custom.css' ),
                              'all' );
        } elseif ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename(__FILE__) . ' (' . __FUNCTION__ . '): Not loading custom CSS, not found or zero size' );
        }
    }
    /**
     * Generate HTML for inline icons
     *
     * Generate HTML for inline icons. We give them "human aliases" here, and
     * generate the appropriate output based on settings such as if Font Awesome
     * is to be used, etc.
     *
     * @param    string $icon_name The icon's "human" name
     * @param    string $add_class Additional class="" we want to add
     * @param    string $add_title title="" we want to add
     * @return   string
     * @since    1.0.0
     */
    protected function cb2fa_make_icon_html( string $icon_name, string $add_class = '', string $add_title = '' ) : string {
        if ( ! empty( $add_class ) ) {
            $add_class = ' ' . trim( $add_class ) . '"';
        } else {
            $add_class = '"';
        }
        if ( ! empty( $add_title ) ) {
            $add_title = ' title="' . esc_html( trim( $add_title ) ) . '"';
        }
        switch( $icon_name ) {
            case 'errornotice':
                switch( $this->cb2fa_icon_style ) {
                    case CB2FA_ICONSTYLE_FA: $html = '<span class="fas fa-exclamation-triangle' . $add_class . $add_title . '></span>'; break;
                    default: $html = '<span class="dashicons dashicons-flag' . $add_class . $add_title . ' style="font-size:24px;"></span>'; break;
                }
                break;
            case 'appicon':
                switch( $this->cb2fa_icon_style ) {
                    case CB2FA_ICONSTYLE_FA: $html = '<span class="fa-solid fa-user-lock' . $add_class . $add_title . '></span>'; break;
                    default: $html = '<span class="dashicons dashicons-lock' . $add_class . $add_title . ' style="font-size:30px;"></span>'; break;
                }
                break;
            case 'copy':
                switch( $this->cb2fa_icon_style ) {
                    case CB2FA_ICONSTYLE_FA: $html = '<span class="far fa-copy' . $add_class . $add_title . ' style="vertical-align:middle;"></span>'; break;
                    default: $html = '<span class="dashicons dashicons-admin-page' . $add_class . $add_title . ' style="vertical-align:middle;"></span>'; break;
                }
                break;
            case 'greencheck':
                switch( $this->cb2fa_icon_style ) {
                    case CB2FA_ICONSTYLE_FA: $html = '<span class="fas fa-check' . $add_class . $add_title . ' style="font-size:14px;margin-left:4px;vertical-align:middle;color:green;"></span>'; break;
                    default: $html = '<span class="dashicons dashicons-yes' . $add_class . $add_title . ' style="font-size:20px;vertical-align:middle;color:green;"></span>'; break;
                }
                break;
             default:
                $html = '';
                break;
        }
        return( $html );
    }
    /**
     * Setup WordPress admin menu.
     *
     * Create menu entry for WordPress, only if 'administrator' role.
     *
     * @since  1.0.0
     */
    public function cb2fa_menu() : void {
        if ( ! $this->cb2fa_is_plugin_admin() )  {
            return;
        }
        // Add our menu entry (stand-alone menu)
        add_menu_page( esc_html( CB2FA_PLUGINNAME_HUMAN ),
                       esc_html( CB2FA_PLUGINNAME_HUMAN ),
                       'manage_options',
                       'cloudbridge-2fa',
                       [ $this, 'cb2fa_admin_page' ],
                       'dashicons-lock'
                       // $position
                       //
                     );
        // The first sub-menu page is a "duplicate" of the parent, because ...
        add_submenu_page ( 'cloudbridge-2fa',
                           esc_html( CB2FA_PLUGINNAME_HUMAN ),
                           esc_html__( 'Settings', 'cloudbridge-2fa' ),
                           'manage_options',
                           'cloudbridge-2fa',
                           [ $this, 'cb2fa_admin_page'] );
        // Add actual sub-menu items
        add_submenu_page ( 'cloudbridge-2fa',
                           esc_html( CB2FA_PLUGINNAME_HUMAN ) . ' - ' . esc_html__( 'Export various data', 'cloudbridge-2fa' ),
                           esc_html__( 'Export', 'cloudbridge-2fa' ),
                           'manage_options',
                           'cloudbridge-2fa'. '-export',
                           [ $this, 'cb2fa_admin_export'] );
        add_submenu_page ( 'cloudbridge-2fa',
                           esc_html( CB2FA_PLUGINNAME_HUMAN ) . ' - ' . esc_html__( 'Import external data', 'cloudbridge-2fa' ),
                           esc_html__( 'Import', 'cloudbridge-2fa' ),
                           'manage_options',
                           'cloudbridge-2fa'. '-import',
                           [ $this, 'cb2fa_admin_import'] );
    }
    /**
     * Fetch WordPress roles.
     *
     * Fetch WordPress roles with WP names and human names, if possible. One could
     * argue that we can just fetch a list of role names from WP, but we may miss
     * roles with no names ... or not? :-)
     *
     * @return array List of roles and their human names
     * @since 1.0.0
     */
    protected function cb2fa_get_wp_roles() : array {
        if ( $this->cb2fa_wp_roles !== null ) {
            return( $this->cb2fa_wp_roles );
        }
        $wp_roles = wp_roles();
        if ( is_object( $wp_roles ) ) {
            // not sure why WP_Roles::get_roles_data() returns false
            // $roles = $wp_roles->get_roles_data();
            $roles = array_keys( $wp_roles->roles );
            $role_names = $role_names_en = $wp_roles->get_names();

        } else {
            $roles = false;
            $role_names = $role_names_en = array();
        }
        $return_roles = array();
        if ( is_array( $roles ) ) {
            foreach( $roles as $role_k => $role_v ) {
                if ( ! empty( $role_names_en[$role_v] ) ) {
                    $return_roles_en[$role_v] = $role_names_en[$role_v];
                } else {
                    $return_roles_en[$role_v] = __( 'Unknown role', 'cloudbridge-2fa' ) . ' (' . $role_v . ')';
                }
                if ( ! empty( $role_names[$role_v] ) ) {
                    $return_roles[$role_v] = translate_user_role( $role_names[$role_v] );
                } else {
                    $return_roles[$role_v] = __( 'Unknown role', 'cloudbridge-2fa' ) . ' (' . $role_v . ')';
                }
            }
        } else {
            error_log( '[CB2FA] ' . basename(__FILE__) . ' (' . __FUNCTION__ . '): wp_roles() returned empty' );
        }
        $this->cb2fa_wp_roles = $return_roles;
        $this->cb2fa_wp_roles_enus = $return_roles_en;
        return( $return_roles );
    }
    /**
     * Determine if allcaps array contains our "admin" values.
     *
     * @param $caps
     * @return bool
     * @since 1.0.0
     */
    private function cb2fa_has_admin_roles( $caps ) : bool {
        if ( is_array( $caps ) ) {
            foreach( $caps as $k => $v ) {
                if ( in_array( $k, self::$cb2fa_admin_caps ) ) {
                    return( true );
                }
            }
        }
        return( false );
    }
    /**
     * Fetch list of all "admin" users from WordPress.
     *
     * @return array
     * @since 1.0.0
     */
    private function cb2fa_get_wordpress_admin_users() : array {
        if ( $this->cb2fa_wordpress_admin_users == null ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): Getting list of WordPress users' );
            }
            $this->cb2fa_wordpress_admin_users = $this->cb2fa_get_all_users();
        } else {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): Using cached list of WordPress users' );
            }
        }
        $admin_users = array();
        if ( is_array( $this->cb2fa_wordpress_admin_users ) ) {
            foreach ( $this->cb2fa_wordpress_admin_users as $wp_user ) {
                if ( ( is_array( $wp_user->caps ) && array_key_exists( 'administrator', $wp_user->caps ) )
                    ||
                    ( is_array( $wp_user->roles ) && in_array( 'administrator', $wp_user->roles ) )
                    ||
                    ( is_array( $wp_user->allcaps ) && $this->cb2fa_has_admin_roles( $wp_user->allcaps ) ) ) {
                    if ( ! empty( $wp_user->data->display_name ) ) {
                        $user_display = $wp_user->data->display_name;
                    } elseif ( ! empty( $wp_user->data->user_nicename ) ) {
                        $user_display = $wp_user->data->user_nicename;
                    } elseif ( ! empty( $wp_user->data->user_email ) ) {
                        $user_display = $wp_user->data->user_email;
                    } else {
                        $user_display = $wp_user->data->user_login;
                    }
                    $admin_users[$wp_user->data->user_login] = $user_display;
                }// administrator
            }// foreach
        }
        return( $admin_users );
    }
    private function cb2fa_is_plugin_admin() : bool {
        if ( $this->_cb2fa_is_plugin_admin === true ) {
            return( true );
        }
        if ( ! is_admin( ) ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): is_admin() == false' );
            }
            return( false );
        }
        if ( function_exists( '\is_user_logged_in' ) && ! \is_user_logged_in() ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): is_user_logged_in() does not exist or returned false' );
            }
            return( false );
        }
        if ( ! function_exists( '\current_user_can' ) || ! function_exists( '\wp_get_current_user' ) || ! \current_user_can( 'administrator' ) ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): current_user_can() | wp_get_current_user() does not exist, or user is not administrator' );
            }
            return( false );
        }
        // Have we been here before?
        if ( $this->_cb2fa_is_plugin_admin === false ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): _is_plugin_admin == false' );
            }
            return( false );
        }
        // Check if we have any restrictions in place
        if ( ! is_array( $this->cb2fa_admin_users ) || empty( $this->cb2fa_admin_users ) ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): No specific admins configured' );
            }
            $this->_cb2fa_is_plugin_admin =  true;
            return( true );
        }
        // First checks passed, check for username restrictions
        $admin_users = $this->cb2fa_get_wordpress_admin_users();
        $current_user = wp_get_current_user();
        if ( empty( $current_user->data->user_login ) ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( basename(__FILE__) . ' (' . __FUNCTION__ . ') No username for current user' );
            }
            return( false );
        }
        if ( ! in_array( $current_user->data->user_login, $this->cb2fa_admin_users ) ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( basename(__FILE__) . ' (' . __FUNCTION__ . ') "' . $current_user->data->user_login . '" is not allowed to manage CB2FA' );
                error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): Configured admin users ' . print_r( $this->cb2fa_admin_users, true ) );
            }
            $this->_cb2fa_is_plugin_admin = false;
            return( false );
        }
        $this->_cb2fa_is_plugin_admin =  true;
        return( true );
    }
    /**
     * Setup WordPress admin options page.
     *
     * Create menu entry for WordPress, only if 'administrator' role.
     *
     * @since  1.0.0
     */
    public function cb2fa_admin_page() : void {
        if ( ! $this->cb2fa_is_plugin_admin() )  {
            return;
        }
        $bypass_users = $this->cb2fa_get_bypass_users();
        if ( empty( $this->cb2fa_form_tab ) ) {
            $this->cb2fa_form_tab = 'general';
        }
        $html = '';
        // Output configuration options$action
        $tab_header = '<div class="wrap">';
            $tab_header .= '<h1>' . $this->cb2fa_make_icon_html( 'appicon' ) . '&nbsp;&nbsp;' . esc_html( CB2FA_PLUGINNAME_HUMAN ) . '</h1>';
            $tab_header .= '<p>' . esc_html__( 'These settings allow general configuration of Cloudbridge 2FA', 'cloudbridge-2fa' ) . '</p>';
            $tab_header .= $this->cb2fa_get_bypass_warning_html( $bypass_users );
            $tab_header .= '<nav class="nav-tab-wrapper">';
            $tab_header .= '<a data-toggle="cb2fa-general" href="#general" class="cb2fa-tab nav-tab">' . esc_html__( 'General', 'cloudbridge-2fa' ) . '</a>';
            $tab_header .= '<a data-toggle="cb2fa-email-otp" href="#email-otp" class="cb2fa-tab nav-tab">' . esc_html__( 'E-mail OTP', 'cloudbridge-2fa' ) . '</a>';
            $tab_header .= '<a data-toggle="cb2fa-roles" href="#roles" class="cb2fa-tab nav-tab">' . esc_html__( 'Roles', 'cloudbridge-2fa' ) . '</a>';
            $tab_header .= '<a data-toggle="cb2fa-access" href="#access" class="cb2fa-tab nav-tab">' . esc_html__( 'Access', 'cloudbridge-2fa' ) . '</a>';
            $tab_header .= '<a data-toggle="cb2fa-bypass-2fa" href="#bypass-2fa" class="cb2fa-tab nav-tab">' . esc_html__( 'Bypass 2FA', 'cloudbridge-2fa' ) . '</a>';
            $tab_header .= '<a data-toggle="cb2fa-about" href="#about" class="cb2fa-tab nav-tab">' . esc_html__( 'About', 'cloudbridge-2fa' ) . '</a>';
            $tab_header .= '</nav>';

            $html .= '<div class="tab-content">';
            $html .= '<div class="cb2fa-config-header">';
            ob_start();
            settings_errors( 'cloudbridge-2fa' );
            $html .= ob_get_contents();
            ob_end_clean();
            $html .= '<form method="post" action="options.php">';
            ob_start();
            settings_fields( 'cloudbridge-2fa' );
            $html .= ob_get_contents();
            ob_end_clean();
            $html .= '<div id="cb2fa-general" class="cb2fa-tab-content cb2fa-is-hidden">';
            ob_start();
            echo '<div class="cb2fa-settings-group">';
            echo '<h2>' . esc_html__( 'Authenticator apps', 'cloudbridge-2fa' ) . '</h2>';
            echo '<p class="cb2fa-section-intro">' . esc_html__( 'Allow standards-based TOTP authenticator apps for this site. Each user enables and manages their own authenticator app from their WordPress profile page.', 'cloudbridge-2fa' ) . '</p>';
            echo '<table class="form-table" role="presentation">';
                 do_settings_fields( 'cloudbridge-2fa', 'cb2fa-settings-general' );
            echo '</table>';
            echo '</div>';
            echo '<div class="cb2fa-settings-group">';
            echo '<h2>' . esc_html__( 'Login screen', 'cloudbridge-2fa' ) . '</h2>';
            echo '<p class="cb2fa-section-intro">' . esc_html__( 'Configure helper text shown on the code entry screen after the user has passed their username and password check.', 'cloudbridge-2fa' ) . '</p>';
            echo '<table class="form-table" role="presentation">';
                 do_settings_fields( 'cloudbridge-2fa', 'cb2fa-settings-login' );
            echo '</table>';
            echo '</div>';
            echo '<div class="cb2fa-settings-group">';
            echo '<h2>' . esc_html__( 'Browser trust', 'cloudbridge-2fa' ) . '</h2>';
            echo '<p class="cb2fa-section-intro">' . esc_html__( 'Configure how long the optional remember-this-browser cookie should remain valid when a role is allowed to use it.', 'cloudbridge-2fa' ) . '</p>';
            echo '<table class="form-table" role="presentation">';
                 do_settings_fields( 'cloudbridge-2fa', 'cb2fa-settings-browser' );
            echo '</table>';
            echo '</div>';
            echo '<div class="cb2fa-settings-group">';
            echo '<h2>' . esc_html__( 'Maintenance', 'cloudbridge-2fa' ) . '</h2>';
            echo '<table class="form-table" role="presentation">';
                 do_settings_fields( 'cloudbridge-2fa', 'cb2fa-settings-maintenance' );
            echo '</table>';
            submit_button( null, 'primary', 'submit', false );
            echo '</div>';
            $html .= ob_get_contents();
            ob_end_clean();
            $html .= '</div>';//cb2fa-general
            $html .= '<div id="cb2fa-email-otp" class="cb2fa-tab-content cb2fa-is-hidden">';
            ob_start();
            echo '<div class="cb2fa-settings-group">';
            echo '<h2>' . esc_html__( 'E-mail OTP', 'cloudbridge-2fa' ) . '</h2>';
            echo '<p class="cb2fa-section-intro">' . esc_html__( 'Configure the e-mail-based one-time code flow, including message behavior and helper text shown during login.', 'cloudbridge-2fa' ) . '</p>';
            echo '<table class="form-table" role="presentation">';
                 do_settings_fields( 'cloudbridge-2fa', 'cb2fa-settings-email' );
            echo '</table>';
            submit_button( null, 'primary', 'submit', false );
            echo '</div>';
            $html .= ob_get_contents();
            ob_end_clean();
            $html .= '</div>';//cb2fa-email-otp
            $html .= '<div id="cb2fa-roles" class="cb2fa-tab-content cb2fa-is-hidden">';
            ob_start();
            $html .= '<p>'  .
                     esc_html__( 'This page allows you to configure how 2FA should be enforced for different WordPress user roles', 'cloudbridge-2fa' ) . '. ' .
                     esc_html__( 'It is recommended that you enable 2FA at least for all roles with elevated privileges', 'cloudbridge-2fa' ) . '.' .
                     '</p>';
            if ( ! $this->cb2fa_active_roles() ) {
                $html .= '<p class="cb2fa-warning">' .
                         esc_html__( 'No roles currently have 2FA enabled', 'cloudbridge-2fa' ) . '.' .
                         '</p>';
            }
            $available_roles = $this->cb2fa_get_wp_roles();
            if ( ! is_array( $available_roles ) ) {
                $html .= '<div class="cb2fa-error">' .
                         esc_html__( 'Unable to fetch WordPress user roles', 'cloudbridge-2fa' ) .
                         '</div>';
            } else {
                // Make sure we don't have unwanted roles
                if ( ! empty( $this->cb2fa_roles_configuration ) ) {
                    $cleaned_roles = array();
                    foreach( $this->cb2fa_roles_configuration as $k => $v ) {
                        if ( array_key_exists( $v, $available_roles ) ) {
                            $cleaned_roles[] = $v;
                        }
                    }
                    $this->cb2fa_roles_configuration = $cleaned_roles;
                }
                if ( ! empty( $this->cb2fa_cookies_configuration ) ) {
                    $cleaned_roles = array();
                    foreach( $this->cb2fa_cookies_configuration as $k => $v ) {
                        if ( array_key_exists( $v, $available_roles ) ) {
                            $cleaned_roles[] = $v;
                        }
                    }
                    $this->cb2fa_cookies_configuration = $cleaned_roles;
                }
            }
            $html .= '<div class="rolegrid">';
            $html .= '<input type="hidden" name="cloudbridge2fa-roles-config[]" value="" />';
            $html .= '<input type="hidden" name="cloudbridge2fa-cookies-config[]" value="" />';
            $html .= '<div class="rolegridrow">';
            $html .= '<div class="rolegridheader">' .
                          esc_html__( 'Role', 'default' ) .
                     '</div><div class="rolegridheader">' .
                          esc_html__( '2FA enabled', 'cloudbridge-2fa' ) .
                     '</div><div class="rolegridheader">' .
                          esc_html__( 'Allow cookie', 'cloudbridge-2fa' ) .
                     '</div></div>';
            foreach( $available_roles as $k => $v ) {
                $html .= '<div class="rolegridrow">' .
                         '<div class="rolegridcol">' . ( ! empty( $v ) ? esc_html( $v ) : esc_html( $k ) ) . '</div>' .
                         '<div class="rolegridcol">' .
                             '<input type="checkbox" name="cloudbridge2fa-roles-config[]" id="cloudbridge2fa-roles-config[]" value="' . esc_attr( $k ) . '"' . ( in_array( $k, $this->cb2fa_roles_configuration ) ? ' checked="checked"':'' ) . ' />' .
                         '</div>' .
                         '<div class="rolegridcol">' .
                             '<input type="checkbox" name="cloudbridge2fa-cookies-config[]" id="cloudbridge2fa-cookies-config[]" value="' . esc_attr( $k ) . '"' . ( in_array( $k, $this->cb2fa_cookies_configuration ) ? ' checked="checked"':'' ) . ' />' .
                         '</div>' .
                         '</div>';
            }
            $html .= '</div>';
            $html .= '<div class="cb2fa-tab-submit">';
            ob_start();
            submit_button( null, 'primary', 'submit', false );
            $html .= ob_get_contents();
            ob_end_clean();
            $html .= '</div>';
            $html .= '</div>';// cb2fa-roles
            $html .= '<div id="cb2fa-access" class="cb2fa-tab-content cb2fa-is-hidden">';
            $admin_users = $this->cb2fa_get_wordpress_admin_users();
            $current_user = wp_get_current_user();
            $current_user_display = '';
            if ( ! empty( $current_user->data ) ) {
                if ( ! empty( $current_user->data->display_name ) ) {
                    $current_user_display = $current_user->data->display_name;
                } elseif ( ! empty( $current_user->data->user_nicename ) ) {
                    $current_user_display = $current_user->data->user_nicename;
                } elseif ( ! empty( $current_user->data->user_email ) ) {
                    $current_user_display = $current_user->data->user_email;
                } else {
                    $current_user_display = $current_user->data->user_login;
                }
            }
            if ( empty( $admin_users ) ) {
                $html .= '<div class="cb2fa-error">' .
                         esc_html__( 'Unable to locate any users with "admininistrator" permissions', 'cloudbridge-2fa' ) . '!' .
                         '</div>';
            } else {
                if ( empty( $this->cb2fa_admin_users ) ) {
                    $html .= '<p class="cb2fa-warning">' .
                             esc_html__( 'All users with "administrator" permissions can currently manage this plugin', 'cloudbridge-2fa' ) . '.' .
                             '</p>';
                }
                if ( empty( $current_user ) ) {
                    $html .= '<p class="cb2fa-warning">' .
                             esc_html__( 'Unable to determine current user', 'cloudbridge-2fa' ) . '.' .
                             '</p>';
                } else {
                    $html .= '<p>' .
                             esc_html__( 'Current user is', 'cloudbridge-2fa' ) . ' <strong>' .
                             ( empty( $current_user_display ) ? esc_html__( 'Unknown', 'cloudbridge-2fa' ) : esc_html( $current_user_display ) ) .
                             '</strong></p>';
                }
                $html .= '<div class="rolegrid">';
                $html .= '<input type="hidden" name="cloudbridge2fa-admin-users[]" value="" />';
                $html .= '<div class="admingridrow">';
                $html .= '<div class="admingridheader">' .
                         esc_html__( 'User', 'cloudbridge-2fa' ) .
                         '</div><div class="admingridheader">' .
                         esc_html__( 'Manage plugin', 'cloudbridge-2fa' ) .
                         '</div></div>';
                $found_current = false;
                foreach( $admin_users as $k => $v ) {
                    $class = 'admingridcol';
                    if ( ! $found_current && $k == $current_user->data->user_login ) {
                        $found_current = true;
                        if ( in_array( $k, $this->cb2fa_admin_users ) ) {
                            $class .= ' admingridcol-current-active';
                        } else {
                            $class .= ' admingridcol-current';
                        }
                    }
                    $html .= '<div class="admingridrow">' .
                             '<div class="' . $class . '">' . ( ! empty( $v ) ? esc_html( $v ) : esc_html( $k ) ) . '</div>' .
                             '<div class="' . $class . ' cb2fa-center">' .
                                 '<input type="checkbox" name="cloudbridge2fa-admin-users[]" id="cloudbridge2fa-admin-users[]" value="' . esc_attr( $k ) . '"' . ( in_array( $k, $this->cb2fa_admin_users ) ? ' checked="checked"':'' ) . ' />' .
                             '</div>' .
                             '</div>';
                }
                $html .= '</div>';
            }
            $html .= '<div class="cb2fa-tab-submit">';
            ob_start();
            submit_button( null, 'primary', 'submit', false );
            $html .= ob_get_contents();
            ob_end_clean();
            $html .= '</div>';
            $html .= '</div>';// cb2fa-access
            $html .= '</form>';
            $html .= '<div id="cb2fa-bypass-2fa" class="cb2fa-tab-content cb2fa-is-hidden">';
            $html .= '<div class="cb2fa-settings-group">';
            $html .= '<h2>' . esc_html__( 'Bypass 2FA', 'cloudbridge-2fa' ) . '</h2>';
            $html .= '<p class="cb2fa-section-intro">' . esc_html__( 'Emergency bypass should only be enabled for accounts that temporarily cannot complete the normal Cloudbridge 2FA login flow. Review and remove bypasses again as soon as they are no longer needed.', 'cloudbridge-2fa' ) . '</p>';
            $html .= '<form method="post" action="' . esc_url( admin_url( 'admin.php?page=cloudbridge-2fa#bypass-2fa' ) ) . '">';
            ob_start();
            wp_nonce_field( 'cb2fa-save-bypass', 'cb2fa_bypass_nonce' );
            $html .= ob_get_contents();
            ob_end_clean();
            $html .= '<input type="hidden" name="cb2fa_bypass_form" value="1" />';
            $html .= '<table class="widefat striped cb2fa-bypass-table" role="presentation">';
            $html .= '<thead><tr>';
            $html .= '<th>' . esc_html__( 'User', 'cloudbridge-2fa' ) . '</th>';
            $html .= '<th>' . esc_html__( 'Role', 'cloudbridge-2fa' ) . '</th>';
            $html .= '<th class="cb2fa-center">' . esc_html__( 'Bypass 2FA', 'cloudbridge-2fa' ) . '</th>';
            $html .= '</tr></thead><tbody>';
            foreach ( $this->cb2fa_get_all_users() as $cb2fa_user ) {
                if ( ! $cb2fa_user instanceof \WP_User ) {
                    continue;
                }
                $html .= '<tr>';
                $html .= '<td>';
                $html .= '<strong>' . esc_html( empty( $cb2fa_user->display_name ) ? $cb2fa_user->user_login : $cb2fa_user->display_name ) . '</strong>';
                $html .= '<div><code>' . esc_html( $cb2fa_user->user_login ) . '</code></div>';
                if ( ! empty( $cb2fa_user->user_email ) ) {
                    $html .= '<div class="description">' . esc_html( $cb2fa_user->user_email ) . '</div>';
                }
                $html .= '</td>';
                $html .= '<td>' . esc_html( $this->cb2fa_get_translated_role_list( $cb2fa_user ) ) . '</td>';
                $html .= '<td class="cb2fa-center">';
                $html .= '<label>';
                $html .= '<input type="checkbox" name="cb2fa_bypass_users[]" value="' . esc_attr( (string)$cb2fa_user->ID ) . '" ' . checked( $this->cb2fa_user_has_bypass( (int)$cb2fa_user->ID ), true, false ) . '/> ';
                $html .= '<span class="screen-reader-text">' . esc_html( sprintf( __( 'Bypass 2FA for %s', 'cloudbridge-2fa' ), $cb2fa_user->user_login ) ) . '</span>';
                $html .= '</label>';
                $html .= '</td>';
                $html .= '</tr>';
            }
            $html .= '</tbody></table>';
            $html .= '<div class="cb2fa-tab-submit">';
            ob_start();
            submit_button( null, 'primary', 'submit', false );
            $html .= ob_get_contents();
            ob_end_clean();
            $html .= '</div>';
            $html .= '</form>';
            $html .= '</div>';
            $html .= '</div>';// cb2fa-bypass-2fa
            $html .= '<div id="cb2fa-about" class="cb2fa-tab-content cb2fa-is-hidden">';
            $html .= '<p>'.
                         '<p>' . esc_html__( 'Thank you for installing', 'cloudbridge-2fa' ) .' ' . esc_html( CB2FA_PLUGINNAME_HUMAN ) . '!' . ' '.
                         esc_html__( 'This WordPress plugin provides two-factor authentication for WordPress, with support for e-mail OTP and authenticator app TOTP', 'cloudbridge-2fa' ) . '.' .
                         '</p>' .
                      '<p>'  . '<img class="cb2fa-wps-logo" alt="" src="' . plugin_dir_url( __FILE__ ) . 'img/webbplatsen_logo.png" />' .
                          esc_html__( 'Commercial support and customizations for this plugin is available from', 'cloudbridge-2fa' ) .
                          ' <a class="cb2fa-ext-link" href="https://webbplatsen.se" target="_blank">WebbPlatsen i Sverige AB</a> '.
                          esc_html__('in Stockholm, Sweden. We speak Swedish and English', 'cloudbridge-2fa' ) . ' :-)' .
                          '<br/><br/>' .
                          esc_html__( 'The plugin is written by Joaquim Homrighausen and sponsored by WebbPlatsen i Sverige AB.', 'cloudbridge-2fa' ) .
                          '<br/><br/>' .
                          esc_html__( 'If you find this plugin useful, the author is happy to receive a donation, good review, or just a kind word.', 'cloudbridge-2fa' ) . ' ' .
                          esc_html__( 'If there is something you feel to be missing from this plugin, or if you have found a problem with the code or a feature, please do not hesitate to reach out to', 'cloudbridge-2fa' ) .
                                      ' <a class="cb2fa-ext-link" href="mailto:support@webbplatsen.se">support@webbplatsen.se</a>' . ' '.
                          esc_html__( 'There is more documentation available at', 'cloudbridge-2fa' ) . ' ' .
                                      '<a class="cb2fa-ext-link" target="_blank" href="https://code.webbplatsen.net/documentation/cloudbridge-2fa/">'.
                                      'code.webbplatsen.net/documentation/cloudbridge-2fa/</a>' .
                      '</p>'.
                      '<p style="margin-top:20px;">' .
                          '<h3>' . esc_html__( 'Other plugins', 'cloudbridge-2fa' ) . '</h3>' .
                          '<p class="cb2fa-row">' .
                              '<a href="https://wordpress.org/plugins/fail2wp" target="_blank" class="cb2fa-ext-link">Fail2WP</a>' .
                              '<br/>' .
                              esc_html__( 'Security plugin that provides integration with fail2ban and many other security features for WordPress', 'cloudbridge-2fa' ) . '.' .
                          '</p>' .
                          '<p class="cb2fa-row">' .
                              '<a href="https://wordpress.org/plugins/cloudbridge-mattermost" target="_blank" class="cb2fa-ext-link">Cloudbridge Mattermost</a>' .
                              '<br/>' .
                              esc_html__( 'Plugin that provides integration with Mattermost, including notifications and OAuth2 authentication', 'cloudbridge-2fa' ) . '.' .
                          '</p>' .
                          '<p class="cb2fa-row">' .
                              '<a href="https://wordpress.org/plugins/easymap" target="_blank" class="cb2fa-ext-link">EasyMap</a>' .
                              '<br/>' .
                              esc_html__( 'Plugin that provides uncomplicated map functionality', 'cloudbridge-2fa' ) . '.' .
                         '</p>' .
                      '</p>' .
                      '</div>';
            $html .= '</div>';// cb2fa-about
            $html .= '</div>'; // cb2fa-config-header
            $html .= '</div>'; // tab-content
        $html .= '</div>'; // wrap
        //
        echo $tab_header . $html;
    }
    /**
     * Display settings.
     *
     * @since  1.0.0
     */
    public function cb2fa_settings() : void {
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . ')' );
        }
        // Add 'Settings' link in plugin list
        add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), [$this, 'cb2fa_settings_link'] );
        // Only do settings and only allow deactivate/delete if we're an admin of sorts
        if ( ! $this->cb2fa_is_plugin_admin() )  {
            add_filter( 'all_plugins', [$this, 'cb2fa_hide_plugin'] );
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): Skipping settings' );
            }
            return;
        }
        $this->cb2fa_handle_bypass_form();
        // Settings
        add_settings_section( 'cb2fa-settings-general', '', false, 'cloudbridge-2fa' );
            add_settings_field( 'cloudbridge2fa-totp-enabled', esc_html__( 'Allow authenticator apps', 'cloudbridge-2fa' ), [$this, 'cb2fa_setting_factor_totp'], 'cloudbridge-2fa', 'cb2fa-settings-general', ['label_for' => 'cloudbridge2fa-totp-enabled'] );
        add_settings_section( 'cb2fa-settings-login', '', false, 'cloudbridge-2fa' );
            add_settings_field( 'cloudbridge2fa-code-input-text-addon', esc_html__( 'OTP code entry text', 'cloudbridge-2fa' ), [$this, 'cb2fa_code_input_text_addon'], 'cloudbridge-2fa', 'cb2fa-settings-login', ['label_for' => 'cloudbridge2fa-code-input-text-addon'] );
        add_settings_section( 'cb2fa-settings-browser', '', false, 'cloudbridge-2fa' );
            add_settings_field( 'cloudbridge2fa-cookie-lifetime', esc_html__( 'Cookie lifetime', 'cloudbridge-2fa' ), [$this, 'cb2fa_setting_cookie_lifetime'], 'cloudbridge-2fa', 'cb2fa-settings-browser', ['label_for' => 'cloudbridge2fa-cookie-lifetime'] );
        add_settings_section( 'cb2fa-settings-email', '', false, 'cloudbridge-2fa' );
            add_settings_field( 'cloudbridge2fa-email-otp-enabled', esc_html__( 'Allow e-mail OTP', 'cloudbridge-2fa' ), [$this, 'cb2fa_setting_factor_email'], 'cloudbridge-2fa', 'cb2fa-settings-email', ['label_for' => 'cloudbridge2fa-email-otp-enabled'] );
            add_settings_field( 'cloudbridge2fa-code-lifetime', esc_html__( 'OTP code lifetime', 'cloudbridge-2fa' ), [$this, 'cb2fa_setting_code_lifetime'], 'cloudbridge-2fa', 'cb2fa-settings-email', ['label_for' => 'cloudbridge2fa-code-lifetime'] );
            add_settings_field( 'cloudbridge2fa-code-email-subject', esc_html__( 'OTP code in e-mail subject', 'cloudbridge-2fa' ), [$this, 'cb2fa_setting_code_email_subject'], 'cloudbridge-2fa', 'cb2fa-settings-email', ['label_for' => 'cloudbridge2fa-code-email-subject'] );
            add_settings_field( 'cloudbridge2fa-code-email-text-addon', esc_html__( 'OTP code e-mail text', 'cloudbridge-2fa' ), [$this, 'cb2fa_code_email_text_addon'], 'cloudbridge-2fa', 'cb2fa-settings-email', ['label_for' => 'cloudbridge2fa-code-email-text-addon'] );
        add_settings_section( 'cb2fa-settings-maintenance', '', false, 'cloudbridge-2fa' );
            add_settings_field( 'cloudbridge2fa-settings-remove', esc_html__( 'Remove settings', 'cloudbridge-2fa' ), [$this, 'cb2fa_setting_remove'], 'cloudbridge-2fa', 'cb2fa-settings-maintenance', ['label_for' => 'cloudbridge2fa-settings-remove'] );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-code-lifetime', ['type' => 'number', 'sanitize_callback' => [$this, 'cb2fa_setting_sanitize_code_lifetime']] );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-email-otp-enabled', ['type' => 'boolean', 'sanitize_callback' => [$this, 'cb2fa_setting_sanitize_checkbox']] );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-totp-enabled', ['type' => 'boolean', 'sanitize_callback' => [$this, 'cb2fa_setting_sanitize_checkbox']] );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-code-email-subject', ['type' => 'boolean', 'sanitize_callback' => [$this, 'cb2fa_setting_sanitize_checkbox']] );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-roles-config', ['type' => 'array', 'sanitize_callback' => [$this, 'cb2fa_setting_sanitize_roles']] );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-admin-users', ['type' => 'array', 'sanitize_callback' => [$this, 'cb2fa_setting_sanitize_admin_users']] );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-cookies-config', ['type' => 'array', 'sanitize_callback' => [$this, 'cb2fa_setting_sanitize_cookies']] );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-code-input-text-addon', ['type' => 'string', 'sanitize_callback' => [$this, 'cb2fa_setting_sanitize_code_input_text_addon']] );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-code-email-text-addon', ['type' => 'string', 'sanitize_callback' => [$this, 'cb2fa_setting_sanitize_textarea_setting']] );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-cookie-lifetime', ['type' => 'number', 'sanitize_callback' => [$this, 'cb2fa_setting_sanitize_cookie_lifetime']] );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-settings-remove', ['type' => 'boolean', 'sanitize_callback' => [$this, 'cb2fa_setting_sanitize_checkbox']] );
    }
    /**
     * Sanitize input.
     *
     * Basic cleaning/checking of user input. Not much to do really.
     *
     * @since  1.0.0
     */
    public function cb2fa_setting_sanitize_code_lifetime( $input ) {
        if ( ! $this->cb2fa_is_plugin_admin() && ! $this->cb2fa_doing_import )  {
            return;
        }
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . ')' );
        }
        return( (int)$this->Utility->x_substr( sanitize_text_field( trim( $input ) ), 0, 3 ) );
    }
    public function cb2fa_setting_sanitize_roles( $input ) {
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . ')' );
        }
        if ( ! $this->cb2fa_is_plugin_admin() && ! $this->cb2fa_doing_import )  {
            return;
        }
        if ( $this->cb2fa_doing_import ) {
            $input = json_decode( $input, true, 2 );
        }
        $available_roles = $this->cb2fa_get_wp_roles();
        $return_val = array();
        if ( is_array( $input ) ) {
            $roles_array = array_keys( $available_roles );
            foreach( $input as $role ) {
                if ( in_array( $role, $roles_array ) ) {
                    // We know $role is clean since it matches
                    $return_val[] = $role;
                }
            }
        }
        return( wp_json_encode( $return_val ) );
    }
    public function cb2fa_setting_sanitize_admin_users( $input ) {
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . ')' );
        }
        if ( ! $this->cb2fa_is_plugin_admin() && ! $this->cb2fa_doing_import )  {
            return;
        }
        if ( $this->cb2fa_doing_import ) {
            $input = json_decode( $input, true, 2 );
        }
        $admin_users = $this->cb2fa_get_wordpress_admin_users();
        $return_val = array();
        if ( is_array( $input ) ) {
            foreach( $input as $user ) {
                if ( ! empty( $admin_users[$user] ) ) {
                    $return_val[] = $user;
                }
            }
        }
        return( wp_json_encode( $return_val ) );
    }
    public function cb2fa_setting_sanitize_cookies( $input ) {
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . ')' );
        }
        if ( ! $this->cb2fa_is_plugin_admin() && ! $this->cb2fa_doing_import )  {
            return;
        }
        if ( $this->cb2fa_doing_import ) {
            $input = json_decode( $input, true, 2 );
        }
        $available_roles = $this->cb2fa_get_wp_roles();
        $return_val = array();
        if ( is_array( $input ) ) {
            $roles_array = array_keys( $available_roles );
            foreach( $input as $role ) {
                if ( in_array( $role, $roles_array ) ) {
                    // We know $role is clean since it matches
                    $return_val[] = $role;
                }
            }
        }
        return( wp_json_encode( $return_val ) );
    }
    public function cb2fa_setting_sanitize_code_input_text_addon( $input ) {
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . ')' );
        }
        if ( ! $this->cb2fa_is_plugin_admin() && ! $this->cb2fa_doing_import )  {
            return;
        }
        return( $this->Utility->x_substr( sanitize_text_field( trim( $input ) ), 0, 200 ) );
    }
    public function cb2fa_setting_sanitize_textarea_setting( $input ) {
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . ')' );
        }
        if ( ! $this->cb2fa_is_plugin_admin() && ! $this->cb2fa_doing_import )  {
            return;
        }
        return( sanitize_textarea_field( $input ) );
    }
    public function cb2fa_setting_sanitize_cookie_lifetime( $input ) {
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . ')' );
        }
        if ( ! $this->cb2fa_is_plugin_admin() && ! $this->cb2fa_doing_import )  {
            return;
        }
        $cookie_lifetime = (int)$this->Utility->x_substr( sanitize_text_field( trim( $input ) ), 0, 3 );
        if ( $cookie_lifetime < 0 ) {
            $cookie_lifetime = 0;
        } elseif ( $cookie_lifetime > 365 ) {
            $cookie_lifetime = 365;
        }
        return( $cookie_lifetime );
    }
    /**
     * Output input fields.
     *
     * @since 1.0.0
     */
    public function cb2fa_setting_factor_email() : void {
        echo '<div class="cb2fa-setting-option">';
        echo '<label for="cloudbridge2fa-email-otp-enabled">';
        echo '<input type="hidden" name="cloudbridge2fa-email-otp-enabled" value="0" />';
        echo '<input type="checkbox" name="cloudbridge2fa-email-otp-enabled" id="cloudbridge2fa-email-otp-enabled" value="1" ' . checked( $this->cb2fa_email_otp_enabled, 1, false ) . '/>';
        echo esc_html__( 'Send a one-time code by e-mail when e-mail is available for the user', 'cloudbridge-2fa' ) . '</label> ';
        echo '</div>';
        echo '<p class="description">' . esc_html__( 'Recommended to keep enabled as a fallback while authenticator apps are being rolled out.', 'cloudbridge-2fa' ) . '</p>';
    }
    public function cb2fa_setting_factor_totp() : void {
        echo '<div class="cb2fa-setting-option">';
        echo '<label for="cloudbridge2fa-totp-enabled">';
        echo '<input type="hidden" name="cloudbridge2fa-totp-enabled" value="0" />';
        echo '<input type="checkbox" name="cloudbridge2fa-totp-enabled" id="cloudbridge2fa-totp-enabled" value="1" ' . checked( $this->cb2fa_totp_enabled, 1, false ) . '/>';
        echo esc_html__( 'Allow users to set up an authenticator app on their WordPress profile page', 'cloudbridge-2fa' ) . '</label> ';
        echo '</div>';
        echo '<p class="description">' . esc_html__( 'Cloudbridge 2FA currently provisions authenticator apps using a manual setup key and recovery codes.', 'cloudbridge-2fa' ) . '</p>';
    }
    public function cb2fa_setting_code_lifetime() : void {
        echo '<input type="text" size="3" maxlength="2" id="cloudbridge2fa-code-lifetime" name="cloudbridge2fa-code-lifetime" value="' . esc_attr( $this->cb2fa_code_lifetime ). '"';
        echo ' />';
        echo '<p class="description">' . esc_html__( 'Lifetime, in minutes, of the OTP (one time password) code sent to user by e-mail', 'cloudbridge-2fa' ) .
             ' (1-60)' .
             '</p>';
    }
    public function cb2fa_code_input_text_addon() : void {
        echo '<input type="text" size="60" maxlength="200" id="cloudbridge2fa-code-input-text-addon" name="cloudbridge2fa-code-input-text-addon" value="' . esc_attr( $this->cb2fa_code_input_text_addon ). '"';
        echo ' />';
        echo '<p class="description">' . esc_html__( 'Additional text to display on OTP (one time password) code input form', 'cloudbridge-2fa' ) .
             '</p>';
    }
    public function cb2fa_code_email_text_addon() : void {
        echo '<textarea rows="8" cols="30" maxlength="500" id="cloudbridge2fa-code-email-text-addon" name="cloudbridge2fa-code-email-text-addon" class="large-text code" style="max-width:510px;">';
        echo esc_html( $this->cb2fa_code_email_text_addon );
        echo '</textarea>';
        echo '<p class="description">' . esc_html__( 'Additional text to include in OTP (one time password) code e-mail, no HTML', 'cloudbridge-2fa' ) .
             '</p>';
    }
    public function cb2fa_setting_cookie_lifetime() : void {
        echo '<input type="text" size="3" maxlength="3" id="cloudbridge2fa-cookie-lifetime" name="cloudbridge2fa-cookie-lifetime" value="' . esc_attr( $this->cb2fa_cookie_lifetime ). '"';
        echo ' />';
        echo '<p class="description">' . esc_html__( 'Lifetime, in days, of 2FA bypass cookie. 0=Until browser is closed.', 'cloudbridge-2fa' ) .
             ' (0-365)' .
             '</p>';
    }
    public function cb2fa_setting_code_email_subject() : void {
        echo '<div class="cb2fa-setting-option">';
        echo '<label for="cloudbridge2fa-code-email-subject">';
        echo '<input type="hidden" name="cloudbridge2fa-code-email-subject" value="0" />';
        echo '<input type="checkbox" name="cloudbridge2fa-code-email-subject" id="cloudbridge2fa-code-email-subject" value="1" ' . ( checked( $this->cb2fa_code_email_subject, 1, false ) ) . '/>';
        echo esc_html__( 'Include OTP (one time password) in e-mail subject', 'cloudbridge-2fa' ) . '</label> ';
        echo '</div>';
    }
    public function cb2fa_setting_remove() : void {
        echo '<div class="cb2fa-setting-option">';
        echo '<label for="cloudbridge2fa-settings-remove">';
        echo '<input type="hidden" name="cloudbridge2fa-settings-remove" value="0" />';
        echo '<input type="checkbox" name="cloudbridge2fa-settings-remove" id="cloudbridge2fa-settings-remove" value="1" ' . ( checked( $this->cb2fa_settings_remove, 1, false ) ) . '/>';
        echo esc_html__( 'Remove all plugin settings and data when plugin is uninstalled', 'cloudbridge-2fa' ) . '</label> ';
        echo '</div>';
    }

    public function cb2fa_user_profile_factor_settings( $user ) : void {
        if ( ! $user instanceof \WP_User ) {
            return;
        }
        if ( ! current_user_can( 'edit_user', $user->ID ) ) {
            return;
        }
        $is_self = ( get_current_user_id() === (int)$user->ID );
        $can_manage_bypass = $this->cb2fa_can_manage_user_bypass();
        $bypass_enabled = $this->cb2fa_user_has_bypass( $user->ID );
        $notice = $this->cb2fa_get_profile_notice( $user->ID );
        $totp_available = ( is_object( $this->TOTP ) && $this->TOTP->cb2fa_is_available() );
        $totp_enabled = ( $totp_available ? $this->TOTP->cb2fa_user_has_totp( $user->ID ) : false );
        $pending_secret = '';
        $recovery_codes = [];

        if ( $totp_available && $is_self && ! $totp_enabled ) {
            $pending_secret = $this->TOTP->cb2fa_ensure_pending_secret( $user->ID );
        }
        if ( $totp_available && $totp_enabled ) {
            $recovery_codes = $this->TOTP->cb2fa_get_recovery_codes( $user->ID );
        }

        echo '<div class="cb2fa-profile-panel">';
        echo '<div class="cb2fa-profile-panel-header">';
        echo '<h2>' . esc_html__( 'Cloudbridge 2FA', 'cloudbridge-2fa' ) . '</h2>';
        echo '<p class="cb2fa-profile-panel-intro">' . esc_html__( 'Manage authenticator app setup, recovery codes, and factor availability for this account.', 'cloudbridge-2fa' ) . '</p>';
        echo '</div>';

        if ( is_array( $notice ) && ! empty( $notice['message'] ) ) {
            $notice_class = 'notice-info';
            if ( ! empty( $notice['type'] ) && $notice['type'] === 'error' ) {
                $notice_class = 'notice-error';
            } elseif ( ! empty( $notice['type'] ) && $notice['type'] === 'success' ) {
                $notice_class = 'notice-success';
            }
            echo '<div class="notice inline ' . esc_attr( $notice_class ) . '"><p><strong>' . esc_html( $notice['message'] ) . '</strong></p></div>';
        }

        echo '<table class="form-table cb2fa-profile-table" role="presentation">';
        wp_nonce_field( 'cb2fa-user-profile', 'cb2fa_user_profile_nonce' );

        echo '<tr>';
        echo '<th scope="row">' . esc_html__( 'Available factors', 'cloudbridge-2fa' ) . '</th>';
        echo '<td>';
        echo '<p>' . esc_html__( 'E-mail OTP', 'cloudbridge-2fa' ) . ': ' . ( $this->cb2fa_email_factor_enabled() ? esc_html__( 'enabled', 'cloudbridge-2fa' ) : esc_html__( 'disabled', 'cloudbridge-2fa' ) ) . '</p>';
        echo '<p>' . esc_html__( 'Authenticator app', 'cloudbridge-2fa' ) . ': ' . ( $this->cb2fa_totp_factor_enabled() ? esc_html__( 'enabled', 'cloudbridge-2fa' ) : esc_html__( 'disabled', 'cloudbridge-2fa' ) ) . '</p>';
        if ( $this->cb2fa_totp_factor_enabled() ) {
            echo '<p class="description">' . esc_html__( 'Authenticator app setup works with standards-based TOTP apps such as Google Authenticator, Microsoft Authenticator, Bitwarden, 2FAS, Authy, Ente Auth, and Apple Passwords.', 'cloudbridge-2fa' ) . '</p>';
        }
        echo '</td>';
        echo '</tr>';

        if ( $can_manage_bypass || $bypass_enabled ) {
            echo '<tr>';
            echo '<th scope="row">' . esc_html__( 'Emergency bypass', 'cloudbridge-2fa' ) . '</th>';
            echo '<td>';
            if ( $bypass_enabled ) {
                echo '<p><strong>' . esc_html__( 'Cloudbridge 2FA bypass is currently enabled for this account.', 'cloudbridge-2fa' ) . '</strong></p>';
            } else {
                echo '<p class="description">' . esc_html__( 'Use this only when the normal Cloudbridge 2FA login path is unavailable for a specific account.', 'cloudbridge-2fa' ) . '</p>';
            }
            if ( $can_manage_bypass ) {
                echo '<p class="description">' . esc_html__( 'Emergency bypass is managed from Cloudbridge 2FA > Bypass 2FA.', 'cloudbridge-2fa' ) . '</p>';
                echo '<p class="description">' . esc_html__( 'Only plugin administrators should change this. When enabled, this account can log in with password only even if its role normally requires Cloudbridge 2FA.', 'cloudbridge-2fa' ) . '</p>';
            } else {
                echo '<p class="description">' . esc_html__( 'This bypass can only be changed by a plugin administrator.', 'cloudbridge-2fa' ) . '</p>';
            }
            echo '</td>';
            echo '</tr>';
        }

        echo '<tr>';
        echo '<th scope="row">' . esc_html__( 'Authenticator status', 'cloudbridge-2fa' ) . '</th>';
        echo '<td>';
        if ( ! $totp_available ) {
            echo '<p class="description">' . esc_html__( 'Authenticator app support is unavailable because PHP openssl support is missing.', 'cloudbridge-2fa' ) . '</p>';
        } elseif ( ! $this->cb2fa_totp_enabled ) {
            echo '<p class="description">' . esc_html__( 'Authenticator app support is currently disabled for this site.', 'cloudbridge-2fa' ) . '</p>';
        } elseif ( $totp_enabled ) {
            echo '<p><strong>' . esc_html__( 'Authenticator app is enabled for this account.', 'cloudbridge-2fa' ) . '</strong></p>';
            if ( $is_self ) {
                echo '<label for="cb2fa_totp_disable">';
                echo '<input type="checkbox" name="cb2fa_totp_disable" id="cb2fa_totp_disable" value="1" />';
                echo esc_html__( 'Disable authenticator app and remove stored recovery codes', 'cloudbridge-2fa' ) . '</label>';
            }
        } else {
            echo '<p><strong>' . esc_html__( 'Authenticator app is not yet enabled for this account.', 'cloudbridge-2fa' ) . '</strong></p>';
            if ( $is_self && ! empty( $pending_secret ) ) {
                echo '<p class="description">' . esc_html__( 'Add the below secret to your authenticator app as a time-based account, then enter the current six-digit code and update your profile.', 'cloudbridge-2fa' ) . '</p>';
            }
        }
        echo '</td>';
        echo '</tr>';

        if ( $totp_available && $this->cb2fa_totp_enabled && $is_self && ! $totp_enabled && ! empty( $pending_secret ) ) {
            $otpauth_uri = $this->TOTP->cb2fa_get_otpauth_uri( $user, $pending_secret );
            $totp_digits = $this->TOTP->cb2fa_get_digits();
            echo '<tr>';
            echo '<th scope="row">' . esc_html__( 'QR code setup', 'cloudbridge-2fa' ) . '</th>';
            echo '<td>';
            echo '<div id="cb2fa-totp-qr" class="cb2fa-totp-qr" data-cb2fa-otpauth="' . esc_attr( $otpauth_uri ) . '"></div>';
            echo '<p class="description">' . esc_html__( 'Scan this QR code with your authenticator app to set up this account. If scanning is unavailable, use the manual setup key below.', 'cloudbridge-2fa' ) . '</p>';
            echo '</td>';
            echo '</tr>';

            echo '<tr>';
            echo '<th scope="row">' . esc_html__( 'Manual setup key', 'cloudbridge-2fa' ) . '</th>';
            echo '<td>';
            echo '<input type="text" readonly="readonly" class="regular-text code" value="' . esc_attr( $pending_secret ) . '" />';
            echo '<p class="description">' . esc_html__( 'Issuer', 'cloudbridge-2fa' ) . ': ' . esc_html( $this->TOTP->cb2fa_get_issuer_name() ) . '</p>';
            echo '<p class="description">' . esc_html__( 'Account', 'cloudbridge-2fa' ) . ': ' . esc_html( $this->TOTP->cb2fa_get_account_name( $user ) ) . '</p>';
            echo '<p class="description">' . esc_html__( 'If your authenticator app cannot scan QR codes, enter the shared key manually as a time-based account.', 'cloudbridge-2fa' ) . '</p>';
            echo '</td>';
            echo '</tr>';

            echo '<tr>';
            echo '<th scope="row">' . esc_html__( 'Authenticator setup', 'cloudbridge-2fa' ) . '</th>';
            echo '<td>';
            echo '<label for="cb2fa_totp_code">' . esc_html__( 'Verification code', 'cloudbridge-2fa' ) . '</label><br/>';
            echo '<input type="text" name="cb2fa_totp_code" id="cb2fa_totp_code" class="regular-text code" maxlength="' . esc_attr( $totp_digits ) . '" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" />';
            echo '<p class="description">' . esc_html( sprintf( __( 'Enter the current %d-digit code from your authenticator app and update your profile to enable it.', 'cloudbridge-2fa' ), $totp_digits ) ) . '</p>';
            echo '</td>';
            echo '</tr>';
        }

        if ( $totp_available && $totp_enabled && $is_self ) {
            echo '<tr>';
            echo '<th scope="row">' . esc_html__( 'Recovery codes', 'cloudbridge-2fa' ) . '</th>';
            echo '<td>';
            if ( empty( $recovery_codes ) ) {
                echo '<p class="description">' . esc_html__( 'No recovery codes are currently stored for this account.', 'cloudbridge-2fa' ) . '</p>';
            } else {
                $formatted_codes = array_map( [$this->TOTP, 'cb2fa_format_recovery_code'], $recovery_codes );
                echo '<textarea readonly="readonly" rows="8" class="large-text code">' . esc_html( implode( "\n", $formatted_codes ) ) . '</textarea>';
                echo '<p class="description">' . esc_html__( 'Store these recovery codes in a safe place. Each code can be used once if your authenticator app is unavailable.', 'cloudbridge-2fa' ) . '</p>';
            }
            echo '<label for="cb2fa_regenerate_recovery_codes">';
            echo '<input type="checkbox" name="cb2fa_regenerate_recovery_codes" id="cb2fa_regenerate_recovery_codes" value="1" />';
            echo esc_html__( 'Generate a new set of recovery codes', 'cloudbridge-2fa' ) . '</label>';
            echo '</td>';
            echo '</tr>';
        }
        echo '</table>';
        echo '</div>';
    }

    public function cb2fa_save_user_profile_factor_settings( int $user_id ) : void {
        if ( ! current_user_can( 'edit_user', $user_id ) ) {
            return;
        }
        if ( empty( $_POST['cb2fa_user_profile_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['cb2fa_user_profile_nonce'] ) ), 'cb2fa-user-profile' ) ) {
            return;
        }
        if ( ! is_object( $this->TOTP ) || ! $this->TOTP->cb2fa_is_available() ) {
            return;
        }
        if ( get_current_user_id() !== $user_id ) {
            return;
        }
        if ( ! empty( $_POST['cb2fa_totp_disable'] ) ) {
            $this->TOTP->cb2fa_disable_totp( $user_id );
            $this->cb2fa_set_profile_notice( $user_id, 'success', __( 'Authenticator app has been disabled for this account.', 'cloudbridge-2fa' ) );
            return;
        }
        if ( ! empty( $_POST['cb2fa_regenerate_recovery_codes'] ) && $this->TOTP->cb2fa_user_has_totp( $user_id ) ) {
            $codes = $this->TOTP->cb2fa_regenerate_recovery_codes( $user_id );
            if ( ! empty( $codes ) ) {
                $this->cb2fa_set_profile_notice( $user_id, 'success', __( 'Recovery codes have been regenerated.', 'cloudbridge-2fa' ) );
            } else {
                $this->cb2fa_set_profile_notice( $user_id, 'error', __( 'Unable to regenerate recovery codes.', 'cloudbridge-2fa' ) );
            }
            return;
        }
        if ( ! $this->cb2fa_totp_enabled || $this->TOTP->cb2fa_user_has_totp( $user_id ) ) {
            return;
        }
        if ( empty( $_POST['cb2fa_totp_code'] ) ) {
            return;
        }
        $pending_secret = $this->TOTP->cb2fa_get_pending_secret( $user_id );
        if ( empty( $pending_secret ) ) {
            $pending_secret = $this->TOTP->cb2fa_ensure_pending_secret( $user_id );
        }
        $verification_code = sanitize_text_field( wp_unslash( $_POST['cb2fa_totp_code'] ) );
        if ( ! $this->TOTP->cb2fa_verify_totp( $pending_secret, $verification_code ) ) {
            $this->cb2fa_set_profile_notice( $user_id, 'error', __( 'The authenticator app code was invalid. Please check the setup key and try again.', 'cloudbridge-2fa' ) );
            return;
        }
        if ( ! $this->TOTP->cb2fa_enable_secret( $user_id, $pending_secret ) ) {
            $this->cb2fa_set_profile_notice( $user_id, 'error', __( 'Unable to store the authenticator app secret for this account.', 'cloudbridge-2fa' ) );
            return;
        }
        $codes = $this->TOTP->cb2fa_regenerate_recovery_codes( $user_id );
        if ( empty( $codes ) ) {
            $this->cb2fa_set_profile_notice( $user_id, 'error', __( 'Authenticator app was enabled, but recovery codes could not be generated.', 'cloudbridge-2fa' ) );
            return;
        }
        $this->cb2fa_set_profile_notice( $user_id, 'success', __( 'Authenticator app has been enabled and recovery codes have been generated.', 'cloudbridge-2fa' ) );
    }

    /**
     * Export configuration data.
     *
     * @since 1.0.0
     * @return void
     */
    public function cb2fa_admin_export() {
        if ( ! $this->cb2fa_is_plugin_admin() )  {
            return;
        }
        $html = '';
        $tab_header = '<div class="wrap">';
            $tab_header .= '<h1>' . $this->cb2fa_make_icon_html( 'appicon' ) . '&nbsp;&nbsp;' . esc_html( CB2FA_PLUGINNAME_HUMAN ) .
                           ': <small>' . esc_html__( 'Export', 'cloudbridge-2fa' ) . '</small></h1>';
            $tab_header .= '<p>' . esc_html__( 'Export configuration data', 'cloudbridge-2fa' ) . '</p>';
            $tab_header .= '<nav class="nav-tab-wrapper">';
            $tab_header .= '<a data-toggle="cb2fa-export-config" href="#cb2fa-export-config" class="cb2fa-tab nav-tab">' . esc_html__( 'Configuration', 'cloudbridge-2fa' ) . '</a>';
            $tab_header .= '</nav>';

            $html .= '<div class="tab-content">';
            $html .= '<div class="cb2fa-config-header">';
            $html .= '<div id="cb2fa-export-config" class="cb2fa-tab-content cb2fa-is-hidden">';
            $cb2fa_export_options = [];
            foreach ( Cloudbridge_2FA_Options::cb2fa_our_options() as $option_name ) {
                $cb2fa_export_options[] = [
                    'option_name'  => $option_name,
                    'option_value' => get_option( $option_name, null ),
                ];
            }
            if ( empty( $cb2fa_export_options ) ) {
                $html .= '<div class="cb2fa-error">' .
                         esc_html__( 'Unable to fetch plugin configuration from the WordPress database', 'cloudbridge-2fa' ) .
                         '</div>';
            } else {
                $html .= '<p>' . esc_html__( 'Copy and paste this Base64 data into another Cloudbridge 2FA installation', 'cloudbridge-2fa' ) . '.</p>';
                // Add our "signature", just for basic import validation
                $cb2fa_export_options[] = array( 'cloudbridge-2fa' => CB2FA_VERSION );
                $html .= '<textarea rows="10" cols="60" class="cb2fa-textarea-importexport" id="cb2fa-textarea-export" readonly>';
                $html .= @ base64_encode( wp_json_encode( $cb2fa_export_options, 0, 3 ) );
                $html .= '</textarea>';
                $html .= '<p><input type="button" name="cb2facfgdoexport" id="cb2facfgdoexport" class="button button-primary" value="' . esc_html__( 'Export', 'cloudbridge-2fa' ) . '" />';
                $html .= '<div id="cb2facfgexport-success" class="cb2fa-inline-notice cb2fa-notice-success cb2fa-is-hidden">' . esc_html__( 'Successfully copied to clipboard', 'cloudbridge-2fa' ) . '</div>';
                $html .= '<div id="cb2facfgexport-fail" class="cb2fa-inline-notice cb2fa-notice-error cb2fa-is-hidden">' . esc_html__( 'Unable to copy to clipboard, please select and copy manually', 'cloudbridge-2fa' ) . '</div>';
                $html .= '</p>';
            }
            //CB2FA_DEFAULT_PREFIX
            $html .= '</div>';//cb2fa-export-config
            $html .= '</div>';//cb2fa-config-header
            $html .= '</div>';//tab-content
        $html .= '</div>'; // wrap
        //
        echo $tab_header . $html;
        // echo wp_kses_post( $tab_header . $html );
    }
    /**
     * Import configuration data.
     *
     * @since 1.0.0
     */
    public function cb2fa_admin_import() {
        if ( ! $this->cb2fa_is_plugin_admin() )  {
            return;
        }
        // Handle submit
        $skipped_options = '';
        $form_error_message = '';
        $auto_added_admin_message = '';
        $import_count = 0;
        if ( ! empty( $_POST['cb2facfgdoimport'] ) ) {
            if ( empty( $_POST['cb2fa_import_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['cb2fa_import_nonce'] ) ), 'cb2fa-import-config' ) ) {
                $form_error_message = __( 'Security check failed, please try again', 'cloudbridge-2fa' );
            } else {
                if ( ! empty( $_POST['cb2fa-textarea-import'] ) ) {
                    $cb2fa_json_importconfig = sanitize_text_field( wp_unslash( $_POST['cb2fa-textarea-import'] ) );
                } else {
                    $cb2fa_json_importconfig = '';
                }
                $decoded_importconfig = base64_decode( $cb2fa_json_importconfig, true );
                // Simple Base64 validation
                if ( empty( $cb2fa_json_importconfig ) || $decoded_importconfig === false || base64_encode( $decoded_importconfig ) != $cb2fa_json_importconfig ) {
                    $form_error_message = __( 'Please enter a valid Base64 encoded string', 'cloudbridge-2fa' );
                } else {
                    $current_user_login = '';
                    // Try json_decode() and validation
                    $json_data = @ json_decode( $decoded_importconfig, true, 3 );
                    if ( ! is_array( $json_data ) || empty( $json_data ) || json_last_error() != 0 ) {
                        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                            error_log( '[CB2FA_DEBUG] ' . basename(__FILE__) . ' (' . __FUNCTION__ . '): json_last_error=' . json_last_error() .', json_last_error_msg "' . json_last_error_msg() .'"' );
                        }
                        $form_error_message = __( 'The specified import data does not seem to contain an exported configuration', 'cloudbridge-2fa' );
                    } else {
                        $found_signature = false;
                        foreach( $json_data as $k => $v ) {
                            if ( is_array( $v ) && ! empty( $v['cloudbridge-2fa'] ) ) {
                                // We don't do any more validation than this at this point
                                $found_signature = true;
                            }
                        }
                        if ( ! $found_signature ) {
                            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                                error_log( '[CB2FA_DEBUG] ' . basename(__FILE__) . ' (' . __FUNCTION__ . '): json data doest not contain "' . 'cloudbridge-2fa' . '"' );
                                error_log( print_r( $json_data, true ) );
                            }
                            $form_error_message = __( 'The specified import data does not seem to contain an exported configuration', 'cloudbridge-2fa' );
                        }
                    }
                    if ( empty( $form_error_message ) ) {
                        $current_user = wp_get_current_user();
                        if ( empty( $current_user->data->user_login ) ) {
                            $form_error_message = __( 'Unable to fetch current username', 'cloudbridge-2fa' );
                        } else {
                            $current_user_login = $current_user->data->user_login;
                        }
                    }
                    // Do import
                    if ( empty( $form_error_message ) ) {
                        $this->cb2fa_doing_import = true;
                        foreach( $json_data as $k => $v ) {
                            if ( is_array( $v ) && empty( $v['cloudbridge-2fa'] ) ) {
                                $option = array();
                                foreach( $v as $cfg_option => $cfg_value ) {
                                    $option[$cfg_option] = $cfg_value;
                                }
                                if ( empty( $option['option_name'] ) || ! isset( $option['option_value'] ) || ! Cloudbridge_2FA_Options::cb2fa_is_our_option( $option['option_name'] )  ) {
                                    if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                                        error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): Skipped unknown option "' . $option['option_name'] . '"' );
                                        error_log( print_r( $json_data, true ) );
                                    }
                                    if ( empty( $form_error_message ) ) {
                                        $form_error_message = __( 'One or more unrecognized options were ignored', 'cloudbridge-2fa' ) . ':';
                                    }
                                    $skipped_options .= esc_html( $option['option_name'] ) . '<br/>';
                                } elseif ( $option['option_name'] != 'cloudbridge-2fa' . '-form-tab' ) {
                                    if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                                        error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): Imported "' . $option['option_name'] . '" with value "' . print_r( $option['option_value'], true ) . '"' );
                                    }
                                    if ( $option['option_name'] == 'cloudbridge2fa-admin-users' ) {
                                        // Make sure we add current user login to admin users, if configured
                                        $admin_users_json = @ json_decode( $option['option_value'], true, 2 );
                                        if ( is_array( $admin_users_json ) && ! empty( $admin_users_json ) ) {
                                            if ( ! in_array( $current_user_login, $admin_users_json ) ) {
                                                if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                                                    error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): Automatically added "' . $current_user_login . '" to CB2FA admins' );
                                                }
                                                $this->_cb2fa_is_plugin_admin = true;
                                                $admin_users_json[] = $current_user_login;
                                                $auto_added_admin_message = __( 'The currently logged in user has been added as an administrator, please check your settings', 'cloudbridge-2fa' );
                                                $option['option_value'] = wp_json_encode( array_unique( $admin_users_json ) );
                                            }
                                        }
                                    }
                                    update_option( $option['option_name'], $option['option_value'] );
                                    $import_count++;
                                }
                            }
                        }
                        $this->cb2fa_doing_import = false;
                        delete_option( 'cloudbridge2fa-form-tab' );
                        $this->cb2fa_form_tab = '';
                    }
                }
            }
        }
        // Possibly format error message
        if ( ! empty( $form_error_message )  ) {
            $form_error_message = '<div class="notice notice-error is-dismissible"><p><strong>'.
                                  esc_html( $form_error_message ) .
                                  ( ! empty( $skipped_options ) ? '<p>' . $skipped_options . '</p>' : '' ) .
                                  '</strong></p></div>';
        } elseif ( $import_count > 0 ) {
            // Finalize import
            $form_error_message = '<div class="notice notice-info is-dismissible"><p><strong>'.
                                  (int)$import_count . ' ' . esc_html__( 'configuration setting(s) imported', 'cloudbridge-2fa' ) .
                                  '</strong></p></div>';
        }
        if ( ! empty( $auto_added_admin_message ) ) {
            $form_error_message = '<div class="notice notice-warning is-dismissible"><p><strong>'.
                                  esc_html( $auto_added_admin_message ) .
                                  '</strong></p></div>' .
                                  $form_error_message;
        }
        //
        echo '<div class="wrap">' . wp_kses_post( $form_error_message );
        echo '<h1>' .
             $this->cb2fa_make_icon_html( 'appicon' ) .
             '&nbsp;&nbsp;' .
             esc_html( CB2FA_PLUGINNAME_HUMAN ) .
             ': <small>' .
             esc_html__( 'Import', 'cloudbridge-2fa' ) .
             '</small></h1>';
        echo '<p>' . esc_html__( 'Import data', 'cloudbridge-2fa' ) . '</p>';
        echo '<nav class="nav-tab-wrapper">';
        echo '<a data-toggle="cb2fa-import-config" href="#cb2fa-import-config" class="cb2fa-tab nav-tab">' . esc_html__( 'Configuration', 'cloudbridge-2fa' ) . '</a>';
        echo '</nav>';

        echo '<form method="post" action="' . esc_url( admin_url( 'admin.php' ) ) . '?page=' . 'cloudbridge-2fa' . '-import" id="cb2fa-tab-form">';
        wp_nonce_field( 'cb2fa-import-config', 'cb2fa_import_nonce' );
        echo '<div class="tab-content">';
        echo '<div class="cb2fa-config-header">';
        echo '<div id="cb2fa-import-config" class="cb2fa-tab-content cb2fa-is-hidden">';
        echo esc_html__( 'This will replace plugin configuration data', 'cloudbridge-2fa' ) . '.';
        echo '<textarea rows="10" cols="60" style="margin-top:25px;" class="cb2fa-textarea-importexport" name="cb2fa-textarea-import" id="cb2fa-textarea-import"></textarea>';
        echo '<p class="description">' . esc_html__( 'Paste previously exported Base64 configuration data into this field', 'cloudbridge-2fa' ) . '.</p>';
        submit_button( esc_html__( 'Import', 'cloudbridge-2fa' ), 'primary', 'cb2facfgdoimport' );
        echo '</div>';//cb2fa-export-config
        echo '</div>';//cb2fa-config-header
        echo '</div>';//tab-content
        echo '</form>';
        echo '</div>';//wrap
    }
    /**
     * Do other init that needs to be delayed.
     *
     * @since 1.0.0
     */
    public function cb2fa_setup_other() : void {
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . ')' );
        }
        // Setup "global" nonce for ajax, etc.
        $this->cb2fa_nonce = wp_create_nonce( 'cloudbridge-2fa' . CB2FA_VERSION );
        // Possibly enable debugging for these
        if ( defined( 'CB2FA_DEBUG_OPTIONS' ) && CB2FA_DEBUG_OPTIONS ) {
            add_action( 'add_option', [$this, 'cb2fa_admin_debug_add_option'], 10, 2 );
            add_action( 'update_option', [$this, 'cb2fa_admin_debug_update_option'], 10, 3 );
            add_action( 'updated_option', [$this, 'cb2fa_admin_debug_updated_option'], 10, 3 );
        }
    }
    /**
     * Debugging
     */
    public function cb2fa_admin_debug_add_option( $option, $value ) {
        if ( defined( 'CB2FA_DEBUG_OPTIONS' ) && CB2FA_DEBUG_OPTIONS ) {
            error_log( '--- ADD' );
            error_log( basename(__FILE__) . ' (' . __FUNCTION__ . ')' );
            error_log( 'option="' . $option . '"' );
            error_log( 'value="' . var_export( $value, true) . '"' );
        }
        return( $value );
    }
    public function cb2fa_admin_debug_update_option( $option, $value, $old_value ) {
        static $ignore_options = array(
            'cron',
            '_transient_doing_cron',
            '_transient_timeout_settings_errors',
        );
        if ( defined( 'CB2FA_DEBUG_OPTIONS' ) && CB2FA_DEBUG_OPTIONS ) {
            if ( ! in_array( $option, $ignore_options ) ) {
                error_log( '--- UPDATE' );
                error_log( basename( __FILE__ ) . ' (' . __FUNCTION__ . ')' );
                error_log( 'option="' . $option . '"' );
                error_log( 'value="' . var_export( $value, true ) . '"' );
                error_log( 'old value="' . var_export( $old_value, true ) . '"' );
            }
        }
        return( true );
    }
    public function cb2fa_admin_debug_updated_option( $option, $old_value, $value ) {
        static $ignore_options = array(
            'cron',
            '_transient_doing_cron',
            '_transient_timeout_settings_errors',
        );
        if ( defined( 'CB2FA_DEBUG_OPTIONS' ) && CB2FA_DEBUG_OPTIONS ) {
            if ( ! in_array( $option, $ignore_options ) ) {
                error_log( '--- UPDATED' );
                error_log( basename(__FILE__) . ' (' . __FUNCTION__ . ')' );
                error_log( 'option="' . $option . '"' );
                error_log( 'value="' . var_export( $value, true) . '"' );
                error_log( 'old value="' . var_export( $old_value, true) . '"' );
            }
        }
    }
    /**
     * Setup language support.
     *
     * @since 1.0.0
     */
    public function setup_locale() {
        if ( ! load_plugin_textdomain( 'cloudbridge-2fa',
                                       false,
                                       dirname( plugin_basename( __FILE__ ) ) . '/languages' ) ) {
            /**
             * We don't consider this to be a "real" error since 2.0.0
             */
            // error_log( 'Unable to load language file (' . dirname( plugin_basename( __FILE__ ) ) . '/languages' . ')' );
        }
    }
    /**
     * Handle post-authentication.
     *
     * This is we would do our thing, after WordPress has handled the username/
     * password validation.
     */
    public function cb2fa_post_wp_authenticate( $user, $username, $password ) {
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . ')' );
        }
        // This should never happen, but ... :-)
        if ( ! $this->cb2fa_active_roles() ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): No active roles, bailing' );
            }
            return ( $user );
        }
        // It's an error and not a user object, bail
        if ( $user instanceof \WP_Error ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): $user object is WP_Error, bailing' );
            }
            return ( $user );
        }
        // It's not a user object, bail
        if ( ! $user instanceof \WP_User ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                if ( $user === null ) {
                    error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): $user object is null, bailing' );
                } else {
                    error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): $user object is not WP_User, bailing' );
                }
            }
            return ( $user );
        }
        // Check for missing or invalid nonce
        $request_nonce = '';
        if ( ! empty( $_REQUEST['cb2fa_nonce'] ) ) {
            $request_nonce = sanitize_text_field( wp_unslash( $_REQUEST['cb2fa_nonce'] ) );
        }
        if ( ! $this->cb2fa_verify_runtime_nonce( $request_nonce ) ) {
            error_log( '[CB2FA_DEBUG] ' . __FUNCTION__ . ' Nonce verification failed' );
            $user = new \WP_Error( 'CB2FA', __( 'Invalid form token, please try again', 'cloudbridge-2fa' ), 'This is CB2FA data' );
            return ( $user );
        }
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . __FUNCTION__ );
            error_log( '[CB2FA_DEBUG] username="' . $username . '"' );
            error_log( '[CB2FA_DEBUG] password="' . $password . '"' );
            error_log( '[CB2FA_DEBUG] ' . __FUNCTION__ . ' Our nonce is "' . $this->cb2fa_nonce . '"' );
            error_log( '[CB2FA_DEBUG] ' . __FUNCTION__ . ' REQUEST is ' . print_r( $_REQUEST, true ) );
            error_log( '[CB2FA_DEBUG] ' . __FUNCTION__ . ' ' . print_r( $user->to_array(), true ) );
            error_log( '[CB2FA_DEBUG] ' . __FUNCTION__ . ' ' . print_r( $user->get_role_caps(), true ) );
            error_log( '[CB2FA_DEBUG] ' . __FUNCTION__ . ' ' . print_r( $user->roles, true ) );
            error_log( '[CB2FA_DEBUG] ' . __FUNCTION__ . ' ' . print_r( $this->cb2fa_roles_configuration, true ) );
            error_log( '[CB2FA_DEBUG] ' . __FUNCTION__ . ' ' . print_r( $this->cb2fa_cookies_configuration, true ) );
        }
        // Make sure user has roles
        if ( ! is_array( $user->roles ) || empty( $user->roles ) ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): No roles for user "' . $user->data->user_email . '"' );
            }
            $user = new \WP_Error( 'CB2FA', __( 'No active roles found for this user on this website, please try again', 'cloudbridge-2fa' ), 'This is CB2FA data' );
            return ( $user );
        }
        if ( $this->cb2fa_user_has_bypass( $user->ID ) ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): per-user bypass enabled for "' . $user->data->user_login . '"' );
            }
            return( $user );
        }
        // Check if 2FA (and possibly cookie) is enabled for this user's role(s)
        $require_2fa = false;
        $allow_cookie = false;
        foreach ( $user->roles as $role ) {
            if ( in_array( $role, $this->cb2fa_roles_configuration, true ) ) {
                if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                    error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): ' . $role . ' is active, 2FA required' );
                }
                $require_2fa = true;
                if ( in_array( $role, $this->cb2fa_cookies_configuration, true ) ) {
                    if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                        error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): ' . $role . ' cookie may be used' );
                    }
                    $allow_cookie = true;
                }
                break;
            }
        }// foreach
        if ( ! $require_2fa ) {
            if ( $this->cb2fa_is_plugin_admin() ) {
                remove_action( 'admin_enqueue_scripts', [ $this, 'cb2fa_setup_admin_css' ] );
                remove_action( 'admin_menu', [ $this, 'cb2fa_menu' ] );
                remove_action( 'admin_init', [ $this, 'cb2fa_settings' ] );
            }
            return( $user );
        }
        // Check if bypass cookie is allowed, and if so, if one is present
        if ( $allow_cookie ) {
            $cb2fa_login = Cloudbridge_2FA_Login::getInstance( $this->cb2fa_nonce, $allow_cookie );
            $cb2fa_login->setFromWordPress( true );
            $cb2fa_login->setUser( $user, $username );
            $cookie_hash = $cb2fa_login->getCookieHash();
            if ( ! empty( $_COOKIE['cb2fa_' . $cookie_hash] ) && $_COOKIE['cb2fa_' . $cookie_hash] == 'cb2fa_cookie' ) {
                if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                    error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): "cb2fa_' . $cookie_hash . '" is set, bailing' );
                }
                return( $user );
            }
        }
        // Clean nonce, probably not needed, but it is external data
        $the_nonce = $request_nonce;
        $challenge = $this->cb2fa_create_login_challenge( $user, $username, $allow_cookie );
        if ( $challenge instanceof \WP_Error ) {
            return( $challenge );
        }
        $this->cb2fa_store_challenge( $username, $the_nonce, $challenge );
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): Created challenge transient for factor "' . $challenge['active_factor'] . '"' );
        }
        // Clear previous output from WordPress and display our form instead
        ob_end_clean();
        nocache_headers();
        $this->cb2fa_auth_form( $user, $username, $challenge, $allow_cookie );
        die();
    }

    /**
     * Add our required fields to the WordPress login form.
     */
    public function cb2fa_login_form() {
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . ')' );
        }
        if ( isset( $_REQUEST['cb2fa_notice'] ) && sanitize_key( wp_unslash( $_REQUEST['cb2fa_notice'] ) ) === 'restart' ) {
            echo '<div id="login_error"><strong>' .
                 esc_html__( 'Your login verification expired. Please sign in again.', 'cloudbridge-2fa' ) .
                 '</strong></div>';
        }
        if ( ! empty( $_REQUEST['cb2fa_timer'] ) && $_REQUEST['cb2fa_timer'] <= time()
                && ! empty( $_REQUEST['cb2fa_nonce'] )
                && $this->cb2fa_verify_runtime_nonce( sanitize_text_field( wp_unslash( $_REQUEST['cb2fa_nonce'] ) ) ) ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): We may be re-directing' );
            }
            if ( ! empty( $_REQUEST['redirect_to'] ) ) {
                $redirect_to = $this->cb2fa_validate_redirect_url(
                    sanitize_url( wp_unslash( $_REQUEST['redirect_to'] ), ['http', 'https'] ),
                    wp_login_url()
                );
                ob_end_clean();
                wp_safe_redirect( $redirect_to );
                die();
            }
        }
        echo '<input type="hidden" name="cb2fa_nonce" value="' . esc_html( $this->cb2fa_nonce ) . '" />';
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): Our nonce is "' . $this->cb2fa_nonce );
        }
    }

    /**
     * Paint our 2FA authentication form.
     *
     * This function does NOT terminate execution!
     *
     * @since 1.0.0
     * @param $user
     * @param string $username
     * @param string $the_pin
     * @param bool $allow_cookie
     * @return void
     */
    protected function cb2fa_auth_form( $user, string $username, array $challenge, bool $allow_cookie = false ) : void {
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . ')' );
        }
        $cb2fa_login = Cloudbridge_2FA_Login::getInstance( $this->cb2fa_nonce, $allow_cookie );
        $cb2fa_login->setFromWordPress( true );
        $cb2fa_login->setUser( $user, $username );
        $cb2fa_login->setChallenge( $challenge );
        if ( ! empty( $challenge['active_factor'] ) && $challenge['active_factor'] === 'email' && ! empty( $challenge['email_code'] ) ) {
            $cb2fa_login->send_2fa_code( $challenge['email_code'] );
        }
        $cb2fa_login->drawForm();
    }

    /**
     * Run plugin.
     *
     * Basically "enqueues" WordPress actions and lets WordPress do its thing.
     *
     * @since 1.0.0
     */
    public function run() : void {
        // Setup i18n. We use the 'init' action rather than 'plugins_loaded' as per
        // https://developer.wordpress.org/reference/functions/load_plugin_textdomain/#user-contributed-notes
        add_action( 'init',                      [$this, 'setup_locale']              );

        if ( $this->cb2fa_active_roles() ) {
            // Only activate hooks if we need to
            add_filter( 'authenticate',          [$this, 'cb2fa_post_wp_authenticate'], 21, 3 );
            add_action( 'login_form',            [$this, 'cb2fa_login_form'],   10, 0 );
        }
        // Admin setup
        if ( is_admin() ) {
            add_action( 'admin_enqueue_scripts', [ $this, 'cb2fa_setup_admin_css' ] );
            add_action( 'admin_menu', [ $this, 'cb2fa_menu' ] );
            add_action( 'admin_init', [ $this, 'cb2fa_settings' ] );
            add_action( 'show_user_profile', [ $this, 'cb2fa_user_profile_factor_settings' ] );
            add_action( 'edit_user_profile', [ $this, 'cb2fa_user_profile_factor_settings' ] );
            add_action( 'personal_options_update', [ $this, 'cb2fa_save_user_profile_factor_settings' ] );
            add_action( 'edit_user_profile_update', [ $this, 'cb2fa_save_user_profile_factor_settings' ] );
        } else {
        // Public setup
            add_action( 'wp_enqueue_scripts',    [$this, 'cb2fa_setup_public_css']  );
        }
        // Other setup
        add_action( 'init',                      [$this, 'cb2fa_setup_other']       );
        // Plugin deactivation, not needed atm :-)
        // register_deactivation_hook( __FILE__, [$this, 'cb2fa_deactivate_plugin'] );
    }

}// Cloudbridge_2FA


/**
 * Activation hook
 */
function cb2fa_activation() {
    update_option( 'cloudbridge2fa-activated', time() );
}
register_activation_hook( __FILE__, __NAMESPACE__ . '\cb2fa_activation' );


/**
 * Run plugin
 *
 * @since 1.0.0
 */
function run_cloudbridge2fa() {
    $plugin = Cloudbridge_2FA::getInstance();
    $plugin->run();
}

run_cloudbridge2fa();
