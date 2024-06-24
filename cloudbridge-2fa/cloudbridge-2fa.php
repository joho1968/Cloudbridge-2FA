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
 * Version:           1.0.3
 * Author:            WebbPlatsen, Joaquim Homrighausen <joho@webbplatsen.se>
 * Author URI:        https://webbplatsen.se/
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       cloudbridge-2fa
 * Domain Path:       /languages
 *
 * cloudbridge-2fa.php
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

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    die;
}
if ( ! defined( 'ABSPATH' ) ) {
    die( '-1' );
}

define( 'CB2FA_WORDPRESS_PLUGIN',         true                    );
define( 'CB2FA_VERSION',                  '1.0.0'                 );
define( 'CB2FA_REV',                      1                       );
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
    protected $cb2fa_wordpress_admin_users = null;
    protected $_cb2fa_is_plugin_admin = null;
    protected $Utility;                                      // @since 1.0.0
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
            if ( ! empty( $_POST)) {
                error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): POST' . "\n" . var_export( $_POST, true ) );
            }
            if ( ! empty( $_REQUEST)) {
                error_log( basename(__FILE__) . ' (' . __FUNCTION__ . '): REQUEST' . "\n" . var_export( $_REQUEST, true ) );
            }
        }
        // Utilities
        $this->Utility = Cloudbridge_2FA_Utility::getInstance();
        if ( ! is_object( $this->Utility ) ) {
            error_log( '[CB2FA] ' . basename(__FILE__) . ' (' . __FUNCTION__ . '): Unable to create $Utility instance (?)' );
        }
        // Try to retain our last used tab. This is lost since WordPress
        // actually calls the constructor twice on an options.php form page
        if ( ! empty( $_POST['cb2fa-form-tab'] ) ) {
            $this->cb2fa_form_tab = sanitize_key( $_POST['cb2fa-form-tab'] );
            update_option( 'cloudbridge2fa-form-tab', $this->cb2fa_form_tab );
        } else {
            $this->cb2fa_form_tab = get_option( 'cloudbridge2fa-form-tab', '' );
        }
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
        wp_enqueue_script( 'cloudbridge-2fa',
                           plugin_dir_url( __FILE__ ) . 'js/cb2fa-admin.js',
                           array(),
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
            $this->cb2fa_wordpress_admin_users = get_users();
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
        if ( empty( $this->cb2fa_form_tab ) ) {
            $this->cb2fa_form_tab = 'general';
        }
        $html = '';
        // Output configuration options$action
        $tab_header = '<div class="wrap">';
            $tab_header .= '<h1>' . $this->cb2fa_make_icon_html( 'appicon' ) . '&nbsp;&nbsp;' . esc_html( CB2FA_PLUGINNAME_HUMAN ) . '</h1>';
            $tab_header .= '<p>' . esc_html__( 'These settings allow general configuration of Cloudbridge 2FA', 'cloudbridge-2fa' ) . '</p>';
            $tab_header .= '<nav class="nav-tab-wrapper">';
            $tab_header .= '<a data-toggle="cb2fa-general" href="#general" class="cb2fa-tab nav-tab">' . esc_html__( 'General', 'cloudbridge-2fa' ) . '</a>';
            $tab_header .= '<a data-toggle="cb2fa-roles" href="#roles" class="cb2fa-tab nav-tab">' . esc_html__( 'Roles', 'cloudbridge-2fa' ) . '</a>';
            $tab_header .= '<a data-toggle="cb2fa-access" href="#access" class="cb2fa-tab nav-tab">' . esc_html__( 'Access', 'cloudbridge-2fa' ) . '</a>';
            $tab_header .= '<a data-toggle="cb2fa-about" href="#about" class="cb2fa-tab nav-tab">' . esc_html__( 'About', 'cloudbridge-2fa' ) . '</a>';
            $tab_header .= '</nav>';

            $html .= '<form method="post" action="options.php">';
            $html .= '<input type="hidden" name="cb2fa-form-tab" id="cb2fa-form-tab" value="' . esc_attr( $this->cb2fa_form_tab ) . '" />';
            $html .= '<div class="tab-content">';
            $html .= '<div class="cb2fa-config-header">';
            $html .= '<div id="cb2fa-general" class="cb2fa-tab-content cb2fa-is-hidden">';
            ob_start();
            settings_fields( 'cloudbridge-2fa' );
            echo '<table class="form-table" role="presentation">';
                 do_settings_fields( 'cloudbridge-2fa', 'cb2fa-settings' );
            echo '</table>';
            $html .= ob_get_contents();
            ob_end_clean();
            $html .= '</div>';//cb2fa-general
            $html .= '<div id="cb2fa-roles" class="cb2fa-tab-content cb2fa-is-hidden">'.
                     '<p>'  .
                     esc_html__( 'This page allows you to configure how 2FA should be enforced for different WordPress user roles', 'cloudbridge-2fa' ) . '. ' .
                     esc_html__( 'It is recommended that you enable 2FA at least for all roles with elevated privileges', 'cloudbridge-2fa' ) . '.' .
                     '</p>';
            if ( ! $this->cb2fa_active_roles() ) {
                $html .= '<p class="cb2fa-warning">' .
                         esc_html__( 'No roles currently have 2FA enabled', 'cloudbridge-2fa' ) . '.' .
                         '</p>';
            }
            $html .= '</p>';
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
            $html .= '<div class="rolegridrow">';
            $html .= '<div class="rolegridheader">' .
                          esc_html__( 'Role' ) .
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
            $html .= '</div>';// cb2fa-access
            $html .= '<div id="cb2fa-about" class="cb2fa-tab-content cb2fa-is-hidden">';
            $html .= '<p>'.
                         '<p>' . esc_html__( 'Thank you for installing', 'cloudbridge-2fa' ) .' ' . esc_html( CB2FA_PLUGINNAME_HUMAN ) . '!' . ' '.
                         esc_html__( 'This WordPress plugin provides simple two factor authentication services for WordPress', 'cloudbridge-2fa' ) . '.' .
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
            ob_start();
            submit_button();
            $html .= ob_get_contents();
            ob_end_clean();
            $html .= '</div>';
            $html .= '</div>'; // tab-content
            $html .= '</form>';
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
            if ( ! empty( $_REQUEST['action'] ) && ( $_REQUEST['action'] == 'deactivate' || $_REQUEST['action'] == 'delete' )
                    && ! empty( $_REQUEST['plugin'] ) && $_REQUEST['plugin'] ==  'cloudbridge-2fa/' . basename(__FILE__ ) ) {
                // Block deactivation attempt. Possibly not the cleanest way...
                if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                    error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): Blocking deactivation' );
                }
                unset( $_REQUEST['action'] );
                unset( $_GET['action'] );
                unset( $_POST['action'] );
            }
            add_filter( 'all_plugins', [$this, 'cb2fa_hide_plugin'] );
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): Skipping settings' );
            }
            return;
        }
        // Settings
        add_settings_section( 'cb2fa-settings', '', false, 'cloudbridge-2fa' );
            add_settings_field( 'cloudbridge2fa-code-lifetime', esc_html__( 'OTP code lifetime', 'cloudbridge-2fa' ), [$this, 'cb2fa_setting_code_lifetime'], 'cloudbridge-2fa', 'cb2fa-settings', ['label_for' => 'cloudbridge2fa-code-lifetime'] );
            add_settings_field( 'cloudbridge2fa-code-email-subject', esc_html__( 'OTP code in e-mail subject', 'cloudbridge-2fa' ), [$this, 'cb2fa_setting_code_email_subject'], 'cloudbridge-2fa', 'cb2fa-settings', ['label_for' => 'cloudbridge2fa-code-email-subject'] );
            add_settings_field( 'cloudbridge2fa-code-input-text-addon', esc_html__( 'OTP code entry text', 'cloudbridge-2fa' ), [$this, 'cb2fa_code_input_text_addon'], 'cloudbridge-2fa', 'cb2fa-settings', ['label_for' => 'cloudbridge2fa-code-input-text-addon'] );
            add_settings_field( 'cloudbridge2fa-code-email-text-addon', esc_html__( 'OTP code e-mail text', 'cloudbridge-2fa' ), [$this, 'cb2fa_code_email_text_addon'], 'cloudbridge-2fa', 'cb2fa-settings', ['label_for' => 'cloudbridge2fa-code-email-text-addon'] );
            add_settings_field( 'cloudbridge2fa-cookie-lifetime', esc_html__( 'Cookie lifetime', 'cloudbridge-2fa' ), [$this, 'cb2fa_setting_cookie_lifetime'], 'cloudbridge-2fa', 'cb2fa-settings', ['label_for' => 'cloudbridge2fa-cookie-lifetime'] );
            add_settings_field( 'cloudbridge2fa-settings-remove', esc_html__( 'Remove settings', 'cloudbridge-2fa' ), [$this, 'cb2fa_setting_remove'], 'cloudbridge-2fa', 'cb2fa-settings', ['label_for' => 'cloudbridge2fa-settings-remove'] );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-code-lifetime', ['type' => 'number', 'sanitize_callback' => [$this, 'cb2fa_setting_sanitize_code_lifetime']] );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-code-email-subject' );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-roles-config', ['type' => 'array', 'sanitize_callback' => [$this, 'cb2fa_setting_sanitize_roles']] );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-admin-users', ['type' => 'array', 'sanitize_callback' => [$this, 'cb2fa_setting_sanitize_admin_users']] );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-cookies-config', ['type' => 'array', 'sanitize_callback' => [$this, 'cb2fa_setting_sanitize_cookies']] );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-code-input-text-addon', ['type' => 'string', 'sanitize_callback' => [$this, 'cb2fa_setting_sanitize_code_input_text_addon']] );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-code-email-text-addon', ['type' => 'string', 'sanitize_callback' => [$this, 'cb2fa_setting_sanitize_textarea_setting']] );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-cookie-lifetime', ['type' => 'number', 'sanitize_callback' => [$this, 'cb2fa_setting_sanitize_cookie_lifetime']] );
        register_setting( 'cloudbridge-2fa', 'cloudbridge2fa-settings-remove' );
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
        return( json_encode( $return_val ) );
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
        return( json_encode( $return_val ) );
    }
    public function cb2fa_setting_sanitize_cookies( $input ) {
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . ')' );
        }
        if ( ! $this->cb2fa_is_plugin_admin() && $this->cb2fa_doing_import )  {
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
        return( json_encode( $return_val ) );
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
        echo '<div class="cb2fa-role-option">';
        echo '<label for="cloudbridge2fa-code-email-subject">';
        echo '<input type="checkbox" name="cloudbridge2fa-code-email-subject" id="cloudbridge2fa-code-email-subject" value="1" ' . ( checked( $this->cb2fa_code_email_subject, 1, false ) ) . '/>';
        echo esc_html__( 'Include OTP (one time password) in e-mail subject', 'cloudbridge-2fa' ) . '</label> ';
        echo '</div>';
    }
    public function cb2fa_setting_remove() : void {
        echo '<div class="cb2fa-role-option">';
        echo '<label for="cloudbridge2fa-settings-remove">';
        echo '<input type="checkbox" name="cloudbridge2fa-settings-remove" id="cloudbridge2fa-settings-remove" value="1" ' . ( checked( $this->cb2fa_settings_remove, 1, false ) ) . '/>';
        echo esc_html__( 'Remove all plugin settings and data when plugin is uninstalled', 'cloudbridge-2fa' ) . '</label> ';
        echo '</div>';
    }

    /**
     * Export configuration data.
     *
     * @since 1.0.0
     * @return void
     */
    public function cb2fa_admin_export() {
        global $wpdb;

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
            $query = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $wpdb->options WHERE option_name LIKE %s ORDER BY option_id",
                                                         $wpdb->esc_like( CB2FA_DEFAULT_PREFIX . '-' ) . '%' ),
                                        ARRAY_A );
            if ( ! is_array( $query ) || empty( $query[0] ) || ! is_array( $query[0] ) ) {
                $html .= '<div class="cb2fa-error">' .
                         esc_html__( 'Unable to fetch plugin configuration from the WordPress database', 'cloudbridge-2fa' ) .
                         '</div>';
            } else {
                $html .= '<p>' . esc_html__( 'Copy and paste this Base64 data into another Cloudbridge 2FA installation', 'cloudbridge-2fa' ) . '.</p>';
                // Add our "signature", just for basic import validation
                $query[] = array( 'cloudbridge-2fa' => CB2FA_VERSION );
                $html .= '<textarea rows="10" cols="60" class="cb2fa-textarea-importexport" id="cb2fa-textarea-export" readonly>';
                $html .= @ base64_encode( json_encode( $query, 0, 3 ) );
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
            if ( ! empty( $_POST['cb2fa-textarea-import'] ) ) {
                $cb2fa_json_importconfig = sanitize_text_field( $_POST['cb2fa-textarea-import'] );
            } else {
                $cb2fa_json_importconfig = '';
            }
            // Simple Base64 validation
            if ( empty( $cb2fa_json_importconfig ) || base64_encode( base64_decode( $cb2fa_json_importconfig ) ) != $cb2fa_json_importconfig ) {
                $form_error_message = __( 'Please enter a valid Base64 encoded string', 'cloudbridge-2fa' );
            } else {
                $current_user_login = '';
                // Try json_decode() and validation
                $json_data = @ json_decode( base64_decode( $cb2fa_json_importconfig ), true, 3 );
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
                                            $option['option_value'] = json_encode( array_unique( $admin_users_json ) );
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
                }// import
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
        echo '<h1>' . $this->cb2fa_make_icon_html( 'appicon' ) . '&nbsp;&nbsp;' . esc_html( CB2FA_PLUGINNAME_HUMAN ) .
             ': <small>' . esc_html__( 'Import', 'cloudbridge-2fa' ) . '</small></h1>';
        echo '<p>' . esc_html__( 'Import data', 'cloudbridge-2fa' ) . '</p>';
        echo '<nav class="nav-tab-wrapper">';
        echo '<a data-toggle="cb2fa-import-config" href="#cb2fa-import-config" class="cb2fa-tab nav-tab">' . esc_html__( 'Configuration', 'cloudbridge-2fa' ) . '</a>';
        echo '</nav>';

        echo '<form method="post" action="' . esc_url( admin_url( 'admin.php' ) ) . '?page=' . 'cloudbridge-2fa' . '-import" id="cb2fa-tab-form">';
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
             * We don't consider this to be a "real" error since 1.1.0
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
        if ( get_class( $user ) === 'WP_Error' ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): $user object is WP_Error, bailing' );
            }
            return ( $user );
        }
        // It's not a user object, bail
        if ( $user === null ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): $user object is null, bailing' );
            }
            return ( null );
        }
        // Make sure there's an e-mail address attached to the user
        if ( empty( $user->data->user_email ) ) {
            if ( !empty( $user->data->user_login ) ) {
                $login_name = $user->data->user_login;
            } elseif ( !empty( $username ) ) {
                $login_name = $username;
            } else {
                $login_name = 'unknown';
            }
            error_log( '[CB2FA_DEBUG] ' . __FUNCTION__ . ' Missing e-mail address for user "' . $login_name . '"' );
            $user = new \WP_Error( 'CB2FA', __( 'Missing e-mail address for user, please try again', 'cloudbridge-2fa' ), 'This is CB2FA data' );
            return ( $user );
        }
        // Check for missing or invalid nonce
        if ( empty( $_REQUEST['cb2fa_nonce'] ) || $_REQUEST['cb2fa_nonce'] != $this->cb2fa_nonce ) {
            error_log( '[CB2FA_DEBUG] ' . __FUNCTION__ . ' Nonce mismatch, wanted "' . $this->cb2fa_nonce . '", got "' . $_REQUEST['cb2fa_nonce'] . '"' );
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
        $the_nonce = sanitize_text_field( $_REQUEST['cb2fa_nonce'] );
        // Create "random" six digit string
        $the_pin_code = '......';
        try {
            for ( $i = 0; $i < 6; $i++ ) {
                $the_pin_code[$i] = random_int( 0, 9 );
            }
        } catch ( \Exception $e ) {
            for ( $i = 0; $i < 6; $i++ ) {
                $the_pin_code[$i] = mt_rand( 0, 9 );
            }
        }
        // Create transient. We use whatever the user entered as a username to
        // avoid disclosure of WordPress user database information since we
        // need to pass this along throughout forms
        $our_transient = CB2FA_TRANSIENT_PREFIX . $username . $the_nonce;
        $our_transient_data = time() . '_' . $the_pin_code . '_' . ( $allow_cookie ? 'Y' : 'N' ) ;
        set_transient( $our_transient, $our_transient_data, ( $this->cb2fa_code_lifetime * 60 ) );
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): Created transient "' . $our_transient . '" with data "' . $our_transient_data . '"' );
        }
        // Clear previous output from WordPress and display our form instead
        ob_end_clean();
        nocache_headers();
        $this->cb2fa_auth_form( $user, $username, $the_pin_code, $allow_cookie );
        die();
    }

    /**
     * Add our required fields to the WordPress login form.
     */
    public function cb2fa_login_form() {
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . ')' );
        }
        if ( ! empty( $_REQUEST['cb2fa_timer'] ) && $_REQUEST['cb2fa_timer'] <= time() &&
                ! empty( $_REQUEST['cb2fa_nonce'] ) && $this->cb2fa_nonce == $_REQUEST['cb2fa_nonce'] ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . '): We may be re-directing' );
            }
            if ( ! empty( $_REQUEST['redirect_to'] ) ) {
                ob_end_clean();
                header( 'Location: ' . sanitize_url( $_REQUEST['redirect_to'] ) );
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
    protected function cb2fa_auth_form( $user, string $username, string $the_pin, bool $allow_cookie = false ) : void {
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . ' (' . __FUNCTION__ . ')' );
        }
        $cb2fa_login = Cloudbridge_2FA_Login::getInstance( $this->cb2fa_nonce, $allow_cookie );
        $cb2fa_login->setFromWordPress( true );
        $cb2fa_login->setUser( $user, $username );
        $cb2fa_login->send_2fa_code( $the_pin );
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
