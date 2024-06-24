<?php
/**
 * Cloudbridge 2FA login form
 *
 * @since      1.0.0
 * @package    Cloudbridge 2FA
 * @subpackage cloudbridge-2fa/include
 * @author     Joaquim Homrighausen <joho@webbplatsen.se>
*
 * class_cb2fa_login.php
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

if ( ! class_exists( 'cloudbridge2fa\Cloudbridge_2FA_Login' ) ) {

class Cloudbridge_2FA_Login {
    public static $instance = null;
    protected $user = null;
    protected string $username = '';
    protected string $blog_title;
    protected string $our_url;
    protected string $nonce;
    protected string $error_message;
    protected string $form_message;
    protected string $email_message;
    protected int $code_lifetime;
    protected int $cookie_lifetime;
    protected int $isFromWordPress;
    protected bool $allow_cookie;

    public static function getInstance( string $nonce, $allow_cookie = false ) {
        null === self::$instance AND self::$instance = new self( $nonce, $allow_cookie );
        return( self::$instance );
    }
    public function __construct( string $nonce, bool $allow_cookie = false ) {
        $this->our_url = plugins_url( 'cb2fa-passthru.php', dirname( __FILE__ ) );
        $this->code_lifetime = get_option( 'cloudbridge2fa-code-lifetime', null );
        if ( $this->code_lifetime === null || $this->code_lifetime < 1 || $this->code_lifetime > 60 ) {
            $this->code_lifetime = CB2FA_TRANSIENT_EXPIRE_DEFAULT;
        }
        $this->cookie_lifetime = get_option( 'cloudbridge2fa-cookie-lifetime', null );
        if ( $this->cookie_lifetime === null || $this->cookie_lifetime < 0 || $this->cookie_lifetime > 365 ) {
            $this->cookie_lifetime = CB2FA_COOKIE_EXPIRE_DEFAULT;
        }
        $this->code_email_subject = get_option( 'cloudbridge2fa-code-email-subject', false );
        if ( ! empty( $this->code_email_subject ) ) {
            $this->code_email_subject = true;
        }
        $this->form_message = get_option( 'cloudbridge2fa-code-input-text-addon', null );
        if ( $this->form_message === null ) {
            $this->form_message = '';
        } else {
            $this->form_message = sanitize_textarea_field( $this->form_message );
        }
        $this->email_message = get_option( 'cloudbridge2fa-code-email-text-addon', null );
        if ( $this->email_message === null ) {
            $this->email_message = '';
        } else {
            $this->email_message = sanitize_textarea_field( $this->email_message );
        }
        $this->allow_cookie = $allow_cookie;
        $this->nonce = $nonce;
        $this->blog_title = get_bloginfo( 'name' );
        $this->setErrorMessage( '' );
        $this->isFromWordPress = false;
    }

    /**
     * Sets error message.
     *
     * The error message is displayed, if non-empty, on the login screen.
     *
     * @param string $message
     */
    public function setErrorMessage( string $message ) {
        $this->error_message = $message;
    }

    /**
     * Setup indicator if we're coming from WordPress.
     *
     * @param bool $fromWordPress
     */
    public function setFromWordPress( bool $fromWordPress ) {
        $this->isFromWordPress = $fromWordPress;
    }

    /**
     * Are we on HTTPS? :-)
     *
     * @return bool
     */
    public function isSSL() {
        if ( function_exists('is_ssl' ) && is_ssl() ) {
            return( true );
        }
        if ( ! empty( $_SERVER['HTTP_CF_VISITOR'] ) ) {
            $v = json_decode( $_SERVER['HTTP_CF_VISITOR'], true );
            if ( is_array( $v ) && ! empty( $v['scheme'] ) && $v['scheme'] === 'https' ) {
                return( true );
            }
        }
        if ( ! empty( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https' ) {
            return( true );
        }
        return( false );
    }
    /**
     * Set user data for 2FA form.
     *
     * @param WP_User|null $user
     * @param string $user_name
     */
    public function setUser( $user, string $user_name = '' ) {
        $this->user = $user;
        if ( ! empty( $user_name ) ) {
            $this->username = $user_name;
        }
    }

    /**
     * Set "allow cookie" flag.
     *
     * @param bool $allow_cookie
     * @return void
     */
    public function setAllowCookie( bool $allow_cookie ) {
        $this->allow_cookie = $allow_cookie;
    }
    /**
     * Get "allow cookie" flag.
     *
     * @return bool
     */
    public function getAllowCookie() {
        return( $this->allow_cookie );
    }

    /**
     * Return currently set username.
     *
     * @return string
     */
    public function getUsername() {
        return( $this->username );
    }

    /**
     * Figure out our cookie hash.
     *
     * @return false|string
     */
    public function getCookieHash() {
        $user_hash = $cookie_hash = '';
        if ( $this->user->data !== null ) {
            if (! empty( $this->user->data->user_login ) ) {
                $user_hash = $this->user->data->user_login;
            } elseif ( ! empty( $this->user->data->user_email ) ) {
                $user_hash = $this->user->data->user_email;
            } elseif ( ! empty( $this->user->data->user_nicename ) ) {
                $user_hash = $this->user->data->user_nicename;
            }
            if ( ! empty( $this->user->data->user_pass ) ) {
                $user_hash .= $this->user->data->user_pass;
            } else {
                if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                    error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . '(' . __FUNCTION__ . '): No password?' );
                }
            }
        }
        if ( empty( $user_hash ) ) {
            error_log( '[CB2FA] ' . basename( __FILE__ ) . '(' . __FUNCTION__ . '): No available sources for user hash value' );
            return( false );
        }
        $hash_algos = hash_algos();
        if ( is_array( $hash_algos ) ) {
            try {
                if ( in_array( 'sha3-512', $hash_algos ) ) {
                    $cookie_hash = hash( 'sha3-512', $user_hash );
                } elseif ( in_array( 'sha3-256', $hash_algos ) ) {
                    $cookie_hash = hash( 'sha3-256', $user_hash );
                } elseif ( in_array( 'sha512', $hash_algos ) ) {
                    $cookie_hash = hash( 'sha512', $user_hash );
                } elseif ( in_array( 'sha256', $hash_algos ) ) {
                    $cookie_hash = hash( 'sha256', $user_hash );
                } else {
                    $cookie_hash = wp_hash( $user_hash, 'secure_auth' );
                }
            } catch ( \Exception $e ) {
                if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                    error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . '(' . __FUNCTION__ . '): hash() exception "' . $e->getMessage() . '"' );
                }
                $cookie_hash = wp_hash( $user_hash, 'secure_auth' );
            }
        }
        if ( empty( $cookie_hash ) ) {
            error_log( '[CB2FA] ' . basename( __FILE__ ) . '(' . __FUNCTION__ . '): Unable to create cookie hash value' );
            return( false );
        }
        if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
            error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . '(' . __FUNCTION__ . '): Cookie hash "' . $cookie_hash . '"' );
        }
        return( $cookie_hash );
    }

    /**
     * Fetch timestamp (now) + cookie lifetime.
     *
     * @return int
     */
    public function getCookieTime() {
        return( time() + ( $this->cookie_lifetime * 86400 ) );
    }

    /**
     * Setup correct e-mail content type.
     *
     * @return string
     */
    public function set_html_mail_content_type() {
        return( 'text/html' );
    }

    /**
     * Setup "name" portion in "From:" e-mail header
     * @return string
     */
    public function set_mail_from_name() {
        return( CB2FA_PLUGINNAME_HUMAN );
    }

    public function send_2fa_code( string $the_code ) {
        if ( empty( $this->user->data->user_email ) ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . '(' . __FUNCTION__ . '): No e-mail address?' );
            }
            return( false );
        }
        // Setup subject
        $email_subject = '[CB2FA]';
        if ( ! empty( $this->blog_title ) ) {
            $email_subject .= ' ' . $this->blog_title;
        }
        $email_title = $email_subject;
        $email_subject .= ' ' . __( 'OTP code', 'cloudbridge-2fa' );
        if ( $this->code_email_subject ) {
            $email_subject .= ': ' . $the_code;
        }
        // Setup body
        $email_body = '<!DOCTYPE html><html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8" /><meta charset="utf-8">' .
                      '<title>' . esc_html( $email_subject ) . '</title></head>' .
                      '<body><main>';
        $email_body .= '<style>';
        $email_body_css = @ file_get_contents( dirname( __FILE__ ) . '/../css/simple.min.css' );
        if ( $email_body_css === false ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . '(' . __FUNCTION__ . '): Unable to read "' . dirname( __FILE__ ) . '/css/simple.min.css' . '"' );
            }
            $email_body_css = 'body { background-color: white !important; color: black !important; font-size: 14px !important; }';
        }
        $email_body .= $email_body_css;
        // $email_body .= '.pin_code_digit { display:inline !important;text-align:center !important; border: 1px solid #000; background-color: #ccc !important; color: black !important; padding: 15px; max-width:75% !important;margin:0 auto !important; border-radius: 5px !important; font-size: 1.9em !important; font-family: monospace;user-select: all !important;}';
        $email_body .= '</style>';
        $email_body .= '<h3 style="text-align:center !important;">' .
                           esc_html( $email_title ) .
                       '</h3>' . "\n\n";
        $email_body .= '<h4 style="text-align:center !important;">' .
                           esc_html__( 'Login OTP code', 'cloudbridge-2fa' ) . ':' .
                           '<br/>' .
                           esc_html( $the_code ) .
                       '</h4>' . "\n\n";
        //$email_body .= '<pre style="font-size:1.9em !important; line-height:2em !important; text-align: center !important; user-select: all !important;">';
        $email_body .= '<div class="notice" style="max-width:75% !important;margin:0 auto !important;margin-top:20px !important;font-size:1.9em !important;text-align:center !important;user-select:all !important;font-family: monospace !important;">';
        for( $c = 0; $c < strlen( $the_code ); $c++ ) {
            $email_body .= '&nbsp;' . esc_html( $the_code[$c] ) . '&nbsp;';
        }
        $email_body .= '</div>' . "\n\n";
        $email_body .= '<div class="notice" style="max-width:75% !important;margin:0 auto !important;margin-top:20px !important;">';
        $email_body .= esc_html__( 'Someone has requested that an OTP code be sent to the e-mail ' .
                                   'address associated with an account on this WordPress site. ' .
                                   'If this was not you, you should change your password on this ' .
                                   'site as soon as possible', 'cloudbridge-2fa' );
        $email_body .= '</div><br/><br/>'. "\n\n";
        $email_body .= '<div class="notice" style="text-align:center !important;max-width:75% !important;margin:0 auto !important;">';
        $email_body .= esc_html__( 'The OTP code is valid for', 'cloudbridge-2fa' ) .
                       ' ' . (int)$this->code_lifetime . ' ' .
                       esc_html__( 'minutes', 'cloudbridge-2fa' );
        $email_body .= '</div><br/><br/>' . "\n\n";
        if ( ! empty( $this->email_message ) ) {
            $email_body .= '<div class="notice" style="text-align:center !important;max-width:75% !important;margin:0 auto !important;">' . esc_html( $this->email_message ) . '</div><br/><br/>';
        }
        $email_body .= '<div style="text-align: center !important;"><small>';
        $email_body .= esc_html__( '2FA provided by', 'cloudbridge-2fa' ) . ' ' . esc_html( CB2FA_PLUGINNAME_HUMAN );
        $email_body .= '</small></div>' . "\n\n";
        $email_body .= '</main></body></html>';
        // Handle WordPress quirks
        add_filter( 'wp_mail_content_type', [$this, 'set_html_mail_content_type'] );
        add_filter( 'wp_mail_from_name', [$this, 'set_mail_from_name'] );
        // Send e-mail
        wp_mail( $this->user->data->user_email,
                 $email_subject,
                 $email_body );
        // "Unhandle" WordPress quirks ;-)
        remove_filter( 'wp_mail_from_name', [$this, 'set_mail_from_name'] );
        remove_filter( 'wp_mail_content_type', [$this, 'set_html_mail_content_type'] );
    }

    /**
     * Draw HTML form with CSS and Javascript.
     */
    public function drawForm() {
        // Use site title from WordPress
        if ( ! empty( $this->blog_title ) ) {
            $title = ' &lsaquo; ' . esc_html( $this->blog_title );
        } else {
            $title = '';
        }
        // Figure out a good place to "try again"
        if ( ! empty( $_REQUEST['redirect_to'] ) ) {
            $redirect_to = sanitize_url( $_REQUEST['redirect_to'], array( 'http', 'https' ) );
        } else {
            $redirect_to = site_url();
        }
        // Draw some basic HTML
        echo '<!DOCTYPE html>' .
             '<html>' .
             '<head>' .
                 '<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />' .
                 '<meta charset="utf-8" />' .
                 '<meta name="viewport" content="width=device-width,initial-scale=1"/>' .
                 '<link href="' . esc_url( plugins_url( 'css/simple.min.css', dirname(__FILE__) ) ) .
                      '" rel="stylesheet" />' .
                '<link href="' . esc_url( plugins_url( 'css/cb2fa-public.css', dirname(__FILE__) ) ) .
                      '" rel="stylesheet" />' .
                 '<title>' .
                     esc_html( 'CB2FA' ) . $title .
                 '</title>' .
             '</head> ' . "\n" .
             '<body>' . "\n" .
             '<script>' .
                 '
                  var cb2fa_form = null;
                  var cb2fa_pincode = null;
                  var cb2fa_submit = null;

                  function cb2fa_setup() {
                     cb2fa_form = document.getElementById("cb2fa_form");
                     cb2fa_pincode = document.getElementById("cb2fa_pincode");
                     cb2fa_submit = document.getElementById("cb2fa_submit");
                     if (cb2fa_submit) {
                         cb2fa_submit.addEventListener("click", function(e) {
                             if (cb2fa_form) {
                                 if (cb2fa_pincode && cb2fa_pincode.value.length > 0) {
                                     cb2fa_form.submit();
                                 }
                             }
                         });
                     }
                     if (cb2fa_pincode) {
                         cb2fa_pincode.addEventListener("keydown", cb2fa_pincode_keydown);
                         cb2fa_pincode.addEventListener("paste", cb2fa_pincode_paste);
                         cb2fa_pincode.focus();
                     }
                     window.addEventListener("keydown", cb2fa_keydown);
                 }
                 function cb2fa_keydown(e) {
                     if (e.defaultPrevented) {
                         return;// already handled
                     }
                     if (e.key == "Enter") {
                         if (e.target.form == cb2fa_form) {
                             e.preventDefault();
                             cb2fa_submit.click();
                             return;
                         }
                     }
                 }
                 function cb2fa_pincode_paste(e) {
                     var pasteData = e.clipboardData.getData("text/plain");
                     cb2fa_pincode.value = pasteData.replace(/\s+/g, "");
                     e.preventDefault();
                 }
                 function cb2fa_pincode_keydown(e) {
                     if (e.key == " " || e.key == "Spacebar") {
                         e.preventDefault();
                         return(false);
                     }
                     return(true);
                 }
                 if (document.readyState === "complete" ||
                        (document.readyState !== "loading" && !document.documentElement.doScroll)) {
                     cb2fa_setup();
                 } else {
                     document.addEventListener("DOMContentLoaded", cb2fa_setup);
                 }
             </script>';
        if ( ! empty( $this->blog_title ) ) {
            echo '<h3 class="cb2fa-otp-site-header">' . esc_html( $this->blog_title ) . '</h3>';
        }
        if ( empty( $_REQUEST['cb2fa_nonce'] ) || $_REQUEST['cb2fa_nonce'] != $this->nonce ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . '(' . __FUNCTION__ . '): Nonce mismatch, or no nonce' );
            }
            $basic_checks_failed = true;
        } elseif ( empty( $this->username ) ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . '(' . __FUNCTION__ . '): No username' );
            }
            $basic_checks_failed = true;
        } elseif ( ! $this->isFromWordPress && ( empty( $_REQUEST['cb2fa_timer'] ) || $_REQUEST['cb2fa_timer'] > time() ) ) {
            if ( defined( 'CB2FA_DEBUG' ) && CB2FA_DEBUG ) {
                error_log( '[CB2FA_DEBUG] ' . basename( __FILE__ ) . '(' . __FUNCTION__ . '): Timer mismatch' );
            }
            $basic_checks_failed = true;
        } else {
            $basic_checks_failed = false;
        }
        echo '<main>';
        echo '<h4 class="cb2fa-otp-plugin-header">' . esc_html( CB2FA_PLUGINNAME_HUMAN ) . '</h4>';
        echo '<div class="notice">';
        if ( $basic_checks_failed ) {
            echo '<h5 class="cb2fa-error-message">' . esc_html__( 'An error occurred, please try again', 'cloudbridge-2fa' ) . '</h5>';
            echo '<div class="cb2fa-center"><a class="cb2fa-link" href="' . esc_url( $redirect_to ) . '">' . esc_html( $redirect_to ) . '</a></div>';
        } else {
            if ( ! empty( $this->error_message ) ) {
                echo '<h5 class="cb2fa-center">' . esc_html( $this->error_message ) . '</h5>';
            } else {
                echo '<div class="cb2fa-center">';
                echo '<p>' . esc_html__( 'An OTP code has been sent to the e-mail address associated with the account', 'cloudbridge-2fa' ) . '.</p>';
                echo '<p>' . esc_html__( 'The code is valid for', 'cloudbridge-2fa' ) .
                             ' ' . esc_html( $this->code_lifetime ) . ' ' .
                             esc_html__( 'minute(s)', 'cloudbridge-2fa' ) .
                    '.</p>';
                echo '</div>';
            }
            echo '<div class="cb2fa-center">';
            echo '<form id="cb2fa_form" method="post" action="' . esc_url( $this->our_url ) . '">';
            if ( ! empty( $redirect_to ) ) {
                echo '<input type="hidden" name="redirect_to" value="' . esc_url( $redirect_to ) . '" />';
            }
            echo '<input type="hidden" name="cb2fa_nonce" value="' . esc_html( $this->nonce ) . '" />';
            echo '<input type="hidden" name="cb2fa_timer" value="' . esc_html( time() ) . '" />';
            echo '<input type="hidden" name="cb2fa_user" value="' . esc_html( $this->username ) . '" />';
            echo '<label for="cb2fa_pincode" style="margin-top:48px;">' . esc_html__( 'Code', 'cloudbridge-2fa' ) . ':</label>';
            echo '<input type="text" tabindex="1" name="cb2fa_pincode" id="cb2fa_pincode" size="6" maxlength="128" class="cb2fa-center" value="" />';
            echo '<div style="margin-top:48px;"><input type="button" name="cb2fa_submit" id="cb2fa_submit" value="OK" /></div>';
            if ( $this->allow_cookie ) {
                if ( ! empty( $_POST['cb2fa_cookie'] ) ) {
                    $our_cookie = sanitize_text_field( $_POST['cb2fa_cookie'] );
                } else {
                    $our_cookie = '';
                }
                $cookie_checked = ( ! empty( $our_cookie ) && $our_cookie == 'cb2fa_cookie' ? 'checked ':'' );
                echo '<div style="margin-top:24px;">';
                echo '<input tabindex="2" aria-description="' .
                         esc_html__( 'Enable checkbox to avoid having to enter an OTP code for future logins', 'cloudbridge-2fa' ) .
                     '" type="checkbox" name="cb2fa_cookie" id="cb2fa_cookie" value="cb2fa_cookie" ' . $cookie_checked . '/>&nbsp;';
                echo '<label for="cb2fa_cookie">' . esc_html__( 'Remember me in this browser', 'cloudbridge-2fa' ) . '</label>';
                echo '</div>';
            }
            echo '</form>';
            echo '</div>';
            echo '<div class="cb2fa-center" style="margin-top:48px;">';
            if ( ! empty( $this->form_message ) ) {
                echo '<mark style="display:block;margin-bottom:16px !important;">' . esc_html( $this->form_message ) . '</mark>';
            }
            echo '<small>' .
                 '<p style="max-width:75% !important;margin: 0 auto !important;"><strong>' .
                  esc_html__( 'If the e-mail message with the code does not arrive, you may attempt to login again by clicking on the below link', 'cloudbridge-2fa' ) .
                  '</strong><br/>' .
                  '<a tabindex="3" class="cb2fa-link" href="' . esc_url( $redirect_to ) . '">' . esc_html__( 'WordPress Login', 'cloudbridge-2fa' ) . '</a>' .
                  '</small></p>';
            echo '</div>';
        }
        echo '</div>';

        echo '</main>';
        echo '</body>' .
             '</html>';
    }
} // class Cloudbridge_2FA_Login


} // ! class_exists( 'Cloudbridge_2FA_Login' )

// class_cb2fa_login.inc.php
