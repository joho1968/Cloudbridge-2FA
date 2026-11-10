=== Cloudbridge 2FA ===
Contributors: joho68, webbplatsen
Donate link: https://code.webbplatsen.net/wordpress/cloudbridge-2fa/
Tags: security, 2fa, passwords
Requires at least: 5.4
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 2.0.2
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Uncomplicated 2FA plugin for WordPress with e-mail OTP and authenticator app support.

== Description ==

This plugin provides uncomplicated 2FA functionality for WordPress. It will
allow you to require a second, one time password or OTP, code to be entered
when certain (or all) users attempt to log in to WordPress.

The plugin supports two factor methods:

* six-digit codes sent by e-mail
* standards-based authenticator apps using TOTP

The e-mail code has a limited lifetime (defaults to 15 minutes). Once a code
has been consumed, it is considered invalid.

Authenticator app setup is handled from the user's own profile page. The plugin
provides a QR code, a manual setup key, and recovery codes for when the
authenticator app is not available.

You may configure that only certain roles are required to use 2FA, and it is
recommended that you enable 2FA for those users with privileged access.

You may also configure the plugin to allow certain roles to enable an OTP code
bypass, which sets an account-specific cookie in that user's web browser.
Several users can share a browser while keeping separate trust settings.
Trusted-browser tokens expire on the server and are invalidated when the
account password changes.

You can add custom text to the OTP code entry form, and you can add custom text
to the OTP code e-mail message.
OTP e-mails include HTML and plain-text versions with the same code, verification
reference, expiry information, and custom text.

The plugin can be configured to allow it to be handled/managed only by specific
users, thus making it harder for someone to accidentally or intentionally
deactivate it. The implemented solution for this is by no means waterproof. If
someone, for example, has access to your WordPress installation by means of FTP
or similar, the plugin files can be physically removed (or moved out of your
WordPress installation), which basically deactivates the plugin as well.


After upgrading to 2.0.2, users must complete 2FA once to trust a browser again.
Existing pending login attempts must be restarted. Protected interactive logins
must use the WordPress login page. Custom forms and XML-RPC password logins
cannot complete CB2FA challenges. REST application-password authentication
continues to be handled separately by WordPress.
E-mail codes use the verification reference shown on the login screen. New
messages are limited to one per account per minute until 2FA succeeds. Successful
verification clears the mail cooldown. Existing codes keep their original expiry
time when switching factors.

== Installation ==

This section describes how to install the plugin and get it working.

1. Upload the contents of the `cloudbridge-2fa` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Configure the plugin settings

= Is the plugin locale aware =

Cloudbridge 2FA uses standard WordPress functionality to handle localization/locale. The native language localization of the plugin is English. It has been translated to Swedish by the author.

= Are there any incompatibilities =

Protected password logins must use the WordPress login page. Custom forms and
XML-RPC password logins cannot complete CB2FA challenges. REST application-password
authentication is handled separately by WordPress.

== Changelog ==

= 2.0.2 =
* Fixed overlapping login attempts invalidating e-mail codes; each attempt now has a separate browser-bound challenge
* Fixed e-mail cooldown renewal after expiry and cleared the cooldown after successful 2FA
* Added PHP log diagnostics for e-mail cooldown, storage, and sending failures
* Added a plain-text alternative to HTML OTP e-mails
* Fixed large OTP digits overflowing narrow e-mail layouts
* Preserved delivered e-mail codes when switching factors and added matching verification references
* Enforced fixed challenge expiry, resend limits, and server-side trusted-browser expiry
* Prevented concurrent OTP/recovery-code reuse and rejected verification when state cannot be saved
* Ran factor handling after normal WordPress and third-party authentication checks
* Preserved WordPress Remember me, corrected recovery-code case handling, and hardened login input handling
* Fixed uninstall cleanup, restricted-browser storage handling, and Swedish plural translations
* Removed credential and sensitive option-value debug logging
* Handled malformed import entries without PHP warnings and limited configuration import diagnostics
* Made existing verification endpoint access guards detectable by Plugin Check without changing login behavior

= 2.0.1 =
* Fixed a settings-page regression where saving one tab could unset values on another tab
* Fixed the Bypass 2FA tab layout after the recent admin UI changes
* Restored returning to the active settings tab after saving
* Sent expired or stale login verification attempts back to the WordPress login screen so the user can start over cleanly

= 2.0.0 =
* Verified with PHP 7.4, 8.1, 8.2, 8.3, and 8.4
* Added authenticator app support using standards-based TOTP
* Added recovery codes for authenticator-enabled accounts
* Added QR code and manual setup key support to the user profile
* Reworked the admin settings so authenticator-app and e-mail OTP settings are easier to find
* Hardened redirect handling in login and OTP completion flows
* Added CSRF protection to configuration import

= 1.0.5 =
* Verified with WordPress 6.8 and 6.9

= 1.0.4 =
* Verified with WordPress 6.7
* Verified with Plugin Check (PCP)
* Corrected some checks for **uninstall.php** and made it more WP-CLI compatible

= 1.0.3 =
* Fix some incorrect links in plugin and **README.txt**

= 1.0.2 =
* Fix of minor PHP warning

= 1.0.1 =
* Fix of minor PHP warning

= 1.0.0 =
* Initial release

== Credits ==

The Cloudbridge 2FA Plugin was written by Joaquim Homrighausen while converting caffeine into code.

Cloudbridge 2FA is sponsored by [WebbPlatsen i Sverige AB](https://webbplatsen.se), Sweden.

Commercial support and customizations for this plugin is available from WebbPlatsen i Sverige AB in Sweden.

If you find this plugin useful, the author is happy to receive a donation, good review, or just a kind word.

If there is something you feel to be missing from this plugin, or if you have found a problem with the code or a feature, please do not hesitate to reach out to support@webbplatsen.se.

This plugin can also be downloaded from [code.webbplatsen.net](https://code.webbplatsen.net/wordpress/cloudbridge-2fa/) and [GitHub](https://github.com/joho1968/Cloudbridge-2FA)

More detailed documentation is available at [https://code.webbplatsen.net/documentation/cloudbridge-2fa/](https://code.webbplatsen.net/documentation/cloudbridge-2fa/)

Kudos to Kev Quirk for [Simple CSS](https://simplecss.org/)

QR code setup on the authenticated profile page uses QR Code Generator for JavaScript by Kazuhiko Arase (MIT license).
