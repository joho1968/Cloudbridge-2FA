=== Cloudbridge 2FA ===
Contributors: joho68, webbplatsen
Donate link: https://code.webbplatsen.net/wordpress/cloudbridge-2fa/
Tags: security, 2fa, passwords
Requires at least: 5.4.0
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 1.0.5
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Uncomplicated 2FA plugin for WordPress. Tested with WordPress 5.5+ and PHP 7.4+.

== Description ==

This plugin provides uncomplicated 2FA plugin for WordPress. It will allow you
to require a second, one time password or OTP, code to be entered when certain
(or all) users attempt to log in to WordPress.

It will send a six-digit code via e-mail to the user attempting to log in. The
code has a limited lifetime (defaults to 15 minutes). Once a code has been
consumed, it is considered invalid.

You may configure that only certain roles are required to use 2FA, and it is
recommended that you enable 2FA for those users with privileged access.

You may also configure the plugin to allow certain roles to enable an OTP code
bypass, which will set a cookie in that user's web browser. The cookies are
partially based on the username, so several users can share the same browser,
but still be required to always enter the OTP code, or bypass it if the cookie
is present.

You can add custom text to the OTP code entry form, and you can add custom text
to the OTP code e-mail message.

The plugin can be configured to allow it to be handled/managed only by specific
users, thus making it harder for someone to accidentally or intentionally
deactivate it. The implemented solution for this is by no means waterproof. If
someone, for example, has access to your WordPress installation by means of FTP
or similar, the plugin files can be physically removed (or moved out of your
WordPress installation), which basically deactivates the plugin as well.

== Installation ==

This section describes how to install the plugin and get it working.

1. Upload the contents of the `cloudbridge-2fa` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Configure the plugin settings

= Is the plugin locale aware =

Cloudbridge 2FA uses standard WordPress functionality to handle localization/locale. The native language localization of the plugin is English. It has been translated to Swedish by the author.

= Are there any incompatibilities =

This is a hard question to answer. There are no known incompatibilities.

== Screenshots ==

1. Sample e-mail content with OTP from Cloudbridge 2FA
2. Sample OTP code entry form when logging into WordPress

== Changelog ==

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
