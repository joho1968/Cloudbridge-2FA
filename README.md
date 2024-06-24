[![Software License](https://img.shields.io/badge/License-GPL%20v2-green.svg?style=flat-square)](LICENSE) [![PHP 7.2\+](https://img.shields.io/badge/PHP-7.2-blue?style=flat-square)](https://php.net) [![PHP 7.4\+](https://img.shields.io/badge/PHP-7.4-blue?style=flat-square)](https://php.net) [![PHP 8.0\+](https://img.shields.io/badge/PHP-8.0-blue?style=flat-square)](https://php.net) [![PHP 8.1\+](https://img.shields.io/badge/PHP-8.1-blue?style=flat-square)](https://php.net) [![WordPress 5](https://img.shields.io/badge/WordPress-6.4-orange?style=flat-square)](https://wordpress.org)

# Cloudbridge 2FA

Uncomplicated 2FA plugin for WordPress. Tested with WordPress 5.5+ and PHP 7.4+.

## Description
![Cloudbridge 2FA banner](/banner/Cloudbridge-2FA-banner-1544x500.png?raw=true "Cloudbridge 2FA banner")

This plugin provides uncomplicated 2FA functionality for WordPress. It will allow
you to require a second, one time password or OTP, code to be entered when certain
(or all) users attempt to log in to WordPress.

It will send a six-digit code via e-mail to the user attempting to log in. The
code has a limited lifetime (defaults to 15 minutes). Once a code has been
consumed, it is considered invalid.

You may configure that only certain roles are required to use 2FA, and it is
recommended that you enable 2FA for those user with privileged access.

You may also configure the plugin to allow certain roles to enable a OTP code
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

## Installation

This section describes how to install the plugin and get it working.

1. Upload the contents of the `cloudbridge-2fa` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Configure the plugin settings

## Is the plugin locale aware

Cloudbridge 2FA uses standard WordPress functionality to handle localization/locale. The native language localization of the plugin is English. It has been translated to Swedish by the author.

## Are there any incompatibilities

This is a hard question to answer. There are no known incompatibilities.

## Changelog

### 1.0.3
* Fix some incorrect links in plugin and `README.md`

### 1.0.2
* Fix of minor PHP warning

### 1.0.1
* Fix of minor PHP warning

### 1.0.0
* Initial release

## Screenshots
![Cloudbridge 2FA login screen](/screenshots/cloudbridge-2fa-screenshot-login.png?raw=true "Cloudbridge 2FA login screen")

![Cloudbridge 2FA OTP code e-mail](/screenshots/cloudbridge-2fa-screenshot-email.png?raw=true "Cloudbridge 2FA OTP e-mail")

## License

Please see [LICENSE](LICENSE) for a full copy of GPLv2

Copyright (C) 2023 [Joaquim Homrighausen](https://github.com/joho1968).

This file is part of Cloudbridge 2FA (CB2FA). Cloudbridge 2FA is free software.

You may redistribute it and/or modify it under the terms of the GNU General Public License version 2, as published by the Free Software Foundation.

Cloudbridge 2FA is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with the SCFA package. If not, write to:

```
The Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor
Boston, MA  02110-1301, USA.
```

## Credits

The Cloudbridge 2FA Plugin was written by Joaquim Homrighausen while converting caffeine into code.

Cloudbridge 2FA is sponsored by [WebbPlatsen i Sverige AB](https://webbplatsen.se), Sweden.

Commercial support and customizations for this plugin is available from WebbPlatsen i Sverige AB in Sweden.

If you find this plugin useful, the author is happy to receive a donation, good review, or just a kind word.

If there is something you feel to be missing from this plugin, or if you have found a problem with the code or a feature, please do not hesitate to reach out to support@webbplatsen.se.

This plugin can also be downloaded from [code.webbplatsen.net](https://code.webbplatsen.net/wordpress/cloudbridge-2fa/) and [GitHub](https://github.com/joho1968/Cloudbridge-2FA)

More detailed documentation is available at [code.webbplatsen.net/documentation/cloudbridge-2fa](https://code.webbplatsen.net/documentation/cloudbridge-2fa/)

### External references

These links are not here for any sort of endorsement or marketing, they're purely for informational purposes.

* me; :monkey: https://joho.se and https://github.com/joho1968
* WebbPlatsen; https://webbplatsen.se and https://code.webbplatsen.net
* Kudos to Kev Quirk for [Simple CSS](https://simplecss.org/)

Stay safe!
