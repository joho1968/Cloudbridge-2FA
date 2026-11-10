# Swedish translations for Cloudbridge 2FA 2.0.2

- Locale: `sv_SE` (Swedish).
- Current catalogue: **174 active messages**, all translated; no fuzzy entries.

## Files

- [POT: all current source messages](cloudbridge-2fa/languages/cloudbridge-2fa.pot)
- [PO: complete Swedish catalogue](cloudbridge-2fa/languages/cloudbridge-2fa-sv_SE.po)
- [MO: compiled Swedish catalogue](cloudbridge-2fa/languages/cloudbridge-2fa-sv_SE.mo)

## WordPress.org translations

1. Open the plugin's translation project on [Translate WordPress](https://translate.wordpress.org/), choose Swedish and the code branch containing the 2.0.2 English messages.
2. Search for the exact English text below, review the Swedish suggestion, and paste it into the matching field. Preserve placeholders such as `%s` and `%d`, punctuation, and any markup.
3. Alternatively, use **Import Translations** with the complete Swedish PO linked above. Review the full catalogue before importing; it includes existing translations as well as the entries below. Any WordPress.org account can import plugin translations as waiting suggestions; translation editors can also import as current. English messages absent from that branch are ignored. See the [Polyglots import instructions](https://make.wordpress.org/polyglots/handbook/translating/glotpress-translate-wordpress-org/#importing-external-files).

Changed bundled translations are not automatically re-imported into an existing WordPress.org project. The local PO/MO and the online approvals therefore need to be kept aligned. Plugin readme translations are a separate subproject; this guide covers PHP/plugin-header messages. See the [WordPress.org translation-system notes](https://make.wordpress.org/meta/handbook/tutorials-guides/translations/).

## Swedish suggestions to copy

### 1. Uncomplicated 2FA plugin for WordPress

English:

```text
Uncomplicated 2FA plugin for WordPress
```

Swedish:

```text
Okomplicerat tillägg för tvåfaktorsautentisering i WordPress
```

### 2. Login verification is busy. Please try again.

English:

```text
Login verification is busy. Please try again.
```

Swedish:

```text
Inloggningsverifieringen är upptagen. Försök igen.
```

### 3. Unable to save login verification. Please try again.

English:

```text
Unable to save login verification. Please try again.
```

Swedish:

```text
Det gick inte att spara inloggningsverifieringen. Försök igen.
```

### 4. Unable to send a new code. Please wait one minute before trying again.

English:

```text
Unable to send a new code. Please wait one minute before trying again.
```

Swedish:

```text
Det gick inte att skicka en ny kod. Vänta en minut innan du försöker igen.
```

### 5. Authenticator app support requires the PHP extension openssl. Contact the server administrator to enable it.

English:

```text
Authenticator app support requires the PHP extension openssl. Contact the server administrator to enable it.
```

Swedish:

```text
Stöd för autentiseringsappar kräver PHP-tillägget openssl. Kontakta serveradministratören för att aktivera det.
```

### 6. It is recommended that you enable 2FA at least for all roles with elevated privileges

English:

```text
It is recommended that you enable 2FA at least for all roles with elevated privileges
```

Swedish:

```text
Det är rekommenderat att du aktiverar 2FA för åtminstone alla roller som har högre behörighet
```

### 7. This WordPress plugin provides two-factor authentication for WordPress, with support for e-mail OTP and authenticator app TOTP

English:

```text
This WordPress plugin provides two-factor authentication for WordPress, with support for e-mail OTP and authenticator app TOTP
```

Swedish:

```text
Det här WordPress-tillägget ger tvåfaktorsautentisering för WordPress, med stöd för OTP via e-post och TOTP via autentiseringsapp
```

### 8. The plugin is written by Joaquim Homrighausen and sponsored by WebbPlatsen i Sverige AB.

English:

```text
The plugin is written by Joaquim Homrighausen and sponsored by WebbPlatsen i Sverige AB.
```

Swedish:

```text
Tillägget är utvecklat av Joaquim Homrighausen och sponsrat av WebbPlatsen i Sverige AB.
```

### 9. Unable to save authenticator settings. Please try again.

English:

```text
Unable to save authenticator settings. Please try again.
```

Swedish:

```text
Det gick inte att spara inställningarna för autentiseringsappen. Försök igen.
```

### 10. Security check failed, please try again

English:

```text
Security check failed, please try again
```

Swedish:

```text
Säkerhetskontrollen misslyckades, försök igen
```

### 11. Please sign in through the WordPress login page to complete two-factor authentication.

English:

```text
Please sign in through the WordPress login page to complete two-factor authentication.
```

Swedish:

```text
Logga in via WordPress inloggningssida för att slutföra tvåfaktorsautentiseringen.
```

### 12. Unable to create login verification. Please try again.

English:

```text
Unable to create login verification. Please try again.
```

Swedish:

```text
Det gick inte att skapa inloggningsverifieringen. Försök igen.
```

### 13. Verification reference: %s

English:

```text
Verification reference: %s
```

Swedish:

```text
Verifieringsreferens: %s
```

### 14. The code is valid for

English:

```text
The code is valid for
```

Swedish:

```text
Koden är giltig i
```

## Names and URLs to keep unchanged

Keep these names and URLs unchanged in Swedish.

```text
https://code.webbplatsen.net/wordpress/cloudbridge-2fa/
```

```text
WebbPlatsen, Joaquim Homrighausen <joho@webbplatsen.se>
```

```text
https://webbplatsen.se/
```

## Refreshing the catalogue

```bash
wp i18n make-pot cloudbridge-2fa cloudbridge-2fa/languages/cloudbridge-2fa.pot --domain=cloudbridge-2fa
msgmerge --no-fuzzy-matching --update --backup=none cloudbridge-2fa/languages/cloudbridge-2fa-sv_SE.po cloudbridge-2fa/languages/cloudbridge-2fa.pot
msgfmt --check --check-format -o cloudbridge-2fa/languages/cloudbridge-2fa-sv_SE.mo cloudbridge-2fa/languages/cloudbridge-2fa-sv_SE.po
```

After extracting changed source, review any new untranslated entries before compiling or importing.
