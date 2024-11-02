# Yubikey TOTP Albert Launcher Plugin

This plugin allows you to quickly fetch and copy to clipboard TOTP codes stored on Yubikeys. 
It's an alternative to Yubico Authenticator.

By default, trigger word is `otp`.

After confirming entry, code will be copied to clipboard. If an entry requires touch, you 
will first be prompted to touch your yubikey in a system notification.

If TOTP on your yubikey is password-protected, this plugin REQUIRES password to be saved using
`ykman` console tool or `Yubico Authenticator` GUI tool, as it cannot prompt for a password.

If you have an icon set loaded into `Yubico Authenticator`, this plugin will try to fetch it
and use it in Albert.

When using with multiple Yubikeys, there are settings you can tweak how it should operate.
Plugin can either:

- List entries only from first detected yubikey (ability to use a specific yubikey by serial number
  is coming soon).
- List entries from all detected Yubikeys, separately.
- List entries from all detected Yubikeys, but merged by entry name and TOTP code.
  This option will not merge entries requiring touch.
- List entries from all detected Yubikeys, but merged by entry name only.
  This will also merge entries requiring touch.