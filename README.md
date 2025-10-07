# WP Session Control

A WordPress plugin that enforces limits on the number of concurrent user sessions and integrates with Amazon Cognito to ensure proper logout behaviour across devices.

## Features

- **Concurrent Session Limits**  
  Restrict the number of simultaneous logins per user (e.g., only allow 1 active session).

- **Session Management Modal**  
  When an old session is killed, the user sees a modal listing active sessions and why the logout occurred.

- **Cognito Integration**  
  Handles front-channel logout with Amazon Cognito. If a session is terminated, the browser is redirected to Cognito’s `/logout` endpoint to clear SSO cookies, preventing silent re-logins.

- **Device Tracking**  
  Each session is mapped to a browser/device ID so that specific sessions can be terminated and tracked reliably.

- **Fallback Handling**  
  If a session cannot be mapped, the plugin falls back to flagging all devices except the current one.

- **Debugging Tools**  
  Verbose logging to the browser console (when debugging is enabled) plus special query parameters (`?wpsc=die`, `?wpsc=die_flag`, etc.) to trace the logout flow step by step.

## Requirements

- WordPress 6.x
- WooCommerce (optional, for sites using subscription/customer flows)
- A configured Amazon Cognito User Pool with Hosted UI
- The Cognito App Client must have a valid **Sign-out URL** pointing to `<your-site>/logout`

## Installation

1. Copy the plugin into your WordPress `wp-content/plugins` directory.
2. Activate **WP Session Control** from the WordPress admin.
3. Configure your Cognito domain, Client ID, and other options via ACF fields or plugin settings.

## Development

- `WPSC_Session_Manager` is the core class handling session enforcement, device mapping, and logout interception.
- Debugging can be enabled by setting the constant:
  ```php
  define('WPSC_DEBUG', true);
  ```
- For development convenience, an `.vscode/sftp.json` file is included (ignored in production) to allow automatic SFTP deployment on save.

## License

MIT License
