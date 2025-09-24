<?php
/**
 * Settings helper for WP Session Control.
 */

if (!defined('ABSPATH')) {
    exit;
}

class WPSC_Settings
{
    const OPTION_KEY = 'wpsc_options';

    /**
     * Register hooks.
     */
    public static function init(): void
    {
        // Make sure defaults exist even if activation hook was skipped.
        add_action('plugins_loaded', [__CLASS__, 'ensure_defaults']);
    }

    /**
     * Create initial options on activation.
     */
    public static function activate(): void
    {
        if (false === get_option(self::OPTION_KEY)) {
            add_option(self::OPTION_KEY, self::get_default_options());
        }
    }

    /**
     * Ensure options exist whenever the plugin loads.
     */
    public static function ensure_defaults(): void
    {
        if (false === get_option(self::OPTION_KEY)) {
            add_option(self::OPTION_KEY, self::get_default_options());
        }
    }

    /**
     * Fetch all plugin options with defaults applied.
     */
    public static function get_options(): array
    {
        $saved = get_option(self::OPTION_KEY, []);

        return wp_parse_args((array) $saved, self::get_default_options());
    }

    /**
     * Fetch single option value.
     */
    public static function get_option(string $key)
    {
        $options = self::get_options();

        return $options[$key] ?? null;
    }

    /**
     * Sanitize and persist settings coming from the admin form.
     */
    public static function sanitize(array $input): array
    {
        $options = self::get_options();

        if (isset($input['session_lifetime_minutes'])) {
            $options['session_lifetime_minutes'] = max(1, absint($input['session_lifetime_minutes']));
        }

        if (isset($input['max_concurrent_sessions'])) {
            $raw = trim((string) $input['max_concurrent_sessions']);
            if ($raw === '') {
                $options['max_concurrent_sessions'] = 0;
            } else {
                $options['max_concurrent_sessions'] = max(0, absint($raw));
            }
        }

        if (isset($input['termination_notice_heading'])) {
            $options['termination_notice_heading'] = sanitize_text_field($input['termination_notice_heading']);
        }

        if (isset($input['termination_notice_content'])) {
            $options['termination_notice_content'] = wp_kses_post($input['termination_notice_content']);
        }

        return $options;
    }

    /**
     * Default settings.
     */
    public static function get_default_options(): array
    {
        return [
            'session_lifetime_minutes' => 30,
            'max_concurrent_sessions' => 2,
            'termination_notice_heading' => __('Session Update', 'wp-session-control'),
            'termination_notice_content' => '',
        ];
    }
}
