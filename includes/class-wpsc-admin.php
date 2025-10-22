<?php
/**
 * Admin settings for WP Session Control.
 */

if (!defined('ABSPATH')) {
    exit;
}

class WPSC_Admin
{
    const OPTION_GROUP = 'wpsc_settings';
    const PAGE_SLUG = 'wpsc-session-control';

    /**
     * Register admin hooks.
     */
    public static function init(): void
    {
        if (!is_admin()) {
            return;
        }

        add_action('admin_menu', [__CLASS__, 'register_menu']);
        add_action('admin_init', [__CLASS__, 'register_settings']);
        add_filter('plugin_action_links_' . WPSC_PLUGIN_BASENAME, [__CLASS__, 'add_settings_link']);

        // Per-user override field on user profile/edit screens
        add_action('show_user_profile', [__CLASS__, 'render_user_override_field']);
        add_action('edit_user_profile', [__CLASS__, 'render_user_override_field']);
        add_action('personal_options_update', [__CLASS__, 'save_user_override_field']);
        add_action('edit_user_profile_update', [__CLASS__, 'save_user_override_field']);
    }

    /**
     * Add "Settings" link on the plugins screen.
     */
    public static function add_settings_link(array $links): array
    {
        $url = admin_url('options-general.php?page=' . self::PAGE_SLUG);
        $links[] = '<a href="' . esc_url($url) . '">' . esc_html__('Settings', 'wp-session-control') . '</a>';

        return $links;
    }

    /**
     * Register options page.
     */
    public static function register_menu(): void
    {
        add_options_page(
            __('Session Control', 'wp-session-control'),
            __('Session Control', 'wp-session-control'),
            'manage_options',
            self::PAGE_SLUG,
            [__CLASS__, 'render_settings_page']
        );
    }

    /**
     * Register settings, sections, and fields.
     */
    public static function register_settings(): void
    {
        register_setting(
            self::OPTION_GROUP,
            WPSC_Settings::OPTION_KEY,
            [
                'sanitize_callback' => [WPSC_Settings::class, 'sanitize'],
                'default' => WPSC_Settings::get_default_options(),
            ]
        );

        add_settings_section(
            'wpsc_general',
            __('General Settings', 'wp-session-control'),
            function (): void {
                echo '<p>' . esc_html__('Configure how long a login is valid and how many simultaneous logins a user may have.', 'wp-session-control') . '</p>';
            },
            self::PAGE_SLUG
        );

        add_settings_field(
            'session_lifetime_minutes',
            __('Session lifetime (minutes)', 'wp-session-control'),
            [__CLASS__, 'render_session_lifetime_field'],
            self::PAGE_SLUG,
            'wpsc_general'
        );

        add_settings_field(
            'max_concurrent_sessions',
            __('Max concurrent sessions', 'wp-session-control'),
            [__CLASS__, 'render_max_sessions_field'],
            self::PAGE_SLUG,
            'wpsc_general'
        );

        add_settings_field(
            'termination_notice_content',
            __('Session limit notice content', 'wp-session-control'),
            [__CLASS__, 'render_termination_notice_field'],
            self::PAGE_SLUG,
            'wpsc_general'
        );

        add_settings_field(
            'termination_notice_heading',
            __('Session limit notice heading', 'wp-session-control'),
            [__CLASS__, 'render_termination_notice_heading_field'],
            self::PAGE_SLUG,
            'wpsc_general'
        );
    }

    /**
     * Render lifetime input.
     */
    public static function render_session_lifetime_field(): void
    {
        $value = (int) WPSC_Settings::get_option('session_lifetime_minutes');
        echo '<input type="number" min="1" class="small-text" id="session_lifetime_minutes" name="' . esc_attr(WPSC_Settings::OPTION_KEY) . '[session_lifetime_minutes]" value="' . esc_attr($value) . '" />';
        echo '<p class="description">' . esc_html__('Time before a user is prompted to log in again.', 'wp-session-control') . '</p>';
    }

    /**
     * Render concurrent sessions input.
     */
    public static function render_max_sessions_field(): void
    {
        $value = (int) WPSC_Settings::get_option('max_concurrent_sessions');
        echo '<input type="number" min="0" class="small-text" id="max_concurrent_sessions" name="' . esc_attr(WPSC_Settings::OPTION_KEY) . '[max_concurrent_sessions]" value="' . esc_attr($value) . '" />';
        echo '<p class="description">' . esc_html__('How many devices/browsers a user may be logged into at once. Set to 0 for unlimited.', 'wp-session-control') . '</p>';
    }

    /**
     * Render termination notice WYSIWYG field.
     */
    public static function render_termination_notice_field(): void
    {
        $option_key = WPSC_Settings::OPTION_KEY . '[termination_notice_content]';
        $content = (string) WPSC_Settings::get_option('termination_notice_content');

        wp_editor(
            $content,
            'wpsc_termination_notice_content',
            [
                'textarea_name' => $option_key,
                'textarea_rows' => 5,
                'editor_height' => 200,
                'media_buttons' => false,
            ]
        );

        echo '<p class="description">' . esc_html__('Shown in a modal when older sessions are terminated for this user. Leave blank for a default message.', 'wp-session-control') . '</p>';
    }

    /**
     * Render termination notice heading field.
     */
    public static function render_termination_notice_heading_field(): void
    {
        $value = (string) WPSC_Settings::get_option('termination_notice_heading');
        echo '<input type="text" class="regular-text" id="termination_notice_heading" name="' . esc_attr(WPSC_Settings::OPTION_KEY) . '[termination_notice_heading]" value="' . esc_attr($value) . '" />';
        echo '<p class="description">' . esc_html__('Displayed as the modal heading when sessions are removed.', 'wp-session-control') . '</p>';
    }

    /**
     * Render the settings page markup.
     */
    public static function render_settings_page(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('Session Control', 'wp-session-control'); ?></h1>
            <form action="<?php echo esc_url(admin_url('options.php')); ?>" method="post">
                <?php
                settings_fields(self::OPTION_GROUP);
                do_settings_sections(self::PAGE_SLUG);
                submit_button();
                ?>
            </form>
        </div>
        <?php
    }
    /**
     * Render the per-user Session Control override on the user profile screen.
     */
    public static function render_user_override_field($user): void
    {
        if (!($user instanceof WP_User)) {
            $user = get_userdata($user);
            if (!($user instanceof WP_User)) {
                return;
            }
        }
        $checked = get_user_meta($user->ID, 'wpsc_disable_for_user', true) ? 'checked' : '';
        ?>
        <h2><?php echo esc_html__('Session Control', 'wp-session-control'); ?></h2>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row">
                    <label for="wpsc_disable_for_user"><?php echo esc_html__('Disable Session Control for this user', 'wp-session-control'); ?></label>
                </th>
                <td>
                    <label>
                        <input type="checkbox" name="wpsc_disable_for_user" id="wpsc_disable_for_user" value="1" <?php echo $checked; ?> />
                        <?php echo esc_html__('Skip session limits, device flags, and modals for this user.', 'wp-session-control'); ?>
                    </label>
                </td>
            </tr>
        </table>
        <?php
    }

    /**
     * Save the per-user override flag from the profile screen.
     */
    public static function save_user_override_field($user_id): void
    {
        // Capability check
        if (!current_user_can('edit_user', $user_id)) {
            return;
        }
        // Sanitize checkbox
        $val = isset($_POST['wpsc_disable_for_user']) && $_POST['wpsc_disable_for_user'] ? '1' : '';
        if ($val === '1') {
            update_user_meta($user_id, 'wpsc_disable_for_user', '1');
        } else {
            delete_user_meta($user_id, 'wpsc_disable_for_user');
        }
        // Clear user meta cache to reflect immediately
        wp_cache_delete($user_id, 'user_meta');
        if (function_exists('clean_user_cache')) {
            clean_user_cache($user_id);
        }
    }
}
