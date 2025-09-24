<?php
/**
 * Core session management logic.
 */

if (!defined('ABSPATH')) {
    exit;
}

class WPSC_Session_Manager
{
    /**
     * Aggregated debug messages for console output.
     */
    private static $debug_messages = [];

    /**
     * Ensure the modal renders only once per request.
     */
    private static $modal_rendered = false;

    /**
     * Attach runtime hooks.
     */
    public static function init(): void
    {
        add_filter('auth_cookie_expiration', [__CLASS__, 'filter_auth_cookie_expiration'], 10, 3);
        add_action('wp_login', [__CLASS__, 'enforce_concurrent_session_limit'], 10, 2);
        add_action('wp_footer', [__CLASS__, 'print_debug_messages'], 100);
        add_action('admin_footer', [__CLASS__, 'print_debug_messages'], 100);
        add_action('wp_footer', [__CLASS__, 'render_termination_modal'], 50);
        add_action('admin_footer', [__CLASS__, 'render_termination_modal'], 50);
        add_action('template_redirect', [__CLASS__, 'maybe_logout_orphan_session'], 1);
        add_action('admin_init', [__CLASS__, 'maybe_logout_orphan_session'], 1);
        add_action('init', [__CLASS__, 'maybe_logout_for_ajax'], 1);
        add_action('rest_api_init', [__CLASS__, 'register_rest_logout_guard']);
    }

    /**
     * Control how long login cookies remain valid.
     */
    public static function filter_auth_cookie_expiration($length, $user_id, $remember)
    {
        unset($length); // Not used after we override the value.

        $minutes = (int) WPSC_Settings::get_option('session_lifetime_minutes');
        $minutes = max(1, $minutes);
        $seconds = $minutes * MINUTE_IN_SECONDS;

        self::log_debug('Calculated session lifetime.', [
            'user_id' => $user_id,
            'remember' => (bool) $remember,
            'lifetime_minutes' => $minutes,
            'lifetime_seconds' => $seconds,
        ], $user_id);

        /**
         * Filter the calculated session lifetime in seconds.
         *
         * @param int    $seconds  Lifetime in seconds.
         * @param int    $user_id  User identifier.
         * @param bool   $remember Whether the session is a persistent login.
         */
        return (int) apply_filters('wpsc_session_lifetime', $seconds, $user_id, (bool) $remember);
    }

    /**
     * Keep the number of active sessions within the configured limit.
     */
    public static function enforce_concurrent_session_limit(string $user_login, WP_User $user): void
    {
        unset($user_login); // Not needed beyond signature compliance.

        $limit = (int) WPSC_Settings::get_option('max_concurrent_sessions');
        $manager = WP_Session_Tokens::get_instance($user->ID);
        $sessions = $manager->get_all();
        $session_count = count($sessions);

        if ($limit < 1) {
            delete_user_meta($user->ID, 'wpsc_allowed_session_hashes');
            self::log_debug('No session limit enforced (limit < 1).', [
                'user_id' => $user->ID,
                'current_session_count' => $session_count,
            ], $user->ID);
            return; // Unlimited sessions allowed.
        }

        if ($session_count <= $limit) {
            self::store_allowed_session_hashes($user->ID, array_keys($sessions));
            self::log_debug('Session count within limit, no action taken.', [
                'user_id' => $user->ID,
                'limit' => $limit,
                'session_count' => $session_count,
            ], $user->ID);
            return;
        }

        self::log_debug('Session limit exceeded, pruning sessions.', [
            'user_id' => $user->ID,
            'limit' => $limit,
            'session_count' => $session_count,
        ], $user->ID);

        uasort($sessions, static function (array $a, array $b): int {
            $a_login = $a['login'] ?? 0;
            $b_login = $b['login'] ?? 0;

            if ($a_login === $b_login) {
                return 0;
            }

            return ($a_login < $b_login) ? 1 : -1; // Newest first.
        });

        $tokens = array_keys($sessions);
        $allowed = [];

        if (function_exists('wp_get_session_token')) {
            $current_token = wp_get_session_token();
            if (is_string($current_token) && $current_token !== '') {
                $allowed[] = self::hash_session_token($current_token);
            }
        }

        foreach ($tokens as $token) {
            if (in_array($token, $allowed, true)) {
                continue;
            }

            if (count($allowed) >= $limit) {
                break;
            }

            $allowed[] = $token;
        }

        $allowed = array_slice(array_values(array_unique($allowed)), 0, $limit);

        $pruned_sessions = array_intersect_key($sessions, array_flip($allowed));
        $destroyed_sessions = array_diff_key($sessions, $pruned_sessions);

        self::replace_session_tokens($user->ID, $pruned_sessions);
        self::store_allowed_session_hashes($user->ID, array_keys($pruned_sessions));

        if (!empty($destroyed_sessions)) {
            $details = self::prepare_destroyed_session_details($destroyed_sessions);
            self::log_debug('Queuing termination notice.', [
                'user_id' => $user->ID,
                'sessions' => $details,
            ], $user->ID);
            self::queue_termination_notice($user->ID, $details);
            $check = get_user_meta($user->ID, 'wpsc_pending_termination_notice', true);
            self::log_debug('Post-queue notice meta check.', [
                'user_id' => $user->ID,
                'meta_value' => $check,
            ], $user->ID);
        }

        if (function_exists('wp_get_session_token')) {
            $token = wp_get_session_token();
            self::log_debug('Current session token hash.', [
                'user_id' => $user->ID,
                'token_hash' => is_string($token) && $token !== '' ? self::hash_session_token($token) : null,
                'raw_token' => $token,
            ], $user->ID);
        }

        self::log_debug('Pruned sessions to enforce limit.', [
            'user_id' => $user->ID,
            'limit' => $limit,
            'allowed_tokens' => array_keys($pruned_sessions),
            'destroyed_tokens' => array_keys($destroyed_sessions),
        ], $user->ID);
    }

    /**
     * Output any queued debug messages into the browser console.
     */
    public static function print_debug_messages(): void
    {
        if (!self::is_debug_enabled()) {
            return;
        }

        if (empty(self::$debug_messages)) {
            return;
        }

        $messages = wp_json_encode(
            self::$debug_messages,
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
        );
        if (false === $messages) {
            return;
        }

        printf(
            '<script>(function(){if(!window.console){return;}var entries=%1$s;console.group("WP Session Control");entries.forEach(function(entry){if(entry.context){console.log(entry.message, entry.context);}else{console.log(entry.message);}});console.groupEnd();})();</script>',
            $messages
        );

        self::$debug_messages = [];
    }

    /**
     * Render Bootstrap modal informing the user about terminated sessions.
     */
    public static function render_termination_modal(): void
    {
        if (self::$modal_rendered || !is_user_logged_in()) {
            return;
        }

        $user_id = get_current_user_id();
        if ($user_id < 1) {
            return;
        }

        $notice = get_user_meta($user_id, 'wpsc_pending_termination_notice', true);
        self::log_debug('Termination notice lookup.', [
            'user_id' => $user_id,
            'notice' => $notice,
        ], $user_id);
        if (!is_array($notice) || empty($notice['sessions'])) {
            return;
        }

        delete_user_meta($user_id, 'wpsc_pending_termination_notice');
        wp_cache_delete($user_id, 'user_meta');
        if (function_exists('clean_user_cache')) {
            clean_user_cache($user_id);
        }
        self::$modal_rendered = true;

        $sessions = array_slice((array) $notice['sessions'], 0, 10);
        $content = (string) WPSC_Settings::get_option('termination_notice_content');
        if ($content === '') {
            $content = __('You have been signed out of your older session to keep your account secure.', 'wp-session-control');
        }

        $content = do_shortcode(wpautop(wp_kses_post($content)));

        $rows = '';
        foreach ($sessions as $session) {
            $rows .= self::render_session_row($session);
        }

        $modal_id = 'wpsc-session-modal';
        $heading = (string) WPSC_Settings::get_option('termination_notice_heading');
        if ($heading === '') {
            $heading = __('Session Update', 'wp-session-control');
        }

        echo '<div class="modal fade" id="' . esc_attr($modal_id) . '" tabindex="-1" aria-hidden="true">';
        echo '<div class="modal-dialog modal-dialog-centered">';
        echo '<div class="modal-content">';
        echo '<div class="modal-header">';
        echo '<h2 class="modal-title">' . esc_html($heading) . '</h2>';
        echo '<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="' . esc_attr__('Close', 'wp-session-control') . '"></button>';
        echo '</div>';
        echo '<div class="modal-body">';
        echo $content;

        if ($rows !== '') {
            echo '<hr />';
            echo '<p>' . esc_html__('Recent sessions:', 'wp-session-control') . '</p>';
            echo '<ul class="list-unstyled wpsc-session-list">' . $rows . '</ul>';
        }

        echo '</div>';
        echo '<div class="modal-footer">';
        echo '<button type="button" data-bs-dismiss="modal">' . esc_html__('Got it', 'wp-session-control') . '</button>';
        echo '</div>';
        echo '</div></div></div>';

        echo '<script>';
        echo '(function(){var el=document.getElementById(' . wp_json_encode($modal_id) . ');if(!el){return;}var show=function(){if(window.bootstrap&&window.bootstrap.Modal){var modal=new window.bootstrap.Modal(el,{backdrop:"static"});modal.show();}else{el.classList.add("show");el.style.display="block";el.setAttribute("aria-modal","true");el.removeAttribute("aria-hidden");var closeBtn=el.querySelector("[data-bs-dismiss=modal]");if(closeBtn){closeBtn.addEventListener("click",function(){el.classList.remove("show");el.style.display="none";});}}};if(document.readyState!=="loading"){show();}else{document.addEventListener("DOMContentLoaded",show);}})();';
        echo '</script>';
    }

    /**
     * Log a debug entry for later output.
     */
    private static function log_debug(string $message, array $context = [], ?int $user_id = null): void
    {
        if (!self::is_debug_enabled()) {
            return;
        }

        self::$debug_messages[] = [
            'message' => $message,
            'context' => $context,
        ];
    }

    /**
     * Prepare notification payload for terminated sessions.
     */
    private static function queue_termination_notice(int $user_id, array $sessions): void
    {
        if (empty($sessions)) {
            delete_user_meta($user_id, 'wpsc_pending_termination_notice');
            wp_cache_delete($user_id, 'user_meta');
            if (function_exists('clean_user_cache')) {
                clean_user_cache($user_id);
            }
            return;
        }

        $payload = [
            'timestamp' => time(),
            'sessions' => array_values($sessions),
        ];

        update_user_meta($user_id, 'wpsc_pending_termination_notice', $payload);
        wp_cache_delete($user_id, 'user_meta');
        if (function_exists('clean_user_cache')) {
            clean_user_cache($user_id);
        }
        self::log_debug('Termination notice persisted.', [
            'user_id' => $user_id,
            'payload' => $payload,
        ], $user_id);
    }

    /**
     * Replace stored session tokens with the allowed list.
     */
    private static function replace_session_tokens(int $user_id, array $allowed_sessions): void
    {
        update_user_meta($user_id, 'session_tokens', $allowed_sessions);
        wp_cache_delete($user_id, 'user_meta');
        if (function_exists('clean_user_cache')) {
            clean_user_cache($user_id);
        }
    }

    /**
     * Transform destroyed session entries into a concise format for the modal.
     */
    private static function prepare_destroyed_session_details(array $sessions): array
    {
        $output = [];

        foreach ($sessions as $token_hash => $data) {
            $output[] = [
                'token' => $token_hash,
                'login' => isset($data['login']) ? (int) $data['login'] : 0,
                'expiration' => isset($data['expiration']) ? (int) $data['expiration'] : 0,
                'ip' => isset($data['ip']) ? (string) $data['ip'] : '',
                'ua' => isset($data['ua']) ? (string) $data['ua'] : '',
            ];
        }

        return $output;
    }

    /**
     * Render a single session row within the modal.
     */
    private static function render_session_row(array $session): string
    {
        $ip = $session['ip'] ?? '';
        $ua = $session['ua'] ?? '';
        $login = isset($session['login']) ? (int) $session['login'] : 0;
        $expiration = isset($session['expiration']) ? (int) $session['expiration'] : 0;
        $token_hash = isset($session['token']) ? (string) $session['token'] : '';
        $current_hash = self::get_current_session_hash();
        $is_current = $current_hash && $token_hash && hash_equals($current_hash, $token_hash);

        $descriptor = self::describe_user_agent($ua);
        $ip_text = $ip ? $ip : __('Unknown IP', 'wp-session-control');
        $login_text = $login ? self::format_session_time($login) : __('Unknown time', 'wp-session-control');

        $classes = ['mb-3'];
        if ($is_current) {
            $classes[] = 'current-session';
        }

        $html = '<li class="' . esc_attr(implode(' ', $classes)) . '">';
        $html .= '<div><strong>' . esc_html($descriptor) . '</strong>';
        if ($is_current) {
            $html .= ' <span class="text-success">' . esc_html__('This session', 'wp-session-control') . '</span>';
        }
        $html .= '</div>';
        $html .= '<div class="text-muted small">' . esc_html__('IP address:', 'wp-session-control') . ' ' . esc_html($ip_text) . '</div>';
        $html .= '<div class="text-muted small">' . esc_html__('Signed in:', 'wp-session-control') . ' ' . esc_html($login_text) . '</div>';
        // if ($token_hash !== '') {
        //     $html .= '<div class="text-muted small">' . esc_html__('Token hash:', 'wp-session-control') . ' <code>' . esc_html($token_hash) . '</code></div>';
        // }
        $html .= '</li>';

        return $html;
    }


    /**
     * Log out the current user if their session token no longer exists.
     */
    public static function maybe_logout_orphan_session(): void
    {
        if (!is_user_logged_in()) {
            return;
        }

        if (self::should_bypass_logout_check()) {
            return;
        }

        if (!function_exists('wp_get_session_token')) {
            return;
        }

        $token = wp_get_session_token();
        if (!is_string($token) || $token === '') {
            return;
        }

        $user_id = get_current_user_id();
        if ($user_id < 1) {
            return;
        }

        $allowed = get_user_meta($user_id, 'wpsc_allowed_session_hashes', true);
        if (!is_array($allowed) || empty($allowed)) {
            return;
        }

        $token_hash = self::hash_session_token($token);
        if (in_array($token_hash, $allowed, true)) {
            return;
        }

        self::log_debug('Current session token not in allowed list; logging out.', [
            'user_id' => $user_id,
            'token_hash' => $token_hash,
        ]);

        wp_logout();

        if (defined('WP_CLI') && WP_CLI) {
            return;
        }

        if (wp_doing_ajax()) {
            wp_send_json_error(['message' => __('Session expired. Please sign in again.', 'wp-session-control')], 403);
        }

        if (defined('REST_REQUEST') && REST_REQUEST) {
            status_header(401);
            wp_send_json_error(['message' => __('Session expired. Please sign in again.', 'wp-session-control')], 401);
        }

        if (!headers_sent()) {
            $redirect = apply_filters('wpsc_orphan_logout_redirect', home_url());
            wp_safe_redirect($redirect);
        }

        exit;
    }

    /**
     * Determine if debugging is active.
     */
    private static function is_debug_enabled(): bool
    {
        if (defined('WPSC_DEBUG')) {
            $enabled = (bool) WPSC_DEBUG;
        } else {
            $enabled = defined('WP_DEBUG') && WP_DEBUG;
        }

        return (bool) apply_filters('wpsc_debug_enabled', $enabled);
    }

    /**
     * Persist the list of allowed session hashes for the user.
     */
    private static function store_allowed_session_hashes(int $user_id, array $allowed_hashes): void
    {
        $normalized = array_values(array_unique(array_filter($allowed_hashes, 'is_string')));

        if (empty($normalized)) {
            delete_user_meta($user_id, 'wpsc_allowed_session_hashes');
            return;
        }

        update_user_meta($user_id, 'wpsc_allowed_session_hashes', $normalized);
        wp_cache_delete($user_id, 'user_meta');
        if (function_exists('clean_user_cache')) {
            clean_user_cache($user_id);
        }
    }

    /**
     * Handle AJAX requests by checking session validity during init.
     */
    public static function maybe_logout_for_ajax(): void
    {
        if (!wp_doing_ajax()) {
            return;
        }

        self::maybe_logout_orphan_session();
    }

    /**
     * Register a REST API guard that enforces session validity.
     */
    public static function register_rest_logout_guard(): void
    {
        add_filter('rest_pre_dispatch', [__CLASS__, 'rest_pre_dispatch_guard'], 0, 3);
    }

    /**
     * Callback wired into rest_pre_dispatch to enforce session validity.
     */
    public static function rest_pre_dispatch_guard($result, $server, $request)
    {
        self::maybe_logout_orphan_session();

        return $result;
    }

    /**
     * Convert timestamps into a readable string using site preferences.
     */
    private static function format_session_time(int $timestamp): string
    {
        if ($timestamp <= 0) {
            return __('Unknown time', 'wp-session-control');
        }

        $format = trim(get_option('date_format') . ' ' . get_option('time_format'));
        if ($format === '') {
            $format = 'Y-m-d H:i';
        }

        return date_i18n($format, $timestamp);
    }

    /**
     * Provide a human friendly description of a user agent string.
     */
    private static function describe_user_agent(string $ua): string
    {
        $ua = trim($ua);
        if ($ua === '') {
            return __('Unknown device', 'wp-session-control');
        }

        $browser = __('Unknown browser', 'wp-session-control');
        if (stripos($ua, 'Edg') !== false) {
            $browser = __('Microsoft Edge', 'wp-session-control');
        } elseif (stripos($ua, 'OPR') !== false || stripos($ua, 'Opera') !== false) {
            $browser = __('Opera', 'wp-session-control');
        } elseif (stripos($ua, 'Chrome') !== false && stripos($ua, 'Chromium') === false && stripos($ua, 'Edg') === false) {
            $browser = __('Chrome', 'wp-session-control');
        } elseif (stripos($ua, 'Firefox') !== false) {
            $browser = __('Firefox', 'wp-session-control');
        } elseif (stripos($ua, 'Safari') !== false && stripos($ua, 'Chrome') === false) {
            $browser = __('Safari', 'wp-session-control');
        } elseif (stripos($ua, 'MSIE') !== false || stripos($ua, 'Trident') !== false) {
            $browser = __('Internet Explorer', 'wp-session-control');
        }

        $platform = __('Unknown platform', 'wp-session-control');
        if (stripos($ua, 'Windows NT') !== false) {
            $platform = __('Windows', 'wp-session-control');
        } elseif (stripos($ua, 'Mac OS X') !== false || stripos($ua, 'Macintosh') !== false) {
            $platform = __('macOS', 'wp-session-control');
        } elseif (stripos($ua, 'Android') !== false) {
            $platform = __('Android', 'wp-session-control');
        } elseif (stripos($ua, 'iPhone') !== false) {
            $platform = __('iPhone', 'wp-session-control');
        } elseif (stripos($ua, 'iPad') !== false) {
            $platform = __('iPad', 'wp-session-control');
        } elseif (stripos($ua, 'Linux') !== false) {
            $platform = __('Linux', 'wp-session-control');
        } elseif (stripos($ua, 'CrOS') !== false) {
            $platform = __('ChromeOS', 'wp-session-control');
        }

        $device = __('Desktop', 'wp-session-control');
        if (stripos($ua, 'iPad') !== false || stripos($ua, 'Tablet') !== false) {
            $device = __('Tablet', 'wp-session-control');
        } elseif (stripos($ua, 'Mobi') !== false || stripos($ua, 'Android') !== false || stripos($ua, 'iPhone') !== false) {
            $device = __('Mobile', 'wp-session-control');
        }

        /* translators: 1: browser label, 2: platform label, 3: device label. */
        return sprintf(__('%1$s on %2$s · %3$s', 'wp-session-control'), $browser, $platform, $device);
    }

    /**
     * Hash a session token the same way WordPress core does.
     */
    private static function hash_session_token(string $token): string
    {
        if (function_exists('wp_hash')) {
            return wp_hash($token, 'session');
        }

        return hash_hmac('sha256', $token, wp_salt('session'));
    }

    /**
     * Retrieve the current session token hash if available.
     */
    private static function get_current_session_hash(): ?string
    {
        if (!function_exists('wp_get_session_token')) {
            return null;
        }

        $token = wp_get_session_token();
        if (!is_string($token) || $token === '') {
            return null;
        }

        return self::hash_session_token($token);
    }

    /**
     * Decide whether the logout guard should be skipped for the current request.
     */
    private static function should_bypass_logout_check(): bool
    {
        if (defined('WP_INSTALLING') && WP_INSTALLING) {
            return true;
        }

        if (defined('DOING_CRON') && DOING_CRON) {
            return true;
        }

        if (defined('WP_CLI') && WP_CLI) {
            return true;
        }

        if (self::is_login_request()) {
            return true;
        }

        $context = [
            'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
            'request_method' => $_SERVER['REQUEST_METHOD'] ?? '',
            'is_ajax' => function_exists('wp_doing_ajax') ? wp_doing_ajax() : false,
            'is_rest' => defined('REST_REQUEST') && REST_REQUEST,
        ];

        return (bool) apply_filters('wpsc_bypass_logout_check', false, $context);
    }

    /**
     * Detect whether the current request is being served from wp-login.php.
     */
    private static function is_login_request(): bool
    {
        if (defined('WP_LOGIN') && WP_LOGIN) {
            return true;
        }

        if (isset($GLOBALS['pagenow']) && 'wp-login.php' === $GLOBALS['pagenow']) {
            return true;
        }

        $script = isset($_SERVER['SCRIPT_NAME']) ? basename((string) $_SERVER['SCRIPT_NAME']) : '';

        return 'wp-login.php' === $script;
    }

}
