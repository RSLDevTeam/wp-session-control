<?php
/**
 * Plugin Name: Session Control
 * Description: Manage WordPress session lifetimes and concurrent login limits.
 * Version: 1.0.2
 * Author: Matt Bates
 * Text Domain: wp-session-control
 */

if (!defined('ABSPATH')) {
    exit;
}

define('WPSC_VERSION', '0.1.0');
define('WPSC_PATH', plugin_dir_path(__FILE__));
define('WPSC_URL', plugin_dir_url(__FILE__));
define('WPSC_PLUGIN_BASENAME', plugin_basename(__FILE__));
define('WPSC_DEBUG', false);

require_once WPSC_PATH . 'includes/class-wpsc-settings.php';
require_once WPSC_PATH . 'includes/class-wpsc-admin.php';
require_once WPSC_PATH . 'includes/class-wpsc-session-manager.php';

register_activation_hook(__FILE__, ['WPSC_Settings', 'activate']);

WPSC_Settings::init();
WPSC_Admin::init();
WPSC_Session_Manager::init();
