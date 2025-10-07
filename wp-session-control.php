<?php
/**
 * Plugin Name: Session Control
 * Description: Manage WordPress session lifetimes and concurrent login limits.
 * Version: 1.0.3
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

// Load PUC
require __DIR__ . '/vendor/yahnis-elsts/plugin-update-checker/plugin-update-checker.php';

use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

// Build update checker against your GitHub repo
$updateChecker = PucFactory::buildUpdateChecker(
    'https://github.com/RSLDevTeam/wp-session-control',
    __FILE__,                     // main plugin file
    'wp-session-control'          // plugin slug
);

// Track the branch you release from
$updateChecker->setBranch('main');

// If you attach compiled ZIPs to GitHub Releases, let PUC use them
$api = $updateChecker->getVcsApi();
if ($api) {
    $api->enableReleaseAssets(); // uses the Release asset ZIP if present
}

// Private repo? Add a token (define it in wp-config.php, never commit it)
if (defined('WPSC_GITHUB_TOKEN') && WPSC_GITHUB_TOKEN) {
    $updateChecker->setAuthentication(WPSC_GITHUB_TOKEN);
}

// Optional: add icons so WP Admin looks nice
$updateChecker->addResultFilter(function($info){
    $info->icons = [
      '1x' => plugins_url('assets/icon-128.png', __FILE__),
      '2x' => plugins_url('assets/icon-256.png', __FILE__),
    ];
    return $info;
});