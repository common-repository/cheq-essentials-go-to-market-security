<?php

/*
 * Plugin Name: CHEQ Essentials - Go To Market Security
 * Description: CHEQ Essentials - Go To Market Security plugin.
 * Version: 1.11
 * Requires at least: 5.6
 * Requires PHP: 5.6
 * Author: CHEQ
 * Author URI: https://cheq.ai/
 */

if (!defined('ABSPATH')) {
    die();
}

define('CHEGTMS_VERSION', '1.11');
define('CHEGTMS_PLUGIN_PATH', plugin_dir_path(__FILE__));
define('CHEGTMS_PLUGIN_URL', plugin_dir_url(__FILE__));

add_action('plugins_loaded', ['CHEGTMS_Blocking', 'init']);
register_activation_hook(__FILE__, ['CHEGTMS_Blocking', 'activate_plugin']);
register_deactivation_hook(__FILE__, ['CHEGTMS_Blocking', 'deactivate_plugin']);
register_uninstall_hook(__FILE__, ['CHEGTMS_Blocking', 'uninstall_plugin']);

const CHEQ_ESSENTIAL = true;
const LOGGER_NAME = "cheq-essential";
const CC_PLUGIN_PAGE = 'cheq-essential-plugin-options';

/**
 * Provide settings fields
 *
 * @package clickcease_plugin
 */
class CHEGTMS_Blocking
{
    /**
     * Plugin constructor.
     */
    public function __construct()
    {
        $whitelist = get_option('clickcease_whitelist', []);

        if (!current_user_can('manage_options')) {
            $client_ip = Utils::get_the_user_ip();
            if (!$client_ip || !in_array($client_ip, $whitelist)) {
                add_action('send_headers', [$this, 'clickcease_server_validation'], -999);
                add_action('wp_enqueue_scripts', [$this, 'enqueue_custom_scripts'], -999);
                add_action('wp_body_open', [$this, 'add_noscript_tag'], -999);
                add_action('wp_ajax_validate_clickcease_response', [$this, 'check_with_clickcease'], -999);
                add_action('wp_ajax_nopriv_validate_clickcease_response', [$this, 'check_with_clickcease'], -999);
            }

            if (!$client_ip) {
                CHEGTMS_LogService::log("Server", "", "", "", "", "", "", "", CHEGTMS_ErrorCodes::NO_CLIENT_IP);
            }
        } else {
            $admin = new CHEGTMS_Admin();
            $admin->init_clickcease_field_setting();
            $fetch_monitoring_data = Utils::send_interval('cheq-essential-monitoring-date', '5 minutes');

            if ($fetch_monitoring_data) {
                $this->update_monitoring_status();
            }

            if ($whitelist) {
                $this->send_whitelist_usage($whitelist);
            }

            $plugin_latests_version = $this->plugin_latests_version();
            $this->send_plugin_latest_version($plugin_latests_version);

            $this->send_plugin_state();
        }
    }

    public static function activate_plugin()
    {
        (new CHEGTMS_RTI())->update_cheq_essential_status(CHEGTMS_DomainState::PLUGIN_ACTIVATED);
        $botzappingAuth = get_option('clickcease_bot_zapping_authenticated', '');
        if ($botzappingAuth) {
            (new CHEGTMS_RTI())->update_cheq_essential_status(CHEGTMS_DomainState::BZ_PLUGIN_ACTIVATED);
        }
    }

    public static function deactivate_plugin()
    {
        (new CHEGTMS_RTI())->update_cheq_essential_status(CHEGTMS_DomainState::PLUGIN_DEACTIVATED);
    }

    public static function uninstall_plugin()
    {
        (new CHEGTMS_RTI())->update_cheq_essential_status(CHEGTMS_DomainState::BZ_PLUGIN_UNINSTALLED);
    }

    public static function init()
    {
        $class = __CLASS__;
        new $class();
    }

    public function clickcease_server_validation()
    {
        $rtiService = new CHEGTMS_RTI();
        if (isset($_GET["clickcease"]) && $_GET["clickcease"] == "valid") {
            return;
        }

        global $wp;

        $clickcease_api_key = get_option('clickcease_api_key', '');
        $current_page = home_url($wp->request);
        $clickcease_domain_key = get_option('clickcease_domain_key', '');
        $botzappingAuth = get_option('clickcease_bot_zapping_authenticated', '');
        $secret_key = get_option('clickcease_secret_key', '');
        $invalid_secret = get_option('cheq_invalid_secret', '');
        $is_monitoring = get_option('monitoring', false);

        $this->check_keys($rtiService, $secret_key, $clickcease_api_key, $clickcease_domain_key);

        if ($clickcease_api_key && $clickcease_domain_key && $botzappingAuth && $secret_key && !$invalid_secret) {
            $validated = $rtiService->auth_with_rti($clickcease_api_key, $current_page, 'page_load', $clickcease_domain_key);
            if (!$is_monitoring && (!$validated['is_valid'] || (isset($_GET["clickcease"]) && ($_GET["clickcease"] == "block" || $_GET["clickcease"] == "clearhtml")))) {
                CHEGTMS_LogService::log(
                    "Server",
                    'blockuser',
                    isset($validated['output']->version) ? $validated['output']->version : '',
                    isset($validated['output']->isInvalid) ? $validated['output']->isInvalid : '',
                    isset($validated['output']->threatTypeCode) ? $validated['output']->threatTypeCode : '',
                    isset($validated['output']->requestId) ? $validated['output']->requestId : '',
                    isset($validated['output']->riskScore) ? $validated['output']->riskScore : '',
                    isset($validated['output']->setCookie) ? $validated['output']->setCookie : ''
                );
                header('Status: 403 Forbidden', true, 403);
                header('HTTP/1.0 403 Forbidden');
                exit();
            }
        } else {
            $logMsg =
                "clickcease_api_key : " .
                $clickcease_api_key .
                " ,clickcease_domain_key: " .
                $clickcease_domain_key .
                ",useBotzapping: " .
                $botzappingAuth .
                ",secret_key:" .
                $secret_key .
                ",invalid_secret: " .
                $invalid_secret;
            CHEGTMS_LogService::log("Server", "", "", "", "", "", "", "", CHEGTMS_ErrorCodes::NO_KEYS, $logMsg);
        }
    }

    public function check_keys($rtiService, $secret_key, $clickcease_api_key, $clickcease_domain_key)
    {
        $new_version_updated = get_option('cc_version_updated', '');

        if ($secret_key && !$new_version_updated) {
            update_option('cc_version_updated', true);
            $rtiService->auth_with_botzapping($clickcease_api_key, $clickcease_domain_key, $secret_key);
        }
    }

    private function send_whitelist_usage($whitelist)
    {
        $send_log = Utils::send_interval('cc_white_list_send_date', '1 days');
        if ($send_log) {
            $log_data_str = json_encode($whitelist);
            CHEGTMS_LogService::log("Plugin", "", "", "", "", "", "", "", CHEGTMS_ErrorCodes::WHITELIST_TRACK, $log_data_str);
        }
    }

    public function cc_redirect($cc_get_value = 'invalid', $cc_get_key = 'clickcease')
    {
        if (strpos(Utils::getServerVariable('REQUEST_URI'), '?') === false) {
            return Utils::getServerVariable('REQUEST_URI') . '?' . $cc_get_key . '=' . $cc_get_value;
        } else {
            return Utils::getServerVariable('REQUEST_URI') . '&' . $cc_get_key . '=' . $cc_get_value;
        }
    }

    public function add_noscript_tag()
    {
        $botzappingAuth = get_option('clickcease_bot_zapping_authenticated', '');
        $api_key = get_option('clickcease_domain_key');
        $domain = Utils::get_active_domain($api_key);
        $baseUrl = $domain . '/ns';
        $installTag = get_option('installTag');


        if (($botzappingAuth && $api_key) || $installTag) {
            echo  '<noscript><iframe src="' . esc_url($baseUrl . '/' . $api_key . '.html?ch=') . '" width="0" height="0" style="display:none"></iframe></noscript>';
        }
    }

    // Validate request on Ajax
    public function check_with_clickcease()
    {
        $rtiService = new CHEGTMS_RTI();
        return $rtiService->validateRTIClient();
    }

    public function enqueue_custom_scripts()
    {
        $api_key = get_option('clickcease_domain_key');
        $botzappingAuth = get_option('clickcease_bot_zapping_authenticated', '');
        $installTag = get_option('installTag');
        $domain = Utils::get_active_domain($api_key);

        if ($botzappingAuth && $api_key) {
            wp_enqueue_script('clickceaseFrontEnd', plugin_dir_url(__FILE__) . 'includes/assets/js/front-end.js', ['jquery'], "1.0");
            wp_localize_script('clickceaseFrontEnd', 'ajax_obj', [
                'cc_nonce' => wp_create_nonce('cc_ajax_nonce'),
                'ajax_url' => admin_url('admin-ajax.php'),
                'ajax_action' => 'validate_clickcease_response',
            ]);
        }

        if (($botzappingAuth && $api_key) || $installTag) {
            $baseUrl = $domain . '/i/' . $api_key . '.js';
            echo '<script async src="' . esc_url($baseUrl) . '" class="ct_clicktrue"></script>';
        }
    }

    private function update_monitoring_status()
    {
        $rtiService = new CHEGTMS_RTI();
        $clickcease_api_key = get_option('clickcease_api_key', '');
        $clickcease_domain_key = get_option('clickcease_domain_key', '');
        $secret_key = get_option('clickcease_secret_key', '');

        if ($clickcease_api_key && $clickcease_domain_key && $secret_key) {
            $isMonitoring = $rtiService->is_monitoring_with_botzapping($clickcease_api_key, $clickcease_domain_key, $secret_key);
            update_option('monitoring', $isMonitoring);
        }
    }

    private function send_plugin_latest_version($plugin_latests_version)
    {
        $send = Utils::send_interval('cc_send_plugin_latest_version', '10 minutes');

        if ($send) {
            $botzappingAuth = get_option('clickcease_bot_zapping_authenticated', '');
            if ($botzappingAuth) {
                $rtiService = new CHEGTMS_RTI();

                $rtiService->update_cheq_essential_domain($plugin_latests_version);
            }
        }
    }

    private function send_plugin_state()
    {
        $cc_send_plugin_state = get_option('cc_send_plugin_state', '');

        if (!$cc_send_plugin_state) {

            $botzappingAuth = get_option('clickcease_bot_zapping_authenticated', '');
            if ($botzappingAuth) {
                (new CHEGTMS_RTI())->update_cheq_essential_status(CHEGTMS_DomainState::BZ_PLUGIN_ACTIVATED);
            } else {
                (new CHEGTMS_RTI())->update_cheq_essential_status(CHEGTMS_DomainState::PLUGIN_ACTIVATED);
            }
            update_option("cc_send_plugin_state", "true");
        }
    }

    private function plugin_latests_version()
    {
        $res = true;
        $plugin_name = $this->get_plugin_name();

        if (!function_exists('get_plugin_updates')) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }

        $domains_need_update = get_plugin_updates();
        foreach ($domains_need_update as $domain) {
            if ($domain->Name === $plugin_name) {
                $res = false;
            }
        }

        return $res;
    }

    private function get_plugin_name()
    {
        if (!function_exists('get_plugin_data')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $plugin_data = get_plugin_data(__FILE__);
        $plugin_name = $plugin_data['Name'];
        return $plugin_name;
    }

    public function check_plugin_state()
    {
        $check_plugin_state = get_option('cc_check_plugin_state', '');
        if (!$check_plugin_state && is_plugin_active(CHEGTMS_PLUGIN_PATH)) {
            (new CHEGTMS_RTI())->update_cheq_essential_status(CHEGTMS_DomainState::PLUGIN_ACTIVATED);
            update_option('cc_check_plugin_state', true);
        }
    }
}

set_error_handler("error_handler");

function error_handler($errno, $errstr, $errfile, $errline)
{
    if (strpos($errfile, CHEGTMS_PLUGIN_PATH) !== false) {
        $error_msg = "errorno:" . $errno . ",errstr:" . $errstr . ",errfile:" . $errfile . ",errline:" . $errline;
        CHEGTMS_LogService::log("Plugin", "", "", "", "", "", "", "", CHEGTMS_ErrorCodes::ERROR, $error_msg);
    }
    return true;
}

register_shutdown_function(function () {
    $err = error_get_last();
    if (!is_null($err)) {
        error_handler("", $err['message'], $err['file'], $err['line']);
    }
});

require_once CHEGTMS_PLUGIN_PATH . 'classes/admin.php';
require_once CHEGTMS_PLUGIN_PATH . 'classes/rtiService.php';
require_once CHEGTMS_PLUGIN_PATH . 'classes/routes.php';
require_once CHEGTMS_PLUGIN_PATH . 'classes/formService.php';
require_once CHEGTMS_PLUGIN_PATH . 'classes/enums.php';
