<?php

class CHEGTMS_LogService
{
    public static function log($logger, $required_action, $version, $isInvalid, $threatType, $request_id, $risk_score = null, $set_cookie = null, $errorCode = 0, $msg = "")
    {
        $clickcease_api_key = get_option('clickcease_api_key', '');
        $clickcease_domain_key = get_option('clickcease_domain_key', '');
        $secret_key = get_option('clickcease_secret_key', '');
        $botzappingAuth = get_option('clickcease_bot_zapping_authenticated', '');

        //we dont want to send logs from users who arent botzapping.
        if ($clickcease_api_key || $clickcease_domain_key || $secret_key || $botzappingAuth) {
            $log_message = "[" . date("d/m/Y-H:i:s") . "] - " . $logger . "\n";
            $log_message .= $required_action . "\n";
            $log_message .= "\tVersion: " . $version . "\n";
            $log_message .= "\tisInvalid: " . $isInvalid . "\n";
            $log_message .= "\tThreatType: " . $threatType . "\n";
            $log_message .= "\tRequestID: " . $request_id . "\n";
            $log_message .= "\Referer: " . Utils::getServerVariable('HTTP_REFERER') . "\n";
            $log_message .= "\ClientIp: " . Utils::get_the_user_ip() . "\n";

            if (!is_null($risk_score)) {
                $log_message .= "\tRiskScore: " . $risk_score . "\n";
            }

            if (!is_null($set_cookie)) {
                $log_message .= "\tSetCookie: " . $set_cookie . "\n";
            }

            $site_url = get_site_url();
            $log_message .= "\tSite Url: " . $site_url . "\n";
            $log_message .= "\tErrorCode: " . $errorCode . "\n";
            $log_message .= "\PluginVersion: " . CHEGTMS_VERSION . "\n";

            if ($msg) {
                $log_message .= "\logMessge: " . $msg . "\n";
            }

            CHEGTMS_LogService::remote_log("info", $clickcease_domain_key, $clickcease_api_key, $log_message, LOGGER_NAME, $required_action, $site_url, $errorCode);
            $log_message .= "------------------------------------------------------------------------------\n";
        }
    }

    public static function logErrorCode(int $errorCode)
    {
        CHEGTMS_LogService::log("Server", "", "", "", "", "", "", "", $errorCode);
    }

    public static function remote_log($level, $tag_hash, $api_key, $message, $application, $action, $site_url, $errorCode)
    {
        $data = new stdClass();
        $data->level = $level;
        $data->tagHash = $tag_hash;
        $data->apiKey = $api_key;
        $data->message = $message;
        $data->application = $application;
        $data->action = $action;
        $data->site_url = $site_url;
        $data->errorCode = $errorCode;

        $dataStr = json_encode($data);
        if (!$dataStr) {
            $data->message = json_last_error_msg();
            $dataStr = json_encode($data);
        }

        if (!$dataStr) {
            wp_remote_post(CHEGTMS_Urls::RTI_LOGGER, [
                'method' => 'POST',
                'timeout' => 0.5,
                'redirection' => 5,
                'blocking' => false,
                'headers' => [
                    'Content-Type' => 'application/json',
                ],
                'body' => $dataStr,
            ]);
        }
    }
}

require_once CHEGTMS_PLUGIN_PATH . '/classes/enums.php';
