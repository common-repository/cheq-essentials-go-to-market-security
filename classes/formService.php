<?php

class CHEGTMS_FormService
{
    public function validateDomainKey($domainKey)
    {
        $domain = CHEGTMS_Urls::HTTPS . Utils::get_active_domain($domainKey);
        $response = wp_remote_get($domain . '/i/' . $domainKey . '.js');
        $response_code = wp_remote_retrieve_response_code($response);
        return $response_code == "200";
    }

    public function validateBotzappingAuth($api_key, $tag_hash_key, $secret_key)
    {
        CHEGTMS_LogService::logErrorCode(CHEGTMS_ErrorCodes::PLUGIN_START_AUTHENTICATE);

        if ($api_key && $tag_hash_key && $secret_key) {
            $rtiService = new CHEGTMS_RTI();
            $clientId = $rtiService->auth_with_botzapping($api_key, $tag_hash_key, $secret_key);

            if ($clientId) {
                $prev_validation_status = get_option('clickcease_bot_zapping_authenticated', '');

                if (!$prev_validation_status && $clientId !== '') {
                    update_option('clickcease_api_key', $api_key);
                    update_option('clickcease_secret_key', $secret_key);
                    if (CHEQ_ESSENTIAL)
                        $rtiService->update_cheq_essential_status(CHEGTMS_DomainState::BZ_PLUGIN_ACTIVATED);
                    else
                        $rtiService->updateUserStatus($api_key, $clientId, CHEGTMS_DomainState::BZ_PLUGIN_ACTIVATED);
                }

                update_option('clickcease_bot_zapping_authenticated', true);
                CHEGTMS_LogService::logErrorCode(CHEGTMS_ErrorCodes::PLUGIN_SUCCESS_AUTHENTICATE);
            } else {
                update_option('clickcease_bot_zapping_authenticated', false);
                CHEGTMS_LogService::logErrorCode(CHEGTMS_ErrorCodes::AUTH_ERROR);
            }
        }

        return $clientId;
    }
}

require_once CHEGTMS_PLUGIN_PATH . '/classes/logService.php';
require_once CHEGTMS_PLUGIN_PATH . '/classes/rtiService.php';
require_once CHEGTMS_PLUGIN_PATH . '/classes/enums.php';
