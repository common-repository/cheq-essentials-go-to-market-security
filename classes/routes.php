<?php

/**
 * This file will create Custom Rest API End Points.
 */
const CC_MAX_IPS = 5;

class CHEGTMS_Admin_Routes
{
  public function __construct()
  {
    add_action('wp_ajax_get_settings', [$this, 'get_settings'], -999);
    add_action('wp_ajax_update_whitelist', [$this, 'update_whitelist'], -999);
    add_action('wp_ajax_save_settings', [$this, 'save_settings'], -999);
    add_action('wp_ajax_updateInstallClickFraud', [$this, 'updateInstallClickFraud'], -999);
    add_action('wp_ajax_updateInstallTag', [$this, 'updateInstallTag'], -999);
  }

  public function get_settings()
  {
    if ($this->save_settings_permission()) {
      $clickcease_api_key = get_option('clickcease_api_key', '');
      $clickcease_domain_key = get_option('clickcease_domain_key', '');
      $secret_key = get_option('clickcease_secret_key', '');
      $remove_tracking = get_option('clickcease_remove_tracking', '');
      $botzappingAuth = get_option('clickcease_bot_zapping_authenticated', '');
      $whitelist = get_option('clickcease_whitelist', []);
      $clientId = get_option('clickcease_client_id', null);
      $installTag = get_option('installTag', '');

      if (!$clientId) {
        $rtiService = new CHEGTMS_RTI();
        $clientId = $rtiService->auth_with_botzapping($clickcease_api_key, $clickcease_domain_key, $secret_key);

        if ($clientId)
          update_option('clickcease_client_id', $clientId);
      }

      $response = [
        'authKey' => $clickcease_api_key,
        'domainKey' => $clickcease_domain_key,
        'secretKey' => $secret_key,
        'installClickFraud' => !filter_var($remove_tracking, FILTER_VALIDATE_BOOLEAN),
        'botzappingAuth' => $botzappingAuth,
        'whitelist' => $whitelist,
        'maxWhitelistLength' => CC_MAX_IPS,
        'clientId' => $clientId,
        'installTag' => filter_var(
          $installTag,
          FILTER_VALIDATE_BOOLEAN
        ),
      ];

      // Send response to Ajax
      echo json_encode([
        "status" => 200,
        "settings" => $response,
      ]);
    }

    wp_die();
  }

  public function save_settings()
  {
    if ($this->save_settings_permission()) {
      $res = Utils::getHttpSuccessResponse();
      $success = true;
      $deactivate = sanitize_text_field($_POST['deactivate']);

      if (!$deactivate || $deactivate === "undefined") {
        $formService = new CHEGTMS_FormService();
        $tag_hash_key = sanitize_text_field($_POST['domainKey']);
        $secret_key = sanitize_text_field($_POST['secretKey']);
        $api_key = sanitize_text_field($_POST['authKey']);
        $validAuth = true;

        $clientId = $formService->validateBotzappingAuth($api_key, $tag_hash_key, $secret_key);
        if (!$clientId) {
          $success = false;
          $res  = Utils::getHttpErrorResponse(CHEGTMS_ResponseMessage::INVALID_KEYS);
          $validAuth = false;
        } else {
          update_option('clickcease_domain_key', $tag_hash_key);
          update_option('secret_checked', true);
          update_option('clickcease_client_id', $clientId);
        }

        if ($validAuth) {
          CHEGTMS_LogService::logErrorCode(CHEGTMS_ErrorCodes::PLUGIN_INSTALL);
        }
      } else {
        $validAuth = !$deactivate;
        if (CHEQ_ESSENTIAL) (new CHEGTMS_RTI())->update_cheq_essential_status(CHEGTMS_DomainState::BZ_PLUGIN_DEACTIVATED);
        else (new CHEGTMS_RTI())->update_user_status(CHEGTMS_DomainState::BZ_PLUGIN_DEACTIVATED);
        CHEGTMS_LogService::logErrorCode(CHEGTMS_ErrorCodes::PLUGIN_REMOVE);
      }

      update_option('clickcease_bot_zapping_authenticated', $validAuth);
      update_option('cheq_invalid_secret', !$validAuth);

      if ($success)
        wp_send_json_success($res);
      else {
        header('Status: ' . CHEGTMS_HTTPCode::BAD_REQUEST);
        header('HTTP/1.0 400 Bad Request');
        wp_send_json_error($res);
        exit();
      }
    }
  }

  public function updateInstallClickFraud()
  {
    if ($this->save_settings_permission()) {
      $installClickFraud = sanitize_text_field($_POST['installClickFraud']);
      $installClickFraud = filter_var($installClickFraud, FILTER_VALIDATE_BOOLEAN);

      update_option('clickcease_remove_tracking', !$installClickFraud);
    }
  }

  //for cheq_essential
  public function updateInstallTag()
  {
    if ($this->save_settings_permission()) {
      $tag_hash_key = sanitize_text_field($_POST['domainKey']);
      $installTag = sanitize_text_field($_POST['installTag']);
      $installTag = filter_var($installTag, FILTER_VALIDATE_BOOLEAN);

      if ($tag_hash_key &&  $installTag) {
        update_option('installTag', $installTag);
        update_option('clickcease_domain_key', $tag_hash_key);
      } else if ($installTag) {
        wp_send_json_error('The tag is empty');
      }

      if (!$installTag)
        update_option('installTag', $installTag);
    }

    wp_send_json_success();
  }

  private function validateIP($accumulator, string $item)
  {
    if (filter_var($item, FILTER_VALIDATE_IP)) {
      array_push($accumulator, $item);
    }

    return $accumulator;
  }

  public function update_whitelist()
  {
    if ($this->save_settings_permission() && isset($_POST['whitelist'])) {
      $whitelist = explode(',', sanitize_text_field($_POST['whitelist']));
      $validatedIPs = array_reduce($whitelist, [$this, 'validateIP'], []);

      if (count($validatedIPs) <= CC_MAX_IPS) {
        update_option('clickcease_whitelist', $validatedIPs);
        echo json_encode([
          "status" => 200
        ]);
      } else
        echo json_encode([
          "status" => 400,
          "error" => "Max allowed entries is 5"
        ]);
    } else
      echo json_encode([
        "status" => 403
      ]);

    wp_die();
  }

  public function save_settings_permission()
  {
    return current_user_can('manage_options');
  }
}

new CHEGTMS_Admin_Routes();

require_once CHEGTMS_PLUGIN_PATH . '/classes/formService.php';
