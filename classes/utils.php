<?php

const CC_REGEX_PORT = '/((?::))(?:[0-9]+)$/';
const CC_REGEX_HOSTNAME = '/^(?:https?:\/\/)?(?:www\.)?/i';

class Utils
{
  public static function getServerVariable($key)
  {
    return isset($_SERVER[$key]) ? sanitize_text_field($_SERVER[$key]) : '';
  }

  public static function getCookieVariable($key)
  {
    return isset($_COOKIE[$key]) ? sanitize_text_field($_COOKIE[$key]) : '';
  }

  public static function get_the_user_ip()
  {
    $ip = "";
    if (!empty(Utils::getServerVariable('HTTP_CLIENT_IP'))) {
      //check ip from share internet
      $ip = Utils::getServerVariable('HTTP_CLIENT_IP');
    } elseif (!empty(Utils::getServerVariable('HTTP_X_FORWARDED_FOR'))) {
      //to check ip is pass from proxy
      $ip = Utils::getServerVariable('HTTP_X_FORWARDED_FOR');
    } else {
      $ip = Utils::getServerVariable('REMOTE_ADDR');
    }

    $ip_explode = explode(',', apply_filters('wpb_get_ip', $ip))[0];

    return preg_replace(CC_REGEX_PORT, '', $ip_explode);
  }

  private static function getResponseObject($statusCode, $message)
  {
    return [
      "status" => $statusCode,
      "message" => $message,
    ];
  }

  public static function getHttpResponse(int $statusCode, string $message)
  {
    $response = Utils::getResponseObject($statusCode, $message);
    return json_encode($response);
  }

  public static function getHttpErrorResponse(string $message)
  {
    return Utils::getHttpResponse(CHEGTMS_HTTPCode::BAD_REQUEST, $message);
  }

  public static function getHttpSuccessResponse($responseArray = [])
  {
    $response = Utils::getResponseObject(CHEGTMS_HTTPCode::SUCCESS, CHEGTMS_ResponseMessage::SUCCESS);
    return json_encode(array_merge($response, $responseArray));
  }

  public static function getDomain()
  {
    $pieces = parse_url(home_url());
    $domain = isset($pieces['host']) ? $pieces['host'] : '';
    $res = preg_replace(CC_REGEX_HOSTNAME, "", $domain);

    return $res;
  }

  public static function get_host()
  {
    $domain = str_replace('http://', '', get_site_url());
    $domain = str_replace('https://', '', $domain);
    return $domain;
  }

  public static function send_interval($option_name, $fetch_interval)
  {
    $fetched_data = false;
    $last_send_date = get_option($option_name, '');

    if ($last_send_date) {
      $next_fetch_date = date("Y-m-d H:i:s", strtotime($last_send_date . ' + ' . $fetch_interval));
      $date_now = date("Y-m-d H:i:s");

      if ($date_now >= $next_fetch_date) {
        $fetched_data = true;
        update_option($option_name, date("Y-m-d H:i:s"));
      }
    } else {
      update_option($option_name, date("Y-m-d H:i:s"));
      $fetched_data = true;
    }

    return $fetched_data;
  }

  public static function get_active_domain($api_key)
  {
    $domain =  $domain = CHEGTMS_Urls::HTTPS . CHEGTMS_Urls::CHEQ_TAG;
    $fetch_active_domain = Utils::send_interval('ce-active-domain', '1 days');

    if ($fetch_active_domain) {
      $temp_domain =   (new CHEGTMS_RTI())->get_active_domain($api_key);
      if ($temp_domain)
        $domain = $temp_domain;
    }

    return $domain;
  }
}
