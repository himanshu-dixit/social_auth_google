<?php

namespace Drupal\social_auth_google\Settings;

use Drupal\social_api\Settings\SettingsBase;

/**
 * Defines methods to get Social Auth Facebook app settings.
 */
class GoogleAuthSettings extends SettingsBase implements GoogleAuthSettingsInterface {

  /**
   * Application ID.
   *
   * @var string
   */
  protected $clientId;

  /**
   * Application secret.
   *
   * @var string
   */
  protected $clientSecret;


  /**
   * The default access token.
   *
   * @var string
   */
  protected $defaultToken;

  /**
   * The redirect URL for social_auth implmeneter.
   *
   * @var string
   */
  protected $oauthRedirectUrl;

  /**
   * {@inheritdoc}
   */
  public function getClientId() {
    if (!$this->clientId) {
      $this->clientId = $this->config->get('client_id');
    }
    return $this->clientId;
  }

  /**
   * {@inheritdoc}
   */
  public function getClientSecret() {
    if (!$this->clientSecret) {
      $this->clientSecret = $this->config->get('client_secret');
    }
    return $this->clientSecret;
  }


}
