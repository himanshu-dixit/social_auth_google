<?php

namespace Drupal\social_auth_google\Plugin\Network;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\social_auth\SocialAuthDataHandler;
use Drupal\social_api\Plugin\NetworkBase;
use Drupal\social_api\SocialApiException;
use Drupal\social_auth_google\Settings\GoogleAuthSettings;
use Symfony\Component\DependencyInjection\ContainerInterface;
use League\OAuth2\Client\Provider\Google;
use Drupal\Core\Site\Settings;

/**
 * Defines a Network Plugin for Social Auth Google.
 *
 * @package Drupal\simple_google_connect\Plugin\Network
 *
 * @Network(
 *   id = "social_auth_google",
 *   social_network = "Google",
 *   type = "social_auth",
 *   handlers = {
 *     "settings": {
 *       "class": "\Drupal\social_auth_google\Settings\GoogleAuthSettings",
 *       "config_id": "social_auth_google.settings"
 *     }
 *   }
 * )
 */
class GoogleAuth extends NetworkBase implements GoogleAuthInterface {

  /**
   * The Social Auth Data Handler.
   *
   * @var \Drupal\social_auth\SocialAuthDataHandler
   */
  protected $dataHandler;

  /**
   * The logger factory.
   *
   * @var \Drupal\Core\Logger\LoggerChannelFactory
   */
  protected $loggerFactory;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    return new static(
      $container->get('social_auth.social_auth_data_handler'),
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('entity_type.manager'),
      $container->get('config.factory'),
      $container->get('logger.factory')
    );
  }

  /**
   * GoogleAuth constructor.
   *
   * @param \Drupal\social_auth\SocialAuthDataHandler $data_handler
   *   The data handler.
   * @param array $configuration
   *   A configuration array containing information about the plugin instance.
   * @param string $plugin_id
   *   The plugin_id for the plugin instance.
   * @param array $plugin_definition
   *   The plugin implementation definition.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity type manager.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The configuration factory object.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   The logger factory.
   */
  public function __construct(SocialAuthDataHandler $data_handler,
                              array $configuration,
                              $plugin_id,
                              array $plugin_definition,
                              EntityTypeManagerInterface $entity_type_manager,
                              ConfigFactoryInterface $config_factory,
                              LoggerChannelFactoryInterface $logger_factory) {

    parent::__construct($configuration, $plugin_id, $plugin_definition, $entity_type_manager, $config_factory);

    $this->dataHandler = $data_handler;
    $this->loggerFactory = $logger_factory;
  }

  /**
   * Sets the underlying SDK library.
   *
   * @return \League\OAuth2\Client\Provider\Google
   *   The initialized 3rd party library instance.
   *
   * @throws SocialApiException
   *   If the SDK library does not exist.
   */
  protected function initSdk() {

    $class_name = '\League\OAuth2\Client\Provider\Google';
    if (!class_exists($class_name)) {
      throw new SocialApiException(sprintf('The Google Library for the league oAuth not found. Class: %s.', $class_name));
    }
    /* @var \Drupal\social_auth_google\Settings\GoogleAuthSettings $settings */
    $settings = $this->settings;
    // Proxy configuration data for outward proxy.
    $proxyUrl =  Settings::get("http_client_config")["proxy"]["http"];
    if ($this->validateConfig($settings)) {
      // All these settings are mandatory.
      $league_settings = [
        'clientId'          => $settings->getClientId(),
        'clientSecret'      => $settings->getClientSecret(),
        'redirectUri'       => $GLOBALS['base_url'] . '/user/login/google/callback',
        'accessType'        => 'offline',
        'verify'            => false,
      ];

      return new Google($league_settings);
    }
    return FALSE;
  }

  /**
   * Checks that module is configured.
   *
   * @param \Drupal\social_auth_google\Settings\GoogleAuthSettings $settings
   *   The Google auth settings.
   *
   * @return bool
   *   True if module is configured.
   *   False otherwise.
   */
  protected function validateConfig(GoogleAuthSettings $settings) {
    $client_id = $settings->getClientId();
    $client_secret = $settings->getClientSecret();
    if (!$client_id || !$client_secret) {
      $this->loggerFactory
        ->get('social_auth_google')
        ->error('Define Client ID and Client Secret on module settings.');
      return FALSE;
    }

    return TRUE;
  }

}
