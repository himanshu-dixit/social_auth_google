<?php

namespace Drupal\social_auth_google;

use Drupal\social_auth\AuthManager\OAuth2Manager;
use Drupal\Core\Config\ConfigFactory;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Entity\EntityFieldManagerInterface;
use Drupal\Core\Routing\UrlGeneratorInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

/**
 * Contains all the logic for Google login integration.
 */
class GoogleAuthManager extends OAuth2Manager {

  /**
   * The logger channel.
   *
   * @var \Drupal\Core\Logger\LoggerChannelFactoryInterface
   */
  protected $loggerFactory;

  /**
   * The event dispatcher.
   *
   * @var \Symfony\Component\EventDispatcher\EventDispatcherInterface
   */
  protected $eventDispatcher;

  /**
   * The entity field manager.
   *
   * @var \Drupal\Core\Entity\EntityFieldManagerInterface
   */
  protected $entityFieldManager;

  /**
   * The url generator.
   *
   * @var \Drupal\Core\Routing\UrlGeneratorInterface
   */
  protected $urlGenerator;

  /**
   * The Google client object.
   *
   * @var \League\OAuth2\Client\Provider\Google
   */
  protected $client;
  /**
   * The Google access token.
   *
   * @var \League\OAuth2\Client\Token\AccessToken
   */
  protected $token;

  /**
   * The Google user.
   *
   * @var \League\OAuth2\Client\Provider\GoogleUser
   */
  protected $user;

  /**
   * The data point to be collected.
   *
   * @var string
   */
  protected $scopes;

  /**
   * Constructor.
   *
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   Used for logging errors.
   * @param \Symfony\Component\EventDispatcher\EventDispatcherInterface $event_dispatcher
   *   Used for dispatching events to other modules.
   * @param \Drupal\Core\Entity\EntityFieldManagerInterface $entity_field_manager
   *   Used for accessing Drupal user picture preferences.
   * @param \Drupal\Core\Routing\UrlGeneratorInterface $url_generator
   *   Used for generating absoulute URLs.
   */
  public function __construct(LoggerChannelFactoryInterface $logger_factory, EventDispatcherInterface $event_dispatcher, EntityFieldManagerInterface $entity_field_manager, UrlGeneratorInterface $url_generator, ConfigFactory $configFactory) {
    $this->loggerFactory      = $logger_factory;
    $this->eventDispatcher    = $event_dispatcher;
    $this->entityFieldManager = $entity_field_manager;
    $this->urlGenerator       = $url_generator;
    $this->setting            = $configFactory->getEditable('social_auth_google.settings');
  }

  /**
   * Authenticates the users by using the access token.
   *
   * @return $this
   *   The current object.
   */
  public function authenticate() {
    $this->token = $this->client->getAccessToken('authorization_code',
      ['code' => $_GET['code']]);

    return $this->token;
  }

  /**
   * Gets the data by using the access token returned.
   *
   * @return array
   *   User info returned by the Google.
   */
  public function getUserInfo() {
    $this->user = $this->client->getResourceOwner($this->token);
    return $this->user;
  }

  /**
   * Gets the data by using the access token returned.
   *
   * @return string
   *   Data returned by Making API Call.
   */
  public function getExtraDetails($url) {
    $httpRequest = $this->client->getAuthenticatedRequest('GET', $url, $this->token, []);
    $data = $this->client->getResponse($httpRequest);
    return $data;
  }

  /**
   * Returns the Google login URL where user will be redirected.
   *
   * @return string
   *   Absolute Google login URL where user will be redirected
   */
  public function getGoogleLoginUrl() {
    $scopes = [
      'email',
      'openid',
      'profile',
    ];

    $google_scopes = explode(',', $this->getScopes());
    foreach ($google_scopes as $scope) {
      array_push($scopes, $scope);
    }

    $login_url = $this->client->getAuthorizationUrl([
      'scope' => $scopes,
    ]);

    // Generate and return the URL where we should redirect the user.
    return $login_url;
  }

  /**
   * Returns the Google login URL where user will be redirected.
   *
   * @return string
   *   Absolute Google login URL where user will be redirected
   */
  public function getState() {
    $state = $this->client->getState();

    // Generate and return the URL where we should redirect the user.
    return $state;
  }

  /**
   * Gets the data Point defined the settings form page.
   *
   * @return string
   *   Data points separtated by comma.
   */
  public function getScopes() {
    if (!$this->scopes) {
      $this->scopes = $this->setting->get('scopes');
    }
    return $this->scopes;
  }

  /**
   * Gets the API calls to collect data.
   *
   * @return string
   *   API calls separtated by comma.
   */
  public function getAPICalls() {
    return $this->setting->get('api_calls');
  }

}
