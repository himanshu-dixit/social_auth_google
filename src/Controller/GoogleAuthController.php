<?php

namespace Drupal\social_auth_google\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\social_api\Plugin\NetworkManager;
use Drupal\social_auth\SocialAuthUserManager;
use Drupal\social_auth_google\GoogleAuthManager;

use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\social_auth_google\GoogleAuthPersistentDataHandler;
use Symfony\Component\HttpFoundation\RequestStack;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;

/**
 * Returns responses for Simple FB Connect module routes.
 */
class GoogleAuthController extends ControllerBase {

  /**
   * The network plugin manager.
   *
   * @var \Drupal\social_api\Plugin\NetworkManager
   */
  private $networkManager;

  /**
   * The user manager.
   *
   * @var \Drupal\social_auth\SocialAuthUserManager
   */
  private $userManager;

  /**
   * The Facebook authentication manager.
   *
   * @var \Drupal\social_auth_facebook\FacebookAuthManager
   */
  private $googleManager;

  /**
   * Used to access GET parameters.
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  private $request;

  /**
   * The Facebook Persistent Data Handler.
   *
   * @var \Drupal\social_auth_facebook\FacebookAuthPersistentDataHandler
   */
  private $persistentDataHandler;

  /**
   * The data point to be collected.
   *
   * @var string
   */
  private $dataPoints;

  /**
   * The logger channel.
   *
   * @var \Drupal\Core\Logger\LoggerChannelFactoryInterface
   */
  protected $loggerFactory;

  /**
   * GoogleAuthController constructor.
   *
   * @param \Drupal\social_api\Plugin\NetworkManager $network_manager
   *   Used to get an instance of social_auth_facebook network plugin.
   * @param \Drupal\social_auth\SocialAuthUserManager $user_manager
   *   Manages user login/registration.
   * @param \Drupal\social_auth_facebook\FacebookAuthManager $facebook_manager
   *   Used to manage authentication methods.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request
   *   Used to access GET parameters.
   * @param \Drupal\social_auth_facebook\FacebookAuthPersistentDataHandler $persistent_data_handler
   *   FacebookAuthPersistentDataHandler object.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   Used for logging errors.
   */
  public function __construct(NetworkManager $network_manager, SocialAuthUserManager $user_manager, GoogleAuthManager $google_manager, RequestStack $request, GoogleAuthPersistentDataHandler $persistent_data_handler, LoggerChannelFactoryInterface $logger_factory) {

    $this->networkManager = $network_manager;
    $this->userManager = $user_manager;
    $this->googleManager = $google_manager;
    $this->request = $request;
    $this->persistentDataHandler = $persistent_data_handler;
    $this->loggerFactory = $logger_factory;

    // Sets the plugin id.
    $this->userManager->setPluginId('social_auth_google');

    // Sets the session keys to nullify if user could not logged in.
    $this->userManager->setSessionKeysToNullify([
      $this->persistentDataHandler->getSessionPrefix() . 'access_token',
    ]);
    $this->setting = $this->config('social_auth_google.settings');
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('plugin.network.manager'),
      $container->get('social_auth.user_manager'),
      $container->get('social_auth_google.manager'),
      $container->get('request_stack'),
      $container->get('social_auth_google.persistent_data_handler'),
      $container->get('logger.factory')
    );
  }

  /**
   * Response for path 'user/simple-google-connect'.
   *
   * Redirects the user to Google for authentication.
   */
  public function redirectToGoogle() {
    /* @var \League\OAuth2\Client\Provider\Google false $google */
    $google = $this->networkManager->createInstance('social_auth_google')->getSdk();

    // If google client could not be obtained.
    if (!$google) {
      drupal_set_message($this->t('Social Auth Google not configured properly. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    // Google service was returned, inject it to $googleManager.
    $this->googleManager->setClient($google);

    // Generates the URL where the user will be redirected for Google login.
    // If the user did not have email permission granted on previous attempt,
    // we use the re-request URL requesting only the email address.
    $google_login_url = $this->googleManager->getGoogleLoginUrl();

    $state = $this->googleManager->getState();

    $this->persistentDataHandler->set('oAuth2State', $state);

    return new TrustedRedirectResponse($google_login_url);
  }

  /**
   * Response for path 'user/login/google/callback'.
   *
   * Google returns the user here after user has authenticated in Google.
   */
  public function returnFromGoogle() {
    // Checks if user cancel login via Google.
    $error = $this->request->getCurrentRequest()->get('error');
    if ($error == 'access_denied') {
      drupal_set_message($this->t('You could not be authenticated.'), 'error');
      return $this->redirect('user.login');
    }

    /* @var \League\OAuth2\Client\Provider\Google false $google */
    $google = $this->networkManager->createInstance('social_auth_google')->getSdk();

    // If Google client could not be obtained.
    if (!$google) {
      drupal_set_message($this->t('Social Auth Google not configured properly. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    $state = $this->persistentDataHandler->get('oAuth2State');

    if (!empty($_GET['error'])) {
      drupal_set_message($this->t('Google login failed. Probably User Declined Authentication.'), 'error');
      return $this->redirect('user.login');
    }
    else if (empty($_GET['state']) || ($_GET['state'] !== $state)) {
      unset($_SESSION['oauth2state']);
      drupal_set_message($this->t('Google login failed. Unvalid oAuth2 State.'), 'error');
      return $this->redirect('user.login');
    }


    $this->googleManager->setClient($google)->authenticate();

    // Gets user's FB profile from Google API.
    if (!$google_profile = $this->googleManager->getUserInfo()) {
      drupal_set_message($this->t('Google login failed, could not load Google profile. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }


    $data = [];

    $data_points = explode(',', $this->getDataPoints());

    foreach ($data_points as $data_point) {
      switch ($data_point) {
        default: $this->loggerFactory->get($this->userManager->getPluginId())->error(
          'Failed to fetch Data Point. Invalid Data Point: @$data_point', ['@$data_point' => $data_point]);
      }
    }

    // Saves access token to session.
    $this->persistentDataHandler->set('access_token', $this->googleManager->getAccessToken());
    var_dump($google_profile);
    // If user information could be retrieved.
    return $this->userManager->authenticateUser($google_profile->getName(), $google_profile->getEmail(), 'social_auth_google', $google_profile->getId(), $google_profile->getAvatar(), json_encode($data));
  }

  /**
   * Gets the data Point defined the settings form page.
   *
   * @return string
   *   Data points separtated by comma.
   */
  public function getDataPoints() {
    if (!$this->dataPoints) {
      $this->dataPoints = $this->config('social_auth_google.settings')->get('data_points');
    }
    return $this->dataPoints;
  }

}
