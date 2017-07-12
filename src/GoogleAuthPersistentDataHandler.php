<?php

namespace Drupal\social_auth_google;

use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * Variables are written to and read from session via this class.
 *
 *  We implement Facebook\PersistentData\PersistentDataInterface using Symfony
 *  Sessions so that we use this instead of native PHP sessions.
 */
class GoogleAuthPersistentDataHandler {
  protected $session;
  protected $sessionPrefix = 'social_auth_google_';

  /**
   * Constructor.
   *
   * @param \Symfony\Component\HttpFoundation\Session\SessionInterface $session
   *   Used for reading data from and writing data to session.
   */
  public function __construct(SessionInterface $session) {
    $this->session = $session;
  }

  /**
   * {@inheritdoc}
   */
  public function get($key) {
    return $this->session->get($this->getSessionPrefix() . $key);
  }

  /**
   * {@inheritdoc}
   */
  public function set($key, $value) {
    $this->session->set($this->getSessionPrefix() . $key, $value);
  }

  /**
   * Gets the session prefix for the data handler.
   *
   * @return string
   *   The session prefix.
   */
  public function getSessionPrefix() {
    return $this->sessionPrefix;
  }

}
