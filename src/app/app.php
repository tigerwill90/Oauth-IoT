<?php
  /**
   * SYLVAIN MULLER
   * TB : Securing an IoT Network with Oauth2.0 protocol
   */

  require __DIR__ . '/../vendor/autoload.php';

  $dotenv = new Dotenv\Dotenv(__DIR__ . '/../');
  $dotenv->load();
  $dotenv->required('DEBUG')->notEmpty()->allowedValues(['true', 'false']);
  $dotenv->required('KEY')->notEmpty();

  $app = new Slim\App([
    'settings' => [
      'displayErrorDetails' => filter_var(getenv('DEBUG'), FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE)
    ]
  ]);

  require __DIR__ . '/config/dependencies.php';

  require __DIR__ . '/config/handlers.php';

  require __DIR__ . '/routes/public.php';

  $app->run();
