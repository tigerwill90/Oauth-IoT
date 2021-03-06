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
    $dotenv->required('DB_NAME')->notEmpty();
    $dotenv->required('DB_USER')->notEmpty();
    $dotenv->required('DB_PASSWORD')->notEmpty();
    $dotenv->required('DB_HOST')->notEmpty();
    $dotenv->required('TIMEZONE')->notEmpty();
    $dotenv->required('TEMPLATE_DIR')->notEmpty();
    $dotenv->required('CACHE_DIR')->notEmpty();
    $dotenv->required('APP_NAME')->notEmpty();
    $dotenv->required('REFRESH_TOKEN_KEY')->notEmpty();
    $dotenv->required('REFRESH_TOKEN_ID')->notEmpty();

    date_default_timezone_set(getenv('TIMEZONE'));

    $app = new Slim\App([
    'settings' => [
      'displayErrorDetails' => filter_var(getenv('DEBUG'), FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE)
    ]
    ]);

    require __DIR__ . '/config/dependencies.php';

    require __DIR__ . '/config/handlers.php';

    require __DIR__ . '/routes/public.php';

    $app->run();
