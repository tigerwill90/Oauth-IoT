<?php

use Psr\Container\ContainerInterface;

$container = $app->getContainer();

/**
 * Introspection controller
 *
 * @param ContainerInterface $c
 * @return \Oauth\Controllers\IntrospectionController
 */
$container[\Oauth\Controllers\IntrospectionController::class] = function (ContainerInterface $c) {
  return new \Oauth\Controllers\IntrospectionController($c->get('IntrospectionService'), $c->get('debugLogger'), $c->get('AesHelper'));
};

/**
 * Connexion controller
 *
 * @param ContainerInterface $c
 * @return \Oauth\Controllers\ConnexionController
 */
$container[\Oauth\Controllers\ConnexionController::class] = function (ContainerInterface $c) {
  return new \Oauth\Controllers\ConnexionController($c->get('JoseHelper'), $c->get('debugLogger'));
};

$container[\Oauth\Controllers\ClientRegistrationController::class] = function (ContainerInterface $c) {
    return new \Oauth\Controllers\ClientRegistrationController($c->get('RequestValidatorManager'), $c->get('ClientRegister'));
};

/**
 * Introspection service
 * @param ContainerInterface $c
 * @return \Oauth\Services\Introspection
 */
$container['IntrospectionService'] = function (ContainerInterface $c) {
    return new \Oauth\Services\Introspection($c->get('JoseHelper'), $c->get('AlgorithmManagerHelper'));
};

/**
 * Authentication service
 * @return \Oauth\Services\Authentication
 */
$container['AuthenticationService'] = function () {
    return new \Oauth\Services\Authentication();
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Helpers\JoseHelper
 */
$container['JoseHelper'] = function (ContainerInterface $c) {
    return new \Oauth\Services\Helpers\JoseHelper($c->get('AlgorithmManagerFactory'), $c->get('compressionMethodManager'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Helpers\AlgorithmManagerHelper
 */
$container['AlgorithmManagerHelper'] = function (ContainerInterface $c) {
    return new Oauth\Services\Helpers\AlgorithmManagerHelper($c->get('AlgorithmManagerFactory'));
};

/**
 * AesHelper Helper
 * @return \Oauth\Services\Helpers\AesHelper
 */
$container['AesHelper'] = function () {
    return new \Oauth\Services\Helpers\AesHelper();
};

/**
 * ClientRegister
 * @param ContainerInterface $c
 * @return \Oauth\Services\Registrations\ClientRegister
 */
$container['ClientRegister'] = function (ContainerInterface $c) {
    return  new \Oauth\Services\Registrations\ClientRegister($c->get('PdoClientStorage'), $c->get('RandomFactory'));
};

/**
 * Pdo client storage
 * @param ContainerInterface $c
 * @return \Oauth\Services\Storage\PDOClientStorage
 */
$container['PdoClientStorage'] = function (ContainerInterface $c) {
    return new \Oauth\Services\Storage\PDOClientStorage($c->get('pdo'));
};

/**
 * Request validator manager
 * @param ContainerInterface $c
 * @return \Oauth\Services\Validators\ValidatorManagerInterface
 */
$container['RequestValidatorManager'] = function (ContainerInterface $c) {
   $requestValidatorManager = new \Oauth\Services\Validators\RequestValidatorManager();
    return $requestValidatorManager
            ->add('registration', $c->get('RegistrationRequestValidator'));
};

/**
 * Registration request validator
 * @return \Oauth\Services\Validators\RequestValidators\ClientRegistrationRequestValidator
 */
$container['RegistrationRequestValidator'] = function () {
    return new \Oauth\Services\Validators\RequestValidators\ClientRegistrationRequestValidator();
};

/**
 * Random factory
 * @return \RandomLib\Generator
 */
$container['RandomFactory'] = function () {
    $factory = new \RandomLib\Factory();
    return $factory->getGenerator(new \SecurityLib\Strength(\SecurityLib\Strength::MEDIUM));
};

/**
 * Algorithm manager factory
 * @return \Jose\Component\Core\AlgorithmManagerFactory
 */
$container['AlgorithmManagerFactory'] = function () {
    $algorithmManagerFactory = new \Jose\Component\Core\AlgorithmManagerFactory();
    return $algorithmManagerFactory
        // JWS Key algorithm
        ->add('HS256', new \Jose\Component\Signature\Algorithm\HS256())
        ->add('HS384', new \Jose\Component\Signature\Algorithm\HS384())
        ->add('HS512', new \Jose\Component\Signature\Algorithm\HS512())
        // JWE Key algorithm
        ->add('A128KW', new \Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW())
        ->add('A192KW', new \Jose\Component\Encryption\Algorithm\KeyEncryption\A192KW())
        ->add('A256KW', new \Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW())
        ->add('A128GCMKW', new \Jose\Component\Encryption\Algorithm\KeyEncryption\A128GCMKW())
        ->add('A192GCMKW', new \Jose\Component\Encryption\Algorithm\KeyEncryption\A192GCMKW())
        ->add('A256GCMKW', new \Jose\Component\Encryption\Algorithm\KeyEncryption\A256GCMKW())
        // JWE Content key algorithm
        ->add('A128CBC-HS256', new \Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256())
        ->add('A192CBC-HS384', new \Jose\Component\Encryption\Algorithm\ContentEncryption\A192CBCHS384())
        ->add('A256CBC-HS512', new \Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512())
        ->add('A128GCM', new \Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM())
        ->add('A192GCM', new \Jose\Component\Encryption\Algorithm\ContentEncryption\A192GCM())
        ->add('A256GCM', new \Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM());
};

/**
 * Compression method manager
 * @return \Jose\Component\Encryption\Compression\CompressionMethodManager
 */
$container['compressionMethodManager'] = function () {
    return \Jose\Component\Encryption\Compression\CompressionMethodManager::create([
      new \Jose\Component\Encryption\Compression\Deflate()
    ]);
};

/**
 * PSR-3 Logger
 * @return \Monolog\Logger
 */
$container['debugLogger'] = function () {
  $log = new \Monolog\Logger('oauth_debug');
  $stream = new \Monolog\Handler\StreamHandler(__DIR__ . '/../../logs/oauth.log', \Monolog\Logger::DEBUG);
  $log->pushHandler($stream);
  return $log;
};

/**
 * PDO
 * @return PDO
 */
$container['pdo'] = function () {
    $pdo = new PDO('mysql:host=' . getenv('DB_HOST') . ';' . 'dbname=' . getenv('DB_NAME') . ';charset=utf8', getenv('DB_USER'), getenv('DB_PASSWORD'));
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $pdo;
};
