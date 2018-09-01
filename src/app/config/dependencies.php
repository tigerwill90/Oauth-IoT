<?php

use Psr\Container\ContainerInterface;

$container = $app->getContainer();

/**
 * @param ContainerInterface $c
 * @return \Oauth\Controllers\IntrospectionController
 */
$container[\Oauth\Controllers\IntrospectionController::class] = function (ContainerInterface $c) {
  return new \Oauth\Controllers\IntrospectionController($c->get('IntrospectionService'), $c->get('debugLogger'), $c->get('AesHelper'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Controllers\ConnexionController
 */
$container[\Oauth\Controllers\ConnexionController::class] = function (ContainerInterface $c) {
  return new \Oauth\Controllers\ConnexionController($c->get('JoseHelper'), $c->get('debugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Controllers\CreateClientController
 */
$container[\Oauth\Controllers\CreateClientController::class] = function (ContainerInterface $c) {
    return new \Oauth\Controllers\CreateClientController($c->get('ValidatorManager'), $c->get('ClientRegister'));
};

$container[\Oauth\Controllers\DeleteClientController::class] = function (ContainerInterface $c) {
    return new \Oauth\Controllers\DeleteClientController($c->get('ValidatorManager'), $c->get('ClientRegister'));
};

$container[\Oauth\Controllers\UpdateClientController::class] = function (ContainerInterface $c) {
    return new \Oauth\Controllers\UpdateClientController($c->get('ValidatorManager'), $c->get('ClientRegister'), $c->get('debugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Introspection
 */
$container['IntrospectionService'] = function (ContainerInterface $c) {
    return new \Oauth\Services\Introspection($c->get('JoseHelper'), $c->get('AlgorithmManagerHelper'), $c->get('debugLogger'));
};

/**
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
 * @return \Oauth\Services\Helpers\AesHelper
 */
$container['AesHelper'] = function () {
    return new \Oauth\Services\Helpers\AesHelper();
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Registrations\ClientRegister
 */
$container['ClientRegister'] = function (ContainerInterface $c) {
    return  new \Oauth\Services\Registrations\ClientRegister($c->get('PdoClientStorage'), $c->get('RandomFactory'), $c->get('debugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Storage\PDOClientStorage
 */
$container['PdoClientStorage'] = function (ContainerInterface $c) {
    return new \Oauth\Services\Storage\PDOClientStorage($c->get('pdo'), $c->get('debugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Validators\ValidatorManagerInterface
 */
$container['ValidatorManager'] = function (ContainerInterface $c) {
   $validatorManager = new \Oauth\Services\Validators\ValidatorManager();
    return $validatorManager
            ->add('register', $c->get('ClientRegisterValidator'))
            ->add('unregister', $c->get('ClientUnregisterValidator'));
};

/**
 * @return \Oauth\Services\Validators\CustomValidators\ClientRegistrationValidator
 */
$container['ClientRegisterValidator'] = function () {
    return new \Oauth\Services\Validators\CustomValidators\ClientRegistrationValidator();
};

$container['ClientUnregisterValidator'] = function () {
    $validator = new \Oauth\Services\Validators\Validator();
    return $validator
            ->add('clientId', new \Oauth\Services\Validators\Parameters\ClientIdentificationRule(true));
};

/**
 * @return \RandomLib\Generator
 */
$container['RandomFactory'] = function () {
    $factory = new \RandomLib\Factory();
    return $factory->getGenerator(new \SecurityLib\Strength(\SecurityLib\Strength::MEDIUM));
};

/**
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
 * @return \Jose\Component\Encryption\Compression\CompressionMethodManager
 */
$container['compressionMethodManager'] = function () {
    return \Jose\Component\Encryption\Compression\CompressionMethodManager::create([
      new \Jose\Component\Encryption\Compression\Deflate()
    ]);
};

/**
 * @return \Monolog\Logger
 */
$container['debugLogger'] = function () {
  $log = new \Monolog\Logger('oauth_debug');
  $formatter = new \Monolog\Formatter\LineFormatter(
      "[%datetime%] [%level_name%]: %message% %context%\n",
      null,
      true,
      true
  );
  $stream = new \Monolog\Handler\StreamHandler(__DIR__ . '/../../logs/oauth.log', \Monolog\Logger::DEBUG);
  $stream->setFormatter($formatter);
  $log->pushHandler($stream);
  return $log;
};

/**
 * @return PDO
 */
$container['pdo'] = function () {
    $pdo = new PDO('mysql:host=' . getenv('DB_HOST') . ';' . 'dbname=' . getenv('DB_NAME') . ';charset=utf8', getenv('DB_USER'), getenv('DB_PASSWORD'));
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $pdo;
};
