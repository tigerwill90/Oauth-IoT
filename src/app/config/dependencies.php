<?php

use Psr\Container\ContainerInterface;

$container = $app->getContainer();

/**
 * @param ContainerInterface $c
 * @return \Oauth\Controllers\IntrospectionEndpoint
 */
$container[\Oauth\Controllers\IntrospectionEndpoint::class] = function (ContainerInterface $c) {
    return new \Oauth\Controllers\IntrospectionEndpoint($c->get('IntrospectionService'), $c->get('Memcached'), $c->get('AesHelper'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Controllers\TokenEndpoint
 */
$container[\Oauth\Controllers\TokenEndpoint::class] = function (ContainerInterface $c) {
    return new \Oauth\Controllers\TokenEndpoint($c->get('JoseHelper'), $c->get('Memcached'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Controllers\AuthenticationEndpoint
 */
$container[\Oauth\Controllers\AuthenticationEndpoint::class] = function (ContainerInterface $c) {
    return new \Oauth\Controllers\AuthenticationEndpoint($c->get('AuthenticationService'), $c->get('ViewRender'), $c->get('ValidatorManager'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Controllers\CreateClientController
 */
$container[\Oauth\Controllers\CreateClientController::class] = function (ContainerInterface $c) {
    return new \Oauth\Controllers\CreateClientController($c->get('ValidatorManager'), $c->get('ClientRegister'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Controllers\DeleteClientController
 */
$container[\Oauth\Controllers\DeleteClientController::class] = function (ContainerInterface $c) {
    return new \Oauth\Controllers\DeleteClientController($c->get('ValidatorManager'), $c->get('ClientRegister'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Controllers\UpdateClientController
 */
$container[\Oauth\Controllers\UpdateClientController::class] = function (ContainerInterface $c) {
    return new \Oauth\Controllers\UpdateClientController($c->get('ValidatorManager'), $c->get('ClientRegister'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Introspection
 */
$container['IntrospectionService'] = function (ContainerInterface $c) {
    return new \Oauth\Services\Introspection($c->get('JoseHelper'), $c->get('AlgorithmManagerHelper'), $c->get('ClaimsCheckerManager'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Token\TokenManager
 */
$container['TokenManager'] = function (ContainerInterface $c) {
    return new \Oauth\Services\Token\TokenManager($c->get('Memcached'), $c->get('RandomFactory'), $c->get('JoseHelper'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Authentication\AuthorizationManager
 */
$container['AuthenticationService'] = function (ContainerInterface $c) {
    $authenticationManager = new \Oauth\Services\Authentication\AuthorizationManager($c->get('Memcached'), $c->get('DebugLogger'));
    return $authenticationManager
            ->add('token', $c->get('ImplicitGrantFlow'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Authentication\ImplicitGrant
 */
$container['ImplicitGrantFlow'] = function (ContainerInterface $c) {
    return new \Oauth\Services\Authentication\ImplicitGrant($c->get('PdoClientStorage'), $c->get('PdoUserStorage'), $c->get('PdoResourceStorage'), $c->get('RandomFactory'), $c->get('TokenManager'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\ClaimsCheckerManager
 */
$container['ClaimsCheckerManager'] = function (ContainerInterface $c) {
    $claimsCheckerManager = new \Oauth\Services\ClaimsCheckerManager();
    return $claimsCheckerManager->add('standard', new \Oauth\Services\ClaimsCheckerRules($c->get('Memcached')));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Helpers\JoseHelper
 */
$container['JoseHelper'] = function (ContainerInterface $c) {
    return new \Oauth\Services\Helpers\JoseHelper($c->get('AlgorithmManagerFactory'), $c->get('CompressionMethodManager'), $c->get('DebugLogger'));
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
    return  new \Oauth\Services\Registrations\ClientRegister($c->get('PdoClientStorage'), $c->get('PdoResourceStorage'), $c->get('RandomFactory'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Storage\PDOClientStorage
 */
$container['PdoClientStorage'] = function (ContainerInterface $c) {
    return new \Oauth\Services\Storage\PDOClientStorage($c->get('Pdo'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Storage\PDOUserStorage
 */
$container['PdoUserStorage'] = function (ContainerInterface $c) {
    return new \Oauth\Services\Storage\PDOUserStorage($c->get('Pdo'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Storage\PDOResourceStorage
 */
$container['PdoResourceStorage'] = function (ContainerInterface $c) {
    return new \Oauth\Services\Storage\PDOResourceStorage($c->get('Pdo'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Validators\ValidatorManagerInterface
 */
$container['ValidatorManager'] = function (ContainerInterface $c) {
   $validatorManager = new \Oauth\Services\Validators\ValidatorManager();
    return $validatorManager
            ->add('register', [$c->get('ClientParameter')])
            ->add('unregister', [$c->get('ClientAttribute')])
            ->add('update',[$c->get('ClientAttribute'), $c->get('ClientParameter'), $c->get('ClientQueryParameter')])
            ->add('sign', [$c->get('SignQueryParameter')])
            ->add('login', [$c->get('LoginParameter')]);
};

/**
 * @return \Oauth\Services\Validators\CustomValidators\ClientRegistrationValidator
 */
$container['ClientParameter'] = function () {
    return new \Oauth\Services\Validators\CustomValidators\ClientRegistrationValidator();
};

/**
 * @return \Oauth\Services\Validators\Validator
 */
$container['ClientAttribute'] = function () {
    $validator = new \Oauth\Services\Validators\AttributeValidator();
    return $validator
            ->add('clientId', new \Oauth\Services\Validators\Rules\ClientIdentificationRule(true));
};

/**
 * @return \Oauth\Services\Validators\Validator
 */
$container['ClientQueryParameter'] = function () {
    $validator = new \Oauth\Services\Validators\QueryValidator();
    return $validator
            ->add('credentials', new \Oauth\Services\Validators\Rules\CredentialRule(false));
};

/**
 * @return \Oauth\Services\Validators\Validator
 */
$container['SignQueryParameter'] = function () {
    $validator = new \Oauth\Services\Validators\QueryValidator();
    return $validator
            ->add('client_id', new \Oauth\Services\Validators\Rules\ClientIdentificationRule(true))
            ->add('redirect_uri', new \Oauth\Services\Validators\Rules\QRedirectUriRule(false))
            ->add('audience', new \Oauth\Services\Validators\Rules\AudienceRule(true));
};

/**
 * @return \Oauth\Services\Validators\Validator
 */
$container['LoginParameter'] = function () {
    $validator = new \Oauth\Services\Validators\ParameterValidator();
    return $validator
            ->add('username', new \Oauth\Services\Validators\Rules\UserNameRule(true))
            ->add('scope', new \Oauth\Services\Validators\Rules\ScopeRule(false))
            ->add('password', new \Oauth\Services\Validators\Rules\UserPasswordRule(true))
            ->add('unique_identifier', new \Oauth\Services\Validators\Rules\TokenRule(true))
            ->add('token_authenticity', new \Oauth\Services\Validators\Rules\TokenRule(true));
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
$container['CompressionMethodManager'] = function () {
    return \Jose\Component\Encryption\Compression\CompressionMethodManager::create([
      new \Jose\Component\Encryption\Compression\Deflate()
    ]);
};

$container['ViewRender'] = function (ContainerInterface $c) {
      $view = new \Slim\Views\Twig(__DIR__ . getenv('TEMPLATE_DIR'), [
          'cache' => false // __DIR__ . getenv('CACHE_DIR')
      ]);

    // Instantiate and add Slim specific extension
    $basePath = rtrim(str_ireplace('index.php', '', $c->get('request')->getUri()->getBasePath()), '/');
    $view->addExtension(new Slim\Views\TwigExtension($c->get('router'), $basePath));

    return $view;
};

/**
 * @return \Monolog\Logger
 */
$container['DebugLogger'] = function () {
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
 * @return Memcached
 */
$container['Memcached'] = function () {
    $mc = new Memcached();
    if (empty($mc->getServerByKey('memcached'))) {
        $mc->addServer('memcached', 11211);
    }
    return $mc;
};

/**
 * @return PDO Connexion
 */
$container['Pdo'] = function () {
    $pdo = new PDO('mysql:host=' . getenv('DB_HOST') . ';' . 'dbname=' . getenv('DB_NAME') . ';charset=utf8', getenv('DB_USER'), getenv('DB_PASSWORD'));
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $pdo;
};
