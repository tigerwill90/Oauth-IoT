<?php

use Psr\Container\ContainerInterface;

$container = $app->getContainer();

/**
 * @param ContainerInterface $c
 * @return \Oauth\Controllers\IntrospectionEndpoint
 */
$container[\Oauth\Controllers\IntrospectionEndpoint::class] = function (ContainerInterface $c) : \Oauth\Controllers\IntrospectionEndpoint
{
    return new \Oauth\Controllers\IntrospectionEndpoint($c->get('IntrospectionService'), $c->get('PdoResourceStorage'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Controllers\TokenEndpoint
 */
$container[\Oauth\Controllers\TokenEndpoint::class] = function (ContainerInterface $c) : \Oauth\Controllers\TokenEndpoint
{
    return new \Oauth\Controllers\TokenEndpoint($c->get('TokenManager'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Controllers\AuthorizationEndpoint
 */
$container[\Oauth\Controllers\AuthorizationEndpoint::class] = function (ContainerInterface $c) : \Oauth\Controllers\AuthorizationEndpoint
{
    return new \Oauth\Controllers\AuthorizationEndpoint($c->get('AuthorizationManager'), $c->get('ViewRender'), $c->get('ValidatorManager'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Controllers\CreateClientController
 */
$container[\Oauth\Controllers\CreateClientController::class] = function (ContainerInterface $c) : \Oauth\Controllers\CreateClientController
{
    return new \Oauth\Controllers\CreateClientController($c->get('ValidatorManager'), $c->get('ClientRegister'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Controllers\DeleteClientController
 */
$container[\Oauth\Controllers\DeleteClientController::class] = function (ContainerInterface $c) : \Oauth\Controllers\DeleteClientController
{
    return new \Oauth\Controllers\DeleteClientController($c->get('ValidatorManager'), $c->get('ClientRegister'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Controllers\UpdateClientController
 */
$container[\Oauth\Controllers\UpdateClientController::class] = function (ContainerInterface $c) : \Oauth\Controllers\UpdateClientController
{
    return new \Oauth\Controllers\UpdateClientController($c->get('ValidatorManager'), $c->get('ClientRegister'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Token\TokenManager
 */
$container['TokenManager'] = function (ContainerInterface $c) : \Oauth\Services\Token\TokenManager
{
    $tokenManager = new \Oauth\Services\Token\TokenManager($c->get('DebugLogger'));
    return $tokenManager
        ->add('authorization_code', $c->get('AuthorizationCodeGrantToken'))
        ->add('refresh_token', $c->get('RefreshTokenGrantToken'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Token\AuthorizationCodeGrant
 */
$container['AuthorizationCodeGrantToken'] = function (ContainerInterface $c) : \Oauth\Services\Token\AuthorizationCodeGrant
{
    return new \Oauth\Services\Token\AuthorizationCodeGrant($c->get('IntrospectionService'), $c->get('PdoClientStorage'), $c->get('PdoResourceStorage'), $c->get('Memcached'), $c->get('RandomFactory'), $c->get('JoseHelper'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Token\RefreshGrant
 */
$container['RefreshTokenGrantToken'] = function (ContainerInterface $c) : \Oauth\Services\Token\RefreshGrant
{
    return new  \Oauth\Services\Token\RefreshGrant($c->get('IntrospectionService'), $c->get('PdoClientStorage'), $c->get('PdoResourceStorage'), $c->get('Memcached'), $c->get('RandomFactory'), $c->get('JoseHelper'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Introspection
 */
$container['IntrospectionService'] = function (ContainerInterface $c) : \Oauth\Services\Introspection
{
    return new \Oauth\Services\Introspection($c->get('JoseHelper'), $c->get('AlgorithmManagerHelper'), $c->get('ClaimsCheckerManager'), $c->get('AesHelper'), $c->get('Memcached'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Authorization\AuthorizationManager
 */
$container['AuthorizationManager'] = function (ContainerInterface $c) : \Oauth\Services\Authorization\AuthorizationManager
{
    $authenticationManager = new \Oauth\Services\Authorization\AuthorizationManager($c->get('Memcached'), $c->get('DebugLogger'));
    return $authenticationManager
            ->add('token', $c->get('ImplicitGrant'))
            ->add('code', $c->get('AuthorizationCodeGrant'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Authorization\ImplicitGrant
 */
$container['ImplicitGrant'] = function (ContainerInterface $c) : \Oauth\Services\Authorization\ImplicitGrant
{
    return new \Oauth\Services\Authorization\ImplicitGrant($c->get('PdoClientStorage'), $c->get('PdoUserStorage'), $c->get('PdoResourceStorage'), $c->get('RandomFactory'), $c->get('JoseHelper'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Authorization\AuthorizationCodeGrant
 */
$container['AuthorizationCodeGrant'] = function (ContainerInterface $c) : \Oauth\Services\Authorization\AuthorizationCodeGrant
{
    return new \Oauth\Services\Authorization\AuthorizationCodeGrant($c->get('PdoClientStorage'), $c->get('PdoUserStorage'), $c->get('PdoResourceStorage'), $c->get('RandomFactory'), $c->get('JoseHelper'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\ClaimsCheckerManager
 */
$container['ClaimsCheckerManager'] = function (ContainerInterface $c) : \Oauth\Services\ClaimsCheckerManager
{
    $claimsCheckerManager = new \Oauth\Services\ClaimsCheckerManager();
    return $claimsCheckerManager
        ->add('standard', new \Oauth\Services\StandardRules($c->get('Memcached')))
        ->add('code', new \Oauth\Services\CodeRules($c->get('Memcached')))
        ->add('refresh', new \Oauth\Services\RefreshRules());
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Helpers\JoseHelper
 */
$container['JoseHelper'] = function (ContainerInterface $c) : \Oauth\Services\Helpers\JoseHelper
{
    return new \Oauth\Services\Helpers\JoseHelper($c->get('AlgorithmManagerFactory'), $c->get('CompressionMethodManager'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Helpers\AlgorithmManagerHelper
 */
$container['AlgorithmManagerHelper'] = function (ContainerInterface $c) : \Oauth\Services\Helpers\AlgorithmManagerHelper
{
    return new Oauth\Services\Helpers\AlgorithmManagerHelper($c->get('AlgorithmManagerFactory'));
};

/**
 * @return \Oauth\Services\Helpers\AesHelper
 */
$container['AesHelper'] = function () : \Oauth\Services\Helpers\AesHelper
{
    return new \Oauth\Services\Helpers\AesHelper();
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Registrations\ClientRegister
 */
$container['ClientRegister'] = function (ContainerInterface $c) : \Oauth\Services\Registrations\ClientRegister
{
    return  new \Oauth\Services\Registrations\ClientRegister($c->get('PdoClientStorage'), $c->get('PdoResourceStorage'), $c->get('RandomFactory'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Storage\PDOClientStorage
 */
$container['PdoClientStorage'] = function (ContainerInterface $c) : \Oauth\Services\Storage\PDOClientStorage
{
    return new \Oauth\Services\Storage\PDOClientStorage($c->get('Pdo'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Storage\PDOUserStorage
 */
$container['PdoUserStorage'] = function (ContainerInterface $c) : \Oauth\Services\Storage\PDOUserStorage
{
    return new \Oauth\Services\Storage\PDOUserStorage($c->get('Pdo'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Storage\PDOResourceStorage
 */
$container['PdoResourceStorage'] = function (ContainerInterface $c) : \Oauth\Services\Storage\PDOResourceStorage
{
    return new \Oauth\Services\Storage\PDOResourceStorage($c->get('Pdo'), $c->get('DebugLogger'));
};

/**
 * @param ContainerInterface $c
 * @return \Oauth\Services\Validators\ValidatorManagerInterface
 */
$container['ValidatorManager'] = function (ContainerInterface $c) : \Oauth\Services\Validators\ValidatorManagerInterface
{
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
$container['ClientParameter'] = function () : \Oauth\Services\Validators\CustomValidators\ClientRegistrationValidator
{
    return new \Oauth\Services\Validators\CustomValidators\ClientRegistrationValidator();
};

/**
 * @return \Oauth\Services\Validators\Validator
 */
$container['ClientAttribute'] = function () : \Oauth\Services\Validators\Validator
{
    $validator = new \Oauth\Services\Validators\AttributeValidator();
    return $validator
            ->add('clientId', new \Oauth\Services\Validators\Rules\ClientIdentificationRule(true));
};

/**
 * @return \Oauth\Services\Validators\Validator
 */
$container['ClientQueryParameter'] = function () : \Oauth\Services\Validators\Validator
{
    $validator = new \Oauth\Services\Validators\QueryValidator();
    return $validator
            ->add('credentials', new \Oauth\Services\Validators\Rules\CredentialRule(false));
};

/**
 * @return \Oauth\Services\Validators\Validator
 */
$container['SignQueryParameter'] = function () : \Oauth\Services\Validators\Validator
{
    $validator = new \Oauth\Services\Validators\QueryValidator();
    return $validator
            ->add('client_id', new \Oauth\Services\Validators\Rules\ClientIdentificationRule(true))
            ->add('redirect_uri', new \Oauth\Services\Validators\Rules\QRedirectUriRule(false))
            ->add('audience', new \Oauth\Services\Validators\Rules\AudienceRule(true));
};

/**
 * @return \Oauth\Services\Validators\Validator
 */
$container['LoginParameter'] = function () : \Oauth\Services\Validators\Validator
{
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
$container['RandomFactory'] = function () : \RandomLib\Generator
{
    $factory = new \RandomLib\Factory();
    return $factory->getGenerator(new \SecurityLib\Strength(\SecurityLib\Strength::MEDIUM));
};

/**
 * @return \Jose\Component\Core\AlgorithmManagerFactory
 */
$container['AlgorithmManagerFactory'] = function () : \Jose\Component\Core\AlgorithmManagerFactory
{
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
$container['CompressionMethodManager'] = function () : \Jose\Component\Encryption\Compression\CompressionMethodManager
{
    return \Jose\Component\Encryption\Compression\CompressionMethodManager::create([
      new \Jose\Component\Encryption\Compression\Deflate()
    ]);
};

/**
 * @param ContainerInterface $c
 * @return \Slim\Views\Twig
 */
$container['ViewRender'] = function (ContainerInterface $c) : \Slim\Views\Twig
{
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
$container['DebugLogger'] = function () : \Monolog\Logger
{
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
$container['Memcached'] = function () : Memcached
{
    $mc = new Memcached();
    if (empty($mc->getServerByKey('memcached'))) {
        $mc->addServer('memcached', 11211);
    }
    return $mc;
};

/**
 * @return PDO Connexion
 */
$container['Pdo'] = function () : PDO
{
    $pdo = new PDO('mysql:host=' . getenv('DB_HOST') . ';' . 'dbname=' . getenv('DB_NAME') . ';charset=utf8', getenv('DB_USER'), getenv('DB_PASSWORD'));
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $pdo;
};
