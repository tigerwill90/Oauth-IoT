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

/**
 * Introspection service
 * @param ContainerInterface $c
 * @return \Oauth\Services\Introspection\Introspection
 */
$container['IntrospectionService'] = function (ContainerInterface $c) {
    return new \Oauth\Services\Introspection\Introspection($c->get('JoseHelper'));
};

/**
 * Authentication service
 * @return \Oauth\Services\Authentication\Authentication
 */
$container['AuthenticationService'] = function () {
    return new \Oauth\Services\Authentication\Authentication();
};

/**
 * Jose service
 * @param ContainerInterface $c
 * @return \Oauth\Services\Jose\Jose
 */
$container['JoseService'] = function (ContainerInterface $c) {
    return new Oauth\Services\Jose\Jose($c->get('AlgorithmManagerFactory'), $c->get('StandardConverter'), $c->get('CompactSerializer'));
};

$container['JoseHelper'] = function (ContainerInterface $c) {
    return new \Oauth\Services\Jose\JoseHelper($c->get('AlgorithmManagerFactory'), $c->get('compressionMethodManager'));
};

/**
 * AesHelper Helper
 *
 * @return \Oauth\Services\AesHelper\AesHelper
 */
$container['AesHelper'] = function () {
    return new \Oauth\Services\AesHelper\AesHelper();
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
 * Compact serializer
 * @param ContainerInterface $c
 * @return \Jose\Component\Signature\Serializer\CompactSerializer
 */
$container['CompactSerializer'] = function (ContainerInterface $c) {
    return new \Jose\Component\Signature\Serializer\CompactSerializer($c->get('StandardConverter'));
};

/**
 * Standard json converter
 * @return \Jose\Component\Core\Converter\StandardConverter
 */
$container['StandardConverter'] = function () {
    return new \Jose\Component\Core\Converter\StandardConverter();
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
 * PSR-3 Logger
 * @return \Monolog\Logger
 */
$container['debugLogger'] = function () {
  $log = new \Monolog\Logger('oauth_debug');
  $stream = new \Monolog\Handler\StreamHandler(__DIR__ . '/../../logs/oauth.log', \Monolog\Logger::DEBUG);
  $log->pushHandler($stream);
  return $log;
};
