<?php

use Psr\Container\ContainerInterface;

$container = $app->getContainer();

/**
 * Introspection controllers
 *
 * @param ContainerInterface $c
 * @return \Oauth\Controllers\IntrospectionController
 */
$container[\Oauth\Controllers\IntrospectionController::class] = function (ContainerInterface $c) {
  return new \Oauth\Controllers\IntrospectionController($c->get('IntrospectionService'));
};

$container[\Oauth\Controllers\ConnexionController::class] = function (ContainerInterface $c) {
  return new \Oauth\Controllers\ConnexionController($c->get('JoseService'));
};

/**
 * Introspection service
 * @param ContainerInterface $c
 * @return \Oauth\Services\Introspection\Introspection
 */
$container['IntrospectionService'] = function (ContainerInterface $c) {
    return new \Oauth\Services\Introspection\Introspection($c->get('JoseService'));
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

/**
 * Algorithm manager factory
 * @return \Jose\Component\Core\AlgorithmManagerFactory
 */
$container['AlgorithmManagerFactory'] = function () {
    $algorithmManagerFactory = new \Jose\Component\Core\AlgorithmManagerFactory();
    return $algorithmManagerFactory
        ->add('HS256', new \Jose\Component\Signature\Algorithm\HS256())
        ->add('HS384', new \Jose\Component\Signature\Algorithm\HS384())
        ->add('HS512', new \Jose\Component\Signature\Algorithm\HS512());
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

