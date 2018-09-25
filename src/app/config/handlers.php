<?php

use \Psr\Container\ContainerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Slim error handler
 * @param \Psr\Container\ContainerInterface $c
 * @return Closure
 */
$container['errorHandler'] = function (ContainerInterface $c) {
    return function (ServerRequestInterface $request, ResponseInterface $response, Exception $e) use ($c) {
        $logger = $c->get('DebugLogger');
        $logger->info('Code : ' . $e->getCode() . ' File : ' . $e->getFile() . ' Line : ' . $e->getLine() . ' Message : ' . $e->getMessage() . ' Trace . ' . $e->getTraceAsString());
        $body = $response->getBody();
        $body->write(json_encode(['error' => 'something goes wrong']));

        $newResponse = $response
            ->withStatus(500)
            ->withBody($body)
            ->withHeader('Content-Type', 'application/json');

        return $newResponse;
    };
};

/**
 * Slim not allowed handler
 * @param ContainerInterface $c
 * @return Closure
 */
$container['notAllowedHandler'] = function (ContainerInterface $c) {
    return function (ServerRequestInterface $request, ResponseInterface $response, array $methods) use ($c) {
        $body = $response->getBody();
        $body->write(json_encode(['error' => 'method not allowed']));

        $newResponse = $response
            ->withStatus(405)
            ->withHeader('Allow', implode(', ', $methods))
            ->withHeader('Content-Type', 'application/json');

        return $newResponse;
    };
};

/**
 * Slim not found handler
 * @param ContainerInterface $c
 * @return Closure
 */
$container['notFoundHandler'] = function (ContainerInterface $c) {
  return function (ServerRequestInterface $request, ResponseInterface $response) use ($c) {
      $logger = $c->get('DebugLogger');
      $logger->info($request->getUri());
      $body = $response->getBody();
      $body->write(json_encode(['error' => 'resource not found']));

      $newResponse = $response
          ->withStatus(404)
          ->withHeader('Content-Type', 'application/json');

      return $newResponse;
  };
};