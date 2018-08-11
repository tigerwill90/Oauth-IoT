<?php

/**
 * Slim error handler
 * @param \Psr\Container\ContainerInterface $c
 * @return Closure
 */
$container['errorHandler'] = function (\Psr\Container\ContainerInterface $c) {
    return function (\Psr\Http\Message\ServerRequestInterface $request,\Psr\Http\Message\ResponseInterface $response, Exception $e) use ($c) {
        error_log('Code : ' . $e->getCode() . ' File : ' . $e->getFile() . ' Line : ' . $e->getLine() . ' Message : ' . $e->getMessage());
        $body = $response->getBody();
        $body->write(json_encode(['error' => $e->getMessage()]));
        $newResponse = $response
            ->withStatus(500)
            ->withBody($body)
            ->withHeader('Content-Type', 'application/json');
        return $newResponse;
    };
};