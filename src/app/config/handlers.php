<?php

/**
 * Slim error handler
 * @param \Psr\Container\ContainerInterface $c
 * @return Closure
 */
$container['errorHandler'] = function (\Psr\Container\ContainerInterface $c) {
    return function (\Psr\Http\Message\ServerRequestInterface $request,\Psr\Http\Message\ResponseInterface $response, Exception $e) use ($c) {
        $logger = $c->get('debugLogger');
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