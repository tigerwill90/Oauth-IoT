<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 11:19 PM
 */

namespace Oauth\Controllers;


use Oauth\Services\Token\TokenManager;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

final class TokenEndpoint
{
    /** @var TokenManager  */
    private $tokenManager;

    /** @var LoggerInterface  */
    private $logger;

    public function __construct(TokenManager $tokenManager, LoggerInterface $logger = null)
    {
        $this->tokenManager = $tokenManager;
        $this->logger = $logger;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     * @throws \Exception
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface
    {
        $body = $response->getBody();

        if (!$this->tokenManager->grantAccess($request)) {
            $body->write(json_encode($this->tokenManager->getArrayErrors()));
            return $response->withBody($body)->withStatus(401)->withHeader('content-type', 'application/json');
        }
        $body->write(json_encode($this->tokenManager->getArrayResponse()));
        return $response->withBody($body)->withStatus(200)->withHeader('content-type', 'application/json');
    }

    /**
     * @param string $message
     * @param array $context
     * @return TokenEndpoint
     */
    private function log(string $message, array $context = []) : self
    {
        if (null !== $this->logger) {
            $this->logger->debug($message, $context);
        }
        return $this;
    }
}