<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 31.08.2018
 * Time: 18:08
 */

namespace Oauth\Controllers;

use Oauth\Services\Exceptions\Storage\StorageException;
use Oauth\Services\Registrations\ClientRegister;
use Oauth\Services\Validators\ValidatorManagerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Slim\Exception\NotFoundException;

final class DeleteClientController
{
    /** @var ValidatorManagerInterface  */
    private $requestValidatorManager;

    /** @var ClientRegister  */
    private $clientRegister;

    /** @var LoggerInterface  */
    private $logger;

    public function __construct(ValidatorManagerInterface $requestValidatorManager, ClientRegister $clientRegister, LoggerInterface $logger = null)
    {
        $this->requestValidatorManager = $requestValidatorManager;
        $this->clientRegister = $clientRegister;
        $this->logger = $logger;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     * @throws NotFoundException
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface
    {
        if ($this->requestValidatorManager->validate(['unregister'], $request)) {
            try {
                $this->clientRegister->unRegister($request->getAttribute('clientId'));
            } catch (StorageException $e) {
                throw new NotFoundException($request, $response);
            }
            return $response->withStatus(204);
        }
        $body = $response->getBody();
        $body->write(json_encode($this->requestValidatorManager->getErrorsMessages()));
        return $response->withBody($body)->withHeader('content-type', 'application/json')->withStatus(400);
    }

    /**
     * @param string $message
     * @param array $context
     * @return DeleteClientController
     */
    private function log(string $message, array $context = []) : self
    {
        if (null !== $this->logger) {
            $this->logger->debug($message, $context);
        }
        return $this;
    }

}