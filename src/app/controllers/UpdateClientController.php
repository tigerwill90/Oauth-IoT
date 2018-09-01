<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 01.09.2018
 * Time: 16:58
 */

namespace Oauth\Controllers;


use Oauth\Services\Clients\Client;
use Oauth\Services\Exceptions\Storage\NoEntityException;
use Oauth\Services\Exceptions\ValidatorException;
use Oauth\Services\Registrations\ClientRegister;
use Oauth\Services\Validators\ValidatorManagerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Slim\Exception\NotFoundException;

final class UpdateClientController
{
    /** @var ValidatorManagerInterface  */
    private $requestValidatorManager;

    /** @var ClientRegister */
    private $clientRegister;

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
        $queryParams = $request->getQueryParams();
        $body = $response->getBody();
        // PUT complete update
        if ($request->getMethod() === 'PUT') {
            if ($this->requestValidatorManager->validate(['register', 'unregister'], $request)) {
                $client = new Client($request->getParsedBody());
                $client->setClientIdentification($request->getAttribute('clientId'));
                try {
                    $this->clientRegister->update($client);
                } catch (ValidatorException $e) {
                    $body->write(json_encode(['message' => $e->getMessage()]));
                    return $response->withBody($body)->withHeader('content-type', 'application/json')->withStatus(400);
                } catch (NoEntityException $e) {
                    throw new NotFoundException($request, $response);
                }
                $body->write(json_encode($client->getRegistrationInformation()));
                return $response->withBody($body)->withStatus(200)->withHeader('content-type', 'application/json');
            }
            $body->write(json_encode($this->requestValidatorManager->getErrorsMessages()));
            return $response->withBody($body)->withHeader('content-type', 'application/json')->withStatus(400);
        }
        // PATCH secret or identification update
        if (!$this->requestValidatorManager->validate(['unregister'], $request)) {
            $body->write(json_encode($this->requestValidatorManager->getErrorsMessages()));
            return $response->withBody($body)->withHeader('content-type', 'application/json')->withStatus(400);
        }

        if (null !== $queryParams['field']) {
            if ($queryParams['field'] === 'client_identification') {
                try {
                    $client = $this->clientRegister->updateIdentification($request->getAttribute('clientId'));
                } catch (ValidatorException $e) {
                    $body->write(json_encode(['message' => $e->getMessage()]));
                    return $response->withBody($body)->withHeader('content-type', 'application/json')->withStatus(400);
                } catch (NoEntityException $e) {
                    throw new NotFoundException($request, $response);
                }
                $body->write(json_encode($client->getRegistrationInformation()));
            }
            if ($queryParams['field'] === 'client_secret') {
                try {
                    $client = $this->clientRegister->updateSecret($request->getAttribute('clientId'));
                } catch (ValidatorException $e) {
                    $body->write(json_encode(['message' => $e->getMessage()]));
                    return $response->withBody($body)->withHeader('content-type', 'application/json')->withStatus(400);
                } catch (NoEntityException $e) {
                    throw new NotFoundException($request, $response);
                }
                $body->write(json_encode($client->getRegistrationInformation()));
            }
        }
        return $response->withStatus(200)->withHeader('content-type', 'application/json');
    }

    /**
     * @param string $message
     * @param array $context
     * @return UpdateClientController
     */
    private function log(string $message, array $context = []) : self
    {
        if (null !== $this->logger) {
            $this->logger->debug($message, $context);
        }
        return $this;
    }
}