<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/30/18
 * Time: 1:06 PM
 */

namespace Oauth\Controllers;

use Oauth\Services\Clients\Client;
use Oauth\Services\Registrations\ClientRegister;
use Oauth\Services\Validators\ValidatorManagerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class ClientRegistrationController
{
    /** @var ValidatorManagerInterface  */
    private $requestValidatorManager;

    /** @var ClientRegister */
    private $clientRegister;

    public function __construct(ValidatorManagerInterface $requestValidatorManager, ClientRegister $clientRegister)
    {
        $this->requestValidatorManager = $requestValidatorManager;
        $this->clientRegister = $clientRegister;
    }

    public function __invoke(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface
    {
        $body = $response->getBody();

        if ($this->requestValidatorManager->validate(['registration'], $request)) {
            $client = new Client($request->getParsedBody());
            $this->clientRegister->register($client);
            $body->write($this->clientRegister->getJsonResponse());
            return $response->withBody($body)->withHeader('Content-Type', 'application/json')->withStatus(201);
        }

        $body->write(json_encode(['errors' => $this->requestValidatorManager->getErrorsMessages()]));
        return $response->withBody($body)->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
}
