<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/30/18
 * Time: 1:06 PM
 */

namespace Oauth\Controllers;

use Oauth\Services\Validators\ValidatorManagerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class ClientRegistrationController
{
    /** @var ValidatorManagerInterface  */
    private $requestValidatorManager;

    public function __construct(ValidatorManagerInterface $requestValidatorManager)
    {
        $this->requestValidatorManager = $requestValidatorManager;
    }

    public function __invoke(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface
    {
        $body = $response->getBody();

        if ($this->requestValidatorManager->validate(['registration'], $request)) {
            $body->write(json_encode(['msg' => 'created']));
            return $response->withBody($body)->withHeader('Content-Type', 'application/json')->withStatus(201);
        }

        $body->write(json_encode(['errors' => $this->requestValidatorManager->getErrorsMessages()]));
        return $response->withBody($body)->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
}
