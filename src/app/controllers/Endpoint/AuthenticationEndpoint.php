<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 3:22 PM
 */

namespace Oauth\Controllers;

use Oauth\Services\Authentication\AuthenticationManager;
use Oauth\services\Authentication\NoRedirectErrorException;
use Oauth\Services\Validators\ValidatorManagerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Slim\Views\Twig;

class AuthenticationEndpoint
{
    /** @var AuthenticationManager  */
    private $authenticationManager;

    /** @var Twig  */
    private $view;
    
    /** @var ValidatorManagerInterface  */
    private $validatorManager;

    /** @var LoggerInterface  */
    private $logger;

    public function __construct(AuthenticationManager $authenticationManager, Twig $view, ValidatorManagerInterface $validatorManager, LoggerInterface $logger = null)
    {
        $this->authenticationManager = $authenticationManager;
        $this->view = $view;
        $this->validatorManager = $validatorManager;
        $this->logger = $logger;
    }

    /**
     * RFC 6749 Protocol Endpoints
     * Section 3.1 Authorization Endpoint
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     * @throws \Exception
     */
    public function sign(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface
    {
        if (!$this->validatorManager->validate(['sign'], $request)) {
            return $this->view->render($response, 'badRequest.twig')->withStatus(400)->withHeader('content-type', 'text/html');
        }

        try {
            if (!$this->authenticationManager->authorizeClient($request)) {
                $errors = $this->authenticationManager->getErrorsMessages();
                $redirectUri = $this->authenticationManager->getRedirectionUri() . '?error=' . $errors['type'] . '&error_description=' . $errors['description'] . ($errors['state']  !== null ? '&state=' .  $errors['state'] : '');
                return $response->withHeader('location', $redirectUri)->withStatus(302);
            }
        } catch (NoRedirectErrorException $e) {
            return $this->view->render($response, 'badRequest.twig')->withStatus(400)->withHeader('content-type', 'text/html');
        } catch (\Exception $e) {
            throw $e;
        }

        $args = [
            'title' => 'Oauth2.0',
            'scopes' => $this->authenticationManager->getResourceScope(),
            'client_name' => $this->authenticationManager->getClientName(),
            'unique_identifier' => $this->authenticationManager->getUniqueIdentifier(),
            'token_authenticity' => $this->authenticationManager->getTokenAuthenticity()
        ];
        return $this->view->render($response, 'login.twig', $args)->withStatus(200)->withHeader('content-type', 'text/html');

    }

    public function login(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface
    {
        $this->log(print_r($request->getParsedBody(), true));
        // Check for mandatory parameter
        $this->validatorManager->validate(['login'], $request);
        // TODO add token rule
        $this->log(print_r($this->validatorManager->getErrorsMessages(), true));

        return $response->withHeader('location', 'https://www.google.ch')->withStatus(301);
    }

    /**
     * @param string $message
     * @param array $context
     * @return AuthenticationEndpoint
     */
    private function log(string $message, array $context = []) : self
    {
        if (null !== $this->logger) {
            $this->logger->debug($message, $context);
        }
        return $this;
    }
}
