<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 3:22 PM
 */

namespace Oauth\Controllers;

use Oauth\Services\Authentication\AuthenticationManager;
use Oauth\Services\Validators\ValidatorManagerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Slim\Views\PhpRenderer;

class AuthenticationEndpoint
{
    /** @var AuthenticationManager  */
    private $authenticationManager;

    /** @var PhpRenderer  */
    private $view;
    
    /** @var ValidatorManagerInterface  */
    private $validatorManager;

    /** @var LoggerInterface  */
    private $logger;

    public function __construct(AuthenticationManager $authenticationManager, PhpRenderer $view, ValidatorManagerInterface $validatorManager, LoggerInterface $logger = null)
    {
        $this->authenticationManager = $authenticationManager;
        $this->view = $view;
        $this->validatorManager = $validatorManager;
        $this->logger = $logger;
    }
    
    public function login(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface
    {
        $body = $response->getBody();
        if ($this->validatorManager->validate(['login'], $request)) {
            if (!$this->authenticationManager->authenticateClient($request)) {
                $body->write(json_encode($this->authenticationManager->getMessages()));
                return $response->withBody($body)->withStatus(400)->withHeader('content-type', 'application/json');
            }
            $queryParams = $request->getQueryParams();
            return $this->view->render($response, 'login.php', ['title' => 'Oauth2.0', 'scope' => explode(' ', $queryParams['scope'])])->withStatus(200);
        }
        $body->write(json_encode($this->validatorManager->getErrorsMessages()));
        return $response->withBody($body)->withStatus(400)->withHeader('content-type', 'application/json');
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
