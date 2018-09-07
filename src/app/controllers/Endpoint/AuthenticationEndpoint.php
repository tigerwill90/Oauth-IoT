<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 3:22 PM
 */

namespace Oauth\Controllers;

use Oauth\Services\Authentication\AuthenticationTimeoutException;
use Oauth\Services\Authentication\AuthorizationManager;
use Oauth\Services\Authentication\InvalidCredential;
use Oauth\services\Authentication\NoRedirectErrorException;
use Oauth\Services\Authentication\SecurityException;
use Oauth\Services\Validators\ValidatorManagerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Slim\Views\Twig;

class AuthenticationEndpoint
{
    /** @var AuthorizationManager  */
    private $authenticationManager;

    /** @var Twig  */
    private $view;
    
    /** @var ValidatorManagerInterface  */
    private $validatorManager;

    /** @var LoggerInterface  */
    private $logger;

    public function __construct(AuthorizationManager $authenticationManager, Twig $view, ValidatorManagerInterface $validatorManager, LoggerInterface $logger = null)
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
            if (!$this->authenticationManager->authorizationRequest($request)) {
                $redirectUri = $this->authenticationManager->getRedirectionUri() . '?' . $this->authenticationManager->getQueryErrorResponse();
                return $response->withHeader('location', $redirectUri)->withStatus(302);
            }
        } catch (NoRedirectErrorException $e) {
            $args = ['error', $e->getMessage()];
            $this->log($e->getMessage());
            return $this->view->render($response, 'badRequest.twig', $args)->withStatus(400)->withHeader('content-type', 'text/html');
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

    /**d
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     */
    public function login(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface
    {
        // TODO add token rule
        $queryUrl = parse_url($request->getHeader('HTTP_REFERER')[0], PHP_URL_QUERY);
        $redirectUri = '';
        parse_str($queryUrl, $queryParams);
        try {
            $this->authenticationManager->authorizationResponse($request);
            $redirectUri = $this->authenticationManager->getRedirectionUri() . '?' . $this->authenticationManager->getQueryResponse();
        } catch (InvalidCredential $e) {
            $this->log('credentials exception');
            $args = [
                'title' => 'Oauth2.0',
                'scopes' => $this->authenticationManager->getResourceScope(),
                'client_name' => $this->authenticationManager->getClientName(),
                'unique_identifier' => $this->authenticationManager->getUniqueIdentifier(),
                'token_authenticity' => $this->authenticationManager->getTokenAuthenticity(),
                'error' => $e->getMessage()
            ];
            return $this->view->render($response, 'login.twig', $args)->withStatus(401)->withHeader('content-type', 'text/html');
        } catch (NoRedirectErrorException $e) {
            $this->log($e->getMessage());
            $args = [
                'title' => 'Oauth2.0',
                'scopes' => $this->authenticationManager->getResourceScope(),
                'client_name' => $this->authenticationManager->getClientName(),
                'unique_identifier' => $this->authenticationManager->getUniqueIdentifier(),
                'token_authenticity' => $this->authenticationManager->getTokenAuthenticity(),
                'error' => $e->getMessage()
            ];
            return $this->view->render($response, 'login.twig', $args)->withStatus(401)->withHeader('content-type', 'text/html');
        } catch (AuthenticationTimeoutException $e) {
            $this->log($e->getMessage());
            return $this->view->render($response, 'expirationException.twig', ['error' =>$e->getMessage()])->withStatus(401)->withHeader('content-type', 'text/html');
        } catch (SecurityException $e) {
            return $this->view->render($response, 'securityException.twig', ['error' =>$e->getMessage()])->withStatus(401)->withHeader('content-type', 'text/html');
        }

        return $response->withHeader('location', $redirectUri)->withStatus(302);
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
