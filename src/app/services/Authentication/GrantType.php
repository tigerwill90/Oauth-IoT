<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 22:01
 */

namespace Oauth\Services\Authentication;

use Oauth\Services\Clients\ClientInterface;
use Oauth\Services\Exceptions\Storage\NoEntityException;
use Oauth\Services\Resources\ResourceInterface;
use Oauth\Services\Storage\ClientStorageInterface;
use Oauth\Services\Storage\ResourceStorageInterface;
use Oauth\Services\Storage\UserStorageInterface;
use Memcached;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

abstract class GrantType
{
    protected const CACHING_TIME = 300;

    /** @var ClientStorageInterface  */
    protected $clientStorage;

    /** @var UserStorageInterface  */
    protected $userStorage;

    /** @var ResourceStorageInterface  */
    protected $resourceStorage;

    /** @var array */
    protected $errorsMessages = [];

    /** @var ClientInterface */
    protected $client;

    /** @var ResourceInterface */
    protected $resource;

    /** @var string */
    protected $redirectUriTarget;

    /** @var LoggerInterface  */
    protected $logger;

    public function __construct(ClientStorageInterface $clientStorage, UserStorageInterface $userStorage, ResourceStorageInterface $resourceStorage, LoggerInterface $logger = null)
    {
        $this->clientStorage = $clientStorage;
        $this->userStorage = $userStorage;
        $this->resourceStorage = $resourceStorage;
        $this->logger = $logger;
    }

    /**
     * RFC 6749
     * Section 4 Obtaining Authorization
     * Section 4.2 Implicit Grant
     * @param ServerRequestInterface $request
     * @return GrantType
     * @throws NoRedirectErrorException
     */
    public function authenticateClient(ServerRequestInterface $request) : self
    {
        $queryParameters = $request->getQueryParams();
        try {
            $this->client = $this->clientStorage->fetch($queryParameters['client_id']);
        } catch (NoEntityException $e) {
            // RFC 6749 4.2.2.1 error response without redirect
            throw new NoRedirectErrorException('This client does not exist');
        }
        return $this;
    }

    /**
     * @param ServerRequestInterface $request
     * @return bool
     * @throws NoRedirectErrorException
     */
    public function validateRequest(ServerRequestInterface $request) : bool
    {
        $queryParameters = $request->getQueryParams();
        // Check redirect_uri
        if (!\in_array($queryParameters['redirect_uri'], $this->client->getRedirectUri(), true)) {
            // RFC 6749 4.2.2.1 error response without redirect
            throw new NoRedirectErrorException('This redirect uri is not configured for this client');
        }

        $this->redirectUriTarget = $queryParameters['redirect_uri'];
        return true;
    }

    /**
     * Authenticate a user
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     */
    public function authenticateUser(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface
    {
        return $response;
    }

    /**
     * @param ServerRequestInterface $request
     * @param Memcached $mc
     * @param string $uniqueIdentifier
     * @param string $tokenAuthenticity
     * @return GrantType
     */
    abstract public function cacheAuthenticationData(ServerRequestInterface $request, Memcached $mc, string $uniqueIdentifier, string $tokenAuthenticity) : self;

    /**
     * @param ServerRequestInterface $request
     * @return bool
     */
    abstract public function invalidGrantType(ServerRequestInterface $request) : bool;

    /**
     * @return ResourceInterface
     */
    public function getResource() : ResourceInterface
    {
        return $this->resource;
    }

    /**
     * @return ClientInterface
     */
    public function getClient() : ClientInterface
    {
        return $this->client;
    }

    /**
     * @return string
     */
    public function getRedirectUriTarget() : string
    {
        return $this->redirectUriTarget;
    }

    /**
     * @return array
     */
    public function getErrorsMessages() : array
    {
        return $this->errorsMessages;
    }

    /**
     * @param string $message
     * @param array $context
     * @return GrantType
     */
    protected function log(string $message, array $context = []) : self
    {
        if (null !== $this->logger) {
            $this->logger->debug($message, $context);
        }
        return $this;
    }
}
