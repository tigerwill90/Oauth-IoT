<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 22:01
 */

namespace Oauth\Services\Authorization;

use Oauth\Services\Clients\ClientInterface;
use Oauth\Services\Exceptions\Storage\NoEntityException;
use Oauth\Services\Helpers\JoseHelperInterface;
use Oauth\Services\Resources\ResourceInterface;
use Oauth\Services\Storage\ClientStorageInterface;
use Oauth\Services\Storage\ResourceStorageInterface;
use Oauth\Services\Storage\UserStorageInterface;
use Memcached;
use Psr\Log\LoggerInterface;
use RandomLib\Generator;

abstract class AuthorizationGrantType
{
    protected const CACHING_TIME = 300;

    protected const COOL_DOWN = 5;

    // Alphanumeric characters
    protected const TOKEN_CHAR_GEN = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

    /** @var ClientStorageInterface  */
    protected $clientStorage;

    /** @var UserStorageInterface  */
    protected $userStorage;

    /** @var ResourceStorageInterface  */
    protected $resourceStorage;

    /** @var Generator */
    protected $generator;

    /** @var JoseHelperInterface */
    protected $joseHelper;

    /** @var array */
    protected $errorsMessages = [];

    /** @var ClientInterface */
    protected $client;

    /** @var ResourceInterface */
    protected $resource;

    /** @var string */
    protected $redirectUriTarget;

    /** @var string */
    protected $uniqueIdentifier;

    /** @var string */
    protected $state;

    /** @var string */
    protected $tokenAuthenticity;

    /** @var string */
    protected $grantMethod;

    /** @var LoggerInterface  */
    protected $logger;

    public function __construct(ClientStorageInterface $clientStorage, UserStorageInterface $userStorage, ResourceStorageInterface $resourceStorage, Generator $generator, JoseHelperInterface $joseHelper, LoggerInterface $logger = null)
    {
        $this->clientStorage = $clientStorage;
        $this->userStorage = $userStorage;
        $this->resourceStorage = $resourceStorage;
        $this->generator = $generator;
        $this->joseHelper = $joseHelper;
        $this->logger = $logger;
    }

    /**
     * RFC 6749
     * Section 4 Obtaining Authorization
     * Section 4.2 Implicit Grant
     * @param array $queryParameters
     * @return AuthorizationGrantType
     * @throws NoRedirectErrorException
     */
    public function authenticateClient(array $queryParameters) : self
    {
        try {
            $this->client = $this->clientStorage->fetch($queryParameters['client_id']);
        } catch (NoEntityException $e) {
            // RFC 6749 4.2.2.1 error response without redirect
            throw new NoRedirectErrorException('This client does not exist');
        }
        return $this;
    }

    /**
     * @param array $queryParameters
     * @return AuthorizationGrantType
     * @throws NoRedirectErrorException
     */
    public function validateRedirectUri(array $queryParameters) : self
    {
        // Check redirect_uri
        $redirectsUri = $this->client->getRedirectUri();
        $nbUri = count($redirectsUri);
        if ($nbUri > 1 && null === $queryParameters['redirect_uri']) {
            throw new NoRedirectErrorException('A redirect uri query parameter is required');
        }

        if (null !== $queryParameters['redirect_uri'] && !\in_array($queryParameters['redirect_uri'], $redirectsUri, true)) {
            // RFC 6749 4.2.2.1 error response without redirect
            throw new NoRedirectErrorException('This redirect uri is not configured for this client');
        }

        if (null === $queryParameters['redirect_uri']) {
            $this->redirectUriTarget = $redirectsUri[0];
        } else {
            $key = array_search($queryParameters['redirect_uri'], $redirectsUri, true);
            $this->redirectUriTarget = $redirectsUri[$key];
        }
        return $this;
    }

    /**
     * @param array $queryParameters
     * @return bool
     * @throws NoRedirectErrorException
     */
    /**
     * @param array $queryParameters
     * @return bool
     * @throws NoRedirectErrorException
     */
    public function validateRequest(array $queryParameters): bool
    {
        $this->grantMethod = $queryParameters['response_type'];

        if (null === $queryParameters['state']) {
            $this->errorsMessages['error'] = 'invalid_request';
            $this->errorsMessages['error_description'] = 'State parameter is missing';
            return false;
        }

        if (!ctype_alnum($queryParameters['state'])) {
            $this->errorsMessages['error'] = 'invalid_request';
            $this->errorsMessages['error_description'] = 'State parameter must be an alphanumeric string';
            return false;
        }

        $this->state = $queryParameters['state'];

        $queryScope = explode(' ', $queryParameters['scope']);
        // Array with invalid scope request
        $scopeOut = array_filter(array_diff($queryScope,$this->client->getScope()), '\strlen');
        // Array with correct scope request (maybe unnecessary)
        $correctedScope = array_filter(array_diff($queryScope, $scopeOut), '\strlen');
        if (!empty($scopeOut)) {
            $this->errorsMessages['error'] = 'invalid_scope';
            $this->errorsMessages['error_description'] = 'This client have no access for this scope element ' . implode('&', $scopeOut);
            $this->errorsMessages['state'] = $this->state;
            return false;
        }

        if ($this->client->getGrantType() !== $queryParameters['response_type']) {
            $this->errorsMessages['error'] = 'unauthorized_client';
            $this->errorsMessages['error_description'] = 'This client is not authorized to request an access token using ' . $queryParameters['response_type'] . 'method';
            $this->errorsMessages['state'] = $this->state;
            return false;
        }

        try {
            // allow maybe more than one audience
            $this->resource = $this->resourceStorage->fetchByAudience($queryParameters['audience']);
            $scopes = $this->resource->getScope();
            // delete not needed scope
            foreach ($scopes as $i =>  $scope) {
                if (!\in_array($scope->getService(), $correctedScope, true)) {
                    unset($scopes[$i]);
                }
            }

            $this->resource->setScope($scopes);

        } catch (NoEntityException $e) {
            throw new NoRedirectErrorException('This resource does not exist');
        }

        return true;
    }

    /**
     * Authenticate a user
     * @param array $params
     * @return AuthorizationGrantType
     * @throws InvalidCredential
     */
    public function authenticateUser(array $params) : self
    {
        try {
            $user = $this->userStorage->fetchByUsername($params['username']);
            if (!password_verify($params['password'], $user->getPassword())) {
                throw new InvalidCredential('Password mismatch for this entity');
            }
        } catch (NoEntityException $e) {
            throw new InvalidCredential('No entity found for this user');
        }
        return $this;
    }

    /**
     * @param array $params
     * @return AuthorizationGrantType
     * @throws NoRedirectErrorException
     */
    public function validateScope(array $params) : self
    {
        $scopes = [];
        foreach($this->resource->getScope() as $scope) {
            $scopes[] = $scope->getService();
        }

        if (null !== $params['scope'] && !empty(array_diff($params['scope'], $scopes))) {
            throw new NoRedirectErrorException('Invalid scope');
        }
        return $this;
    }

    /**
     * @param Memcached $mc
     * @return ImplicitGrant
     * @throws \ErrorException
     */
    public function cacheAuthenticationData(Memcached $mc) : self
    {
        $this->tokenAuthenticity = $this->generator->generateString(32, self::TOKEN_CHAR_GEN);
        // Get a unique identifier
        $break = 0;
        while (true) {
            $uniqueIdentifier = $this->generator->generateString(8, self::TOKEN_CHAR_GEN);
            if (empty($mc->get($uniqueIdentifier))) {
                $this->uniqueIdentifier = $uniqueIdentifier;
                // Cache data
                $mc->add($uniqueIdentifier, [
                    'state' => $this->state,
                    'token_authenticity' => $this->tokenAuthenticity,
                    'client' => $this->client,
                    'resource' => $this->resource,
                    'redirect_uri_target' => $this->redirectUriTarget,
                    'grant_method' => $this->grantMethod
                ], self::CACHING_TIME);
                break;
            }
            if ($break >= self::COOL_DOWN) {
                throw new \ErrorException('Impossible to create an unique identifier');
            }
            $break++;
        }
        return $this;
    }

    /**
     * @param string $uniquerIdentifier
     * @param array $cache
     * @return AuthorizationGrantType
     */
    public function populateFromCache(string $uniquerIdentifier, array $cache) : self
    {
        $this->uniqueIdentifier = $uniquerIdentifier;
        $this->state = $cache['state'];
        $this->tokenAuthenticity = $cache['token_authenticity'];
        $this->client = (object)$cache['client'];
        $this->resource = (object)$cache['resource'];
        $this->redirectUriTarget = $cache['redirect_uri_target'];
        $this->grantMethod = $cache['grant_method'];
        return $this;
    }

    /**
     * @param string $uniquerIdentifier
     * @param Memcached $mc
     * @return AuthorizationGrantType
     */
    public function updateCache(string $uniquerIdentifier, Memcached $mc) : self
    {
        $this->tokenAuthenticity = $this->generator->generateString(32, self::TOKEN_CHAR_GEN);
        $mc->replace($uniquerIdentifier, [
            'state' => $this->state,
            'token_authenticity' => $this->tokenAuthenticity,
            'client' => $this->client,
            'resource' => $this->resource,
            'redirect_uri_target' => $this->redirectUriTarget,
            'grant_method' => $this->grantMethod
        ], self::CACHING_TIME);
        return $this;
    }


    /**
     * @param array $queryParameters
     * @return AuthorizationGrantType
     */
    abstract public function invalidGrantType(array $queryParameters) : self;

    /**
     * RFC 6749
     * Section 3.1.2 Redirection endpoint and url encoding style
     * @param array $cache
     * @param array $params
     * @param Memcached $mc
     * @return string
     */
    abstract public function getQueryResponse(array $cache, array $params, Memcached $mc) : string;

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
    public function getUniqueIdentifier() : string
    {
        return $this->uniqueIdentifier;
    }

    /**
     * @return string
     */
    public function getTokenAuthenticity() : string
    {
        return $this->tokenAuthenticity;
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
     * @return AuthorizationGrantType
     */
    protected function log(string $message, array $context = []) : self
    {
        if (null !== $this->logger) {
            $this->logger->debug($message, $context);
        }
        return $this;
    }
}
