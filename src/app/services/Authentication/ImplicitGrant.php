<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 22:03
 */

namespace Oauth\Services\Authentication;

use Oauth\Services\Exceptions\Storage\NoEntityException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Memcached;

class ImplicitGrant extends GrantType
{
    /**
     * @param ServerRequestInterface $request
     * @return bool
     * @throws NoRedirectErrorException
     */
    public function validateRequest(ServerRequestInterface $request): bool
    {
        $queryParameters = $request->getQueryParams();
        // Check redirect_uri
        if (!\in_array($queryParameters['redirect_uri'], $this->client->getRedirectUri(), true)) {
            // RFC 6749 4.2.2.1 error response without redirect
            throw new NoRedirectErrorException('This redirect uri is not configured for this client');
        }

        $this->redirectUriTarget = $queryParameters['redirect_uri'];

        if (null === $queryParameters['state']) {
            $this->errorsMessages['type'] = 'invalid_request';
            $this->errorsMessages['description'] = 'State parameter is missing';
            return false;
        }

        if (!ctype_alnum($queryParameters['state'])) {
            $this->errorsMessages['type'] = 'invalid_request';
            $this->errorsMessages['description'] = 'State parameter must be an alphanumeric string';
            return false;
        }

        $queryScope = explode(' ', $queryParameters['scope']);
        $scopeOut = array_diff($queryScope,$this->client->getScope());
        $correctedScope = array_diff($queryScope, $scopeOut);
        if (!empty($scopeOut)) {
            $this->errorsMessages['type'] = 'invalid_scope';
            $this->errorsMessages['description'] = 'This client have no access for this scope element ' . implode('&', $scopeOut);
            $this->errorsMessages['state'] = $queryParameters['state'];
            return false;
        }

        if ($this->client->getGrantType() !== $queryParameters['response_type']) {
            $this->errorsMessages['type'] = 'unauthorized_client';
            $this->errorsMessages['description'] = 'This client is not authorized to request an access token using ' . $queryParameters['response_type'] . 'method';
            $this->errorsMessages['state'] = $queryParameters['state'];
            return false;
        }

        try {
            // allow maybe more than one audience
            $this->resource = $this->resourceStorage->fetchByAudience($queryParameters['audience']);
            $scopes = $this->resource->getScope();
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
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     */
    public function authenticateUser(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface
    {
        $params = $request->getParsedBody();
    }

    /**
     * @param ServerRequestInterface $request
     * @param Memcached $mc
     * @param string $uniqueIdentifier
     * @param string $tokenAuthenticity
     * @return ImplicitGrant
     */
    public function cacheAuthenticationData(ServerRequestInterface $request, Memcached $mc, string $uniqueIdentifier, string $tokenAuthenticity) : GrantType
    {
        $queryParameters = $request->getQueryParams();
        // Cache data
        $mc->add($uniqueIdentifier, [
            'state' => $queryParameters['state'],
            'token_authenticity' => $tokenAuthenticity,
            'client' => $this->client,
            'resource' => $this->resource,
            'grant_method' => $queryParameters['response_type']
        ], self::CACHING_TIME);
        return $this;
    }

    /**
     * @param ServerRequestInterface $request
     * @return bool
     * @throws NoRedirectErrorException
     */
    public function invalidGrantType(ServerRequestInterface $request): bool
    {
        try {
            parent::authenticateClient($request);
            return parent::validateRequest($request);
        } catch (NoRedirectErrorException $e) {
            throw $e;
        }
    }
}