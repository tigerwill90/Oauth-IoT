<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 22:03
 */

namespace Oauth\Services\Authentication;

use Oauth\Services\Exceptions\Storage\NoEntityException;

class ImplicitGrant extends AuthorizationGrantType
{
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
        $scopeOut = array_diff($queryScope,$this->client->getScope());
        $correctedScope = array_diff($queryScope, $scopeOut);
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
     * RFC 6749
     * Section 3.1.2 Redirection endpoint and url encoding style
     * @param array $cache
     * @return string
     * @throws \Exception
     */
    public function getQueryResponse(array $cache): string
    {
        $resource = $cache['resource'];
        $this->tokenManager->createKeySet($resource);

        $scopes = [];
        foreach ($resource->getScope() as $scope) {
            $scopes[] = $scope->getService();
        }

        $queryResponse = [
            'access_token' => $this->tokenManager->getAccessToken(),
            'token_type' => 'JWT',
            'expires_in' => 1000,
            'scope' => implode('+', $scopes),
            'shared_key' => $this->tokenManager->getSharedKey(),
            'state' => $cache['state']
        ];

        return http_build_query($queryResponse, null, '&', PHP_QUERY_RFC3986);
    }

    /**
     * @param array $queryParameters
     * @return AuthorizationGrantType
     * @throws NoRedirectErrorException
     */
    public function invalidGrantType(array $queryParameters): AuthorizationGrantType
    {
        try {
            parent::authenticateClient($queryParameters);
            parent::validateRedirectUri($queryParameters);
        } catch (NoRedirectErrorException $e) {
            throw $e;
        }
        return $this;
    }
}