<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 22:03
 */

namespace Oauth\Services\Authentication;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Memcached;
use Oauth\Services\Exceptions\Storage\NoEntityException;

class ImplicitGrant extends AuthorizationGrantType
{
    private const EXPIRATION = 86399;

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
     * @param array $params
     * @param Memcached $mc
     * @return string
     * @throws \Exception
     */
    public function getQueryResponse(array $cache, array $params, Memcached $mc): string
    {
        $resource = $cache['resource'];

        // TODO validate : avoid duplicating kid
        $kid = $this->generator->generateString(4, self::TOKEN_CHAR_GEN);

        // create KEYSet
        $sharedKey = JWK::create([
            'alg' => $resource->getSharedKeyAlgorithm(),
            'kty' => 'oct',
            'kid' => $kid . '-s',
            'k' => $this->generator->generateString($resource->getKeySize(), self::TOKEN_CHAR_GEN),
            'key_ops' => ['encrypt', 'decrypt']
        ]);

        $accessTokenKey = JWK::create([
            'alg' => 'HS256',
            'kty' => 'oct',
            'use' => 'sig',
            'k' => $this->generator->generateString(32, self::TOKEN_CHAR_GEN),
            'kid' => $kid,
        ]);

        $jwkSet = $mc->get($resource->getAudience());

        $jweKey = null;
        if ($resource->getPopMethod() !== 'introspection') {
            $jweKey = JWK::create([
                'alg' => 'A256KW',
                'enc' => 'A256CBC-HS512',
                'kty' => 'oct',
                'use' => 'enc',
                'k' => $resource->getResourceSecret(),
                'kid' => $kid . '-j'
            ]);
        }

        if (empty($jwkSet)) {
            if (null !== $jweKey) {
                $jwkSet = JWKSet::createFromKeys([$sharedKey, $accessTokenKey, $jweKey]);
            } else {
                $jwkSet = JWKSet::createFromKeys([$sharedKey, $accessTokenKey]);
            }
            $mc->set($resource->getAudience(), $jwkSet, self::EXPIRATION);
        } else {
            if (null !== $jweKey) {
                $jwkSet = $jwkSet->with($sharedKey)->with($accessTokenKey)->with($jweKey);
            } else {
                $jwkSet = $jwkSet->with($sharedKey)->with($accessTokenKey);
            }

            $mc->replace($resource->getAudience(), $jwkSet, self::EXPIRATION);
        }

        $payload = [
            'exp' => time() + self::EXPIRATION, // 23:59:59
            'aud' => $resource->getAudience()
        ];

        if (null !== $jweKey) {
            try {
                $payload['cnf'] = $this->joseHelper
                    ->setJwk($jweKey)
                    ->createToken($sharedKey->all());
            } catch (\Exception $e) {
                throw $e;
            }
        }

        if (null !== $params['scope']) {
            $payload['scope'] = implode(' ', $params['scope']);
        }

        try {
            $jwt = $this->joseHelper
                ->setJwk($accessTokenKey)
                ->createToken($payload);
        } catch (\Exception $e) {
            throw $e;
        }

        $queryResponse = [
            'access_token' => $jwt,
            'token_type' => 'JWT',
            'expires_in' => self::EXPIRATION,
            'scope' => implode('+', $params['scope']),
            'state' => $cache['state']
        ];

        if (null === $jweKey) {
            $queryResponse['shared_key'] = $sharedKey->get('k');
        }

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