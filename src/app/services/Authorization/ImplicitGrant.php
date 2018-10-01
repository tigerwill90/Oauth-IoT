<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 22:03
 */

namespace Oauth\Services\Authorization;

use Jose\Component\Core\JWK;
use Memcached;

class ImplicitGrant extends AuthorizationGrantType
{
    private const JWT_EXPIRATION = 86400;
    private const JWK_EXPIRATION = self::JWT_EXPIRATION + 60;
    private const MAX_KID_ATTEMPTS = 5;
    private const KID_LENGTH = 4;
    private const JWT_KEY_LENGTH = 32;
    private const NONCE_LENGTH = 10;

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

        $kid = $this->generator->generateString(self::KID_LENGTH, self::TOKEN_CHAR_GEN);
        $maxTry = 0;
        while (!empty($mc->get($kid)) || !empty($mc->get($kid . '-s'))) {
            $kid = $this->generator->generateString(self::KID_LENGTH, self::TOKEN_CHAR_GEN);
            $maxTry++;
            if ($maxTry >= self::MAX_KID_ATTEMPTS) {
                throw new \RuntimeException('Impossible to create unique kid');
            }
        }

        // create shared key for PoP
        $sharedKey = JWK::create([
            'alg' => $resource->getSharedKeyAlgorithm(),
            'kty' => 'oct',
            'kid' => $kid . '-s',
            'k' => $this->generator->generateString($resource->getKeySize(), self::TOKEN_CHAR_GEN),
            'key_ops' => ['encrypt', 'decrypt']
        ]);

        $mc->set($kid . '-s', $sharedKey, self::JWK_EXPIRATION);

        // create access token key
        $accessTokenKey = JWK::create([
            'alg' => 'HS256',
            'kty' => 'oct',
            'use' => 'sig',
            'k' => $this->generator->generateString(self::JWT_KEY_LENGTH, self::TOKEN_CHAR_GEN),
            'kid' => $kid,
        ]);

        $mc->set($kid, $accessTokenKey, self::JWK_EXPIRATION);

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

        $payload = [
            'exp' => time() + self::JWT_EXPIRATION, // 23:59:59
            'aud' => $resource->getAudience(),
            'jti' => $this->generator->generateString(self::NONCE_LENGTH, self::TOKEN_CHAR_GEN)
        ];

        if (null !== $jweKey) {
            try {
                $payload['cnf'] = $this->joseHelper
                    ->setJwk($jweKey)
                    ->createToken([
                        'alg' => $sharedKey->get('alg'),
                        'kty' => $sharedKey->get('kty'),
                        'k' => $sharedKey->get('k')
                    ]);
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
            'expires_in' => self::JWT_EXPIRATION,
            'scope' => implode('+', $params['scope']),
            'state' => $cache['state']
        ];

        $queryResponse['shared_key'] = $sharedKey->get('k');
        $queryResponse['key_algorithm'] = $sharedKey->get('alg');

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