<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 29.09.2018
 * Time: 10:46
 */

namespace Oauth\Services\Authorization;

use Jose\Component\Core\JWK;
use Memcached;

class AuthorizationCodeGrant extends AuthorizationGrantType
{
    private const JWT_EXPIRATION = 600;
    private const JWK_EXPIRATION = self::JWT_EXPIRATION + 60;
    private const MAX_KID_ATTEMPTS = 5;
    private const KID_LENGTH = 4;
    private const JWE_KEY_LENGTH = 32;
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
        $client = $cache['client'];

        $kid = $this->generator->generateString(self::KID_LENGTH, self::TOKEN_CHAR_GEN);
        $maxTry = 0;
        while (!empty($mc->get($kid))) {
            $kid = $this->generator->generateString(self::KID_LENGTH, self::TOKEN_CHAR_GEN);
            $maxTry++;
            if ($maxTry >= self::MAX_KID_ATTEMPTS) {
                throw new \RuntimeException('Impossible to create unique kid');
            }
        }

        $jweKey = JWK::create([
            'alg' => 'A256KW',
            'enc' => 'A256CBC-HS512',
            'kty' => 'oct',
            'use' => 'enc',
            'k' => $this->generator->generateString(self::JWE_KEY_LENGTH, self::TOKEN_CHAR_GEN),
            'kid' => $kid,
            'key_ops' => ['encrypt', 'decrypt']
        ]);

        $mc->set($kid, $jweKey, self::JWK_EXPIRATION);

        $payload = [
            'aud' => $client->getClientName(),
            'exp' => time() + self::JWT_EXPIRATION,
            'iat' => time(),
            'iss' => getenv('APP_NAME'),
            'sub' => 'authorization_code',
            'jti' => $this->generator->generateString(self::NONCE_LENGTH, self::TOKEN_CHAR_GEN),
            'jwt' => [
                'aud' => $resource->getAudience(),
            ]
        ];

        if (null !== $params['scope']) {
            $payload['jwt']['scope'] = implode(' ', $params['scope']);
        }

        try {
            $jwt = $this->joseHelper
                ->setJwk($jweKey)
                ->createToken($payload);
        } catch (\Exception $e) {
            throw $e;
        }

        $queryResponse = [
            'code' => $jwt,
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