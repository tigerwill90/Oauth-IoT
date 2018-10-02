<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 29.09.2018
 * Time: 14:32
 */

namespace Oauth\Services\Token;

use Jose\Component\Core\JWK;
use Oauth\Services\Exceptions\Storage\NoEntityException;
use Oauth\Services\IntrospectionInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizationCodeGrant extends TokenGrantType
{
    private const JWT_EXPIRATION = 60;
    private const JWK_EXPIRATION = self::JWT_EXPIRATION + 60;
    private const MAX_KID_ATTEMPTS = 5;
    private const KID_LENGTH = 4;
    private const NONCE_LENGTH = 10;
    private const JWT_KEY_LENGTH = 32;
    private const REFRESH_TOKEN_EXPIRATION = 2592000; // 30 days

    /**
     * @param array $queryParameters
     * @return bool
     */
    public function validateRequest(array $queryParameters): bool
    {
        // check if all required parameter is present
        if (null === $queryParameters['code']) {
            $this->errors['error'] = 'invalid_request';
            $this->errors['description'] = 'the code query parameter is required';
            return false;
        }

        if (null === $queryParameters['redirect_uri']) {
            $this->errors['error'] = 'invalid_request';
            $this->errors['description'] = 'the redirect uri query parameter is required';
            return false;
        }

        if (null === $queryParameters['client_id']) {
            $this->errors['error'] = 'invalid_request';
            $this->errors['description'] = 'the client id query parameter is required';
            return false;
        }

        // check if client id is correct
        if ($this->client->getClientIdentification() !== $queryParameters['client_id']) {
            $this->errors['error'] = 'invalid_client';
            $this->errors['description'] = 'the client id query parameter must match with the authenticated client';
            return false;
        }

        // check if redirect uri is valid
        if (!\in_array($queryParameters['redirect_uri'], $this->client->getRedirectUri(), true)) {
            $this->errors['error'] = 'invalid_redirect_uri';
            $this->errors['description'] = 'the redirect uri must be valid';
            return false;
        }

        return true;
    }

    public function introspectToken(ServerRequestInterface $request): bool
    {
        $isValid =$this->introspection
            ->withChecker('code')
            ->setAudience($this->client)
            ->setRequestParameterToVerify('code')
            ->setMandatoryClaims([
                IntrospectionInterface::CLAIM_ISS,
                IntrospectionInterface::CLAIM_AUD,
                IntrospectionInterface::CLAIM_SUB,
                IntrospectionInterface::CLAIM_EXP,
                IntrospectionInterface::CLAIM_IAT,
                IntrospectionInterface::CLAIM_JTI
            ])
            ->introspectToken($request, null, true);

        if (!$isValid) {
            $this->errors['error'] = 'invalid_request';
            $this->errors['description'] = 'the introspection request is invalid';
            return false;
        }

        if ($this->introspection->getResponseArray()['active'] === false) {
            $this->errors['error'] = 'invalid_token';
            $this->errors['description'] = 'the token is inactive';
            return false;
        }

        $this->claims = $this->introspection->getClaims();

        if (!array_key_exists('aud', $this->claims['jwt']) || !isset($this->claims['jwt']['aud'])) {
            $this->errors['error'] = 'invalid_token';
            $this->errors['description'] = 'the token is invalid';
            return false;
        }

        try {
            $this->resource = $this->resourceStorage->fetchByAudience($this->claims['jwt']['aud']);
        } catch (NoEntityException $e) {
            $this->errors['error'] = 'invalid_audience';
            $this->errors['description'] = 'the targeted audience do not exist';
            return false;
        }

        return true;
    }

    /**
     * Create an authorizationCode response
     * @return array
     * @throws \Exception
     */
    public function getResponseArray(): array
    {
        $kid = $this->generator->generateString(self::KID_LENGTH, self::TOKEN_CHAR_GEN);
        $maxTry = 0;
        while (!empty($this->mc->get($kid)) || !empty($this->mc->get($kid . '-s'))) {
            $kid = $this->generator->generateString(self::KID_LENGTH, self::TOKEN_CHAR_GEN);
            $maxTry++;
            if ($maxTry >= self::MAX_KID_ATTEMPTS) {
                throw new \RuntimeException('Impossible to create unique kid');
            }
        }

        // create shared key
        $sharedKey = JWK::create([
            'alg' => $this->resource->getSharedKeyAlgorithm(),
            'kty' => 'oct',
            'kid' => $kid . '-s',
            'k' => $this->generator->generateString($this->resource->getKeySize(), self::TOKEN_CHAR_GEN),
            'key_ops' => ['encrypt', 'decrypt']
        ]);

        $this->mc->set($kid . '-s', $sharedKey, self::JWK_EXPIRATION);

        // create access token key
        $jwtKey = JWK::create([
            'alg' => 'HS256',
            'kty' => 'oct',
            'use' => 'sig',
            'k' => $this->generator->generateString(self::JWT_KEY_LENGTH, self::TOKEN_CHAR_GEN),
            'kid' => $kid,
        ]);

        $this->mc->set($kid, $jwtKey, self::JWK_EXPIRATION);

        // create refresh token key
        $refreshTokenKey = JWK::create([
            'alg' => 'A256KW',
            'enc' => 'A256CBC-HS512',
            'kty' => 'oct',
            'use' => 'enc',
            'k' => getenv('REFRESH_TOKEN_KEY'),
            'kid' => getenv('REFRESH_TOKEN_ID')
        ]);

        $payload = [
            'exp' => time() + self::JWT_EXPIRATION,
            'aud' => $this->resource->getAudience(),
            'jti' => $this->generator->generateString(self::NONCE_LENGTH, self::TOKEN_CHAR_GEN)
        ];

        if (\is_string($this->claims['jwt']['scope'])) {
            $payload['scope'] = $this->claims['jwt']['scope'];
        }

        // create access token
        try {
            $jwt = $this->joseHelper
                ->setJwk($jwtKey)
                ->createToken($payload);
        } catch (\Exception $e) {
            throw $e;
        }

        // create refresh token
        unset($payload);
        $payload = [
            'aud' => $this->client->getAudience(),
            'jti' => $this->generator->generateString(self::NONCE_LENGTH, self::TOKEN_CHAR_GEN),
            'iss' => getenv('APP_NAME'),
            'iat' => time(),
            'sub' => 'refresh_token',
            'exp' => time() + self::REFRESH_TOKEN_EXPIRATION,
            'jwt' => [
                'aud' => $this->resource->getAudience()
            ]
        ];

        if (\is_string($this->claims['jwt']['scope'])) {
            $payload['jwt']['scope'] = $this->claims['jwt']['scope'];
        }

        try {
            $refreshToken = $this->joseHelper
                    ->setJwk($refreshTokenKey)
                    ->createToken($payload);
        } catch (\Exception $e) {
            throw $e;
        }

        $response = [
            'access_token' => $jwt,
            'token_type' => 'JWT',
            'expire_in' => self::JWT_EXPIRATION,
            'refresh_token' => $refreshToken,
            'shared_key' => [
                'alg' => $sharedKey->get('alg'),
                'kty' => $sharedKey->get('kty'),
                'k' => $sharedKey->get('k')
            ]
        ];

        return $response;
    }
}
