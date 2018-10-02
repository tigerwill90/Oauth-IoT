<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 29.09.2018
 * Time: 14:33
 */

namespace Oauth\Services\Token;


use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Oauth\Services\Exceptions\Storage\NoEntityException;
use Oauth\Services\IntrospectionInterface;
use Psr\Http\Message\ServerRequestInterface;

class RefreshGrant extends TokenGrantType
{
    private const JWT_EXPIRATION = 3600;
    private const JWK_EXPIRATION = self::JWT_EXPIRATION + 60;
    private const MAX_KID_ATTEMPTS = 5;
    private const KID_LENGTH = 4;
    private const NONCE_LENGTH = 10;
    private const JWT_KEY_LENGTH = 32;

    /** @var string */
    private $scope;

    /**
     * @param array $queryParameters
     * @return bool
     */
    public function validateRequest(array $queryParameters): bool
    {
        // check if all required parameter is present
        if (null === $queryParameters['refresh_token']) {
            $this->errors['error'] = 'invalid_request';
            $this->errors['description'] = 'the refresh_token query parameter is required';
            return false;
        }

        return true;
    }

    /**
     * @param ServerRequestInterface $request
     * @return bool
     */
    public function introspectToken(ServerRequestInterface $request): bool
    {
        // create refresh token key
        $refreshTokenKey = JWK::create([
            'alg' => 'A256KW',
            'enc' => 'A256CBC-HS512',
            'kty' => 'oct',
            'use' => 'enc',
            'k' => getenv('REFRESH_TOKEN_KEY'),
            'kid' => getenv('REFRESH_TOKEN_ID')
        ]);

        $jwkSet = JWKSet::createFromKeys([$refreshTokenKey]);

        $isValid =$this->introspection
            ->withChecker('refresh')
            ->setAudience($this->client)
            ->setRequestParameterToVerify('refresh_token')
            ->setMandatoryClaims([
                IntrospectionInterface::CLAIM_ISS,
                IntrospectionInterface::CLAIM_AUD,
                IntrospectionInterface::CLAIM_SUB,
                IntrospectionInterface::CLAIM_IAT,
                IntrospectionInterface::CLAIM_EXP
            ])
            ->introspectToken($request, $jwkSet, true);

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

        $queryParams = $request->getQueryParams();

        // validate requested scope
        if (!empty($queryParams['scope']) && null === $this->claims['jwt']['scope']) {
            $this->errors['error'] = 'invalid_scope';
            $this->errors['description'] = 'The requested scope include scope not originally granted by the resource owner';
            return false;
        }

        if (array_key_exists('scope', $this->claims['jwt']) && !empty($queryParams['scope'])  && !empty($this->claims['jwt']['scope']) && !empty(array_diff(explode(' ' , $queryParams['scope']), explode(' ', $this->claims['jwt']['scope'])))) {
            $this->errors['error'] = 'invalid_scope';
            $this->errors['description'] = 'The requested scope include scope not originally granted by the resource owner';
            return false;
        }

        // Set scope if exist, else take originally scope
        if (!empty($queryParams['scope'])) {
            $this->scope = $queryParams['scope'];
        } else {
            $this->scope = $this->claims['jwt']['scope'];
        }

        return true;
    }

    /**
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

        $payload = [
            'exp' => time() + self::JWT_EXPIRATION,
            'aud' => $this->resource->getAudience(),
            'jti' => $this->generator->generateString(self::NONCE_LENGTH, self::TOKEN_CHAR_GEN)
        ];

        if (\is_string($this->claims['jwt']['scope'])) {
            $payload['scope'] = $this->scope;
        }

        // create access token
        try {
            $jwt = $this->joseHelper
                ->setJwk($jwtKey)
                ->createToken($payload);
        } catch (\Exception $e) {
            throw $e;
        }

        $response = [
            'access_token' => $jwt,
            'token_type' => 'JWT',
            'expire_in' => self::JWT_EXPIRATION,
            'shared_key' => [
                'alg' => $sharedKey->get('alg'),
                'kty' => $sharedKey->get('kty'),
                'k' => $sharedKey->get('k')
            ]
        ];

        return $response;
    }
}