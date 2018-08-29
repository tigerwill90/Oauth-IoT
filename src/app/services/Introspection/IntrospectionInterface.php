<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 3:15 PM
 */

namespace Oauth\Services;

/**
 * OAuth 2.0 Token Introspection RFC 7662
 *
 * Interface IntrospectionInterface
 * @package Oauth\services\Introspection
 * @see https://tools.ietf.org/html/rfc7662
 *
 */
interface IntrospectionInterface
{

    public const PARAM_TOKEN = 'token';
    public const PARAM_TYPE_HINT = 'token_type_hint';
    public const RESP_ACTIVE = 'active';
    public const RESP_SCOPE = 'scope';
    public const RESP_USERNAME = 'username';
    public const RESP_CLIENT_ID = 'client_id';
    public const RESP_TOKEN_TYPE = 'token_type';
    public const RESP_EXP = 'exp';
    public const RESP_IAT = 'iat';
    public const RESP_NBF = 'nbf';
    public const RESP_SUB = 'sub';
    public const RESP_AUD = 'aud';
    public const RESP_ISS = 'iss';
    public const RESP_JTI = 'jti';
    public const CLAIM_EXP = 'exp';
    public const CLAIM_IAT = 'iat';
    public const CLAIM_NBF = 'nbf';
    public const CLAIM_SUB = 'sub';
    public const CLAIM_AUD = 'aud';
    public const CLAIM_ISS = 'iss';
    public const CLAIM_JTI = 'jti';
    public const CLAIM_SCOPE = 'scope';
    public const ERROR = 'error';
    public const ERROR_MSG = 'invalid request';

    /**
     * Inject a callable class to process verification of claims
     *
     * @param ClaimsCheckerInterface $claimsChecker
     * @return IntrospectionInterface
     */
    public function injectClaimsChecker(ClaimsCheckerInterface $claimsChecker) : IntrospectionInterface;

    /**
     * Set claim who MUST be in the token and who need to be verified
     * Must follow RFC 7662 Section 2
     *
     * @param string[] $claims => must be standardized claims
     * @return IntrospectionInterface
     */
    public function setClaimsToVerify(array $claims = [self::CLAIM_ISS, self::CLAIM_EXP, self::CLAIM_JTI]) : IntrospectionInterface;

    /**
     * Set parameters who MUST representing the introspection request and OPTIONAL parameter
     * Must follow RFC 7662 Section 2.1
     *
     * @param string $token
     * @param string $tokenTypeHint
     * @param string[] $optional
     * @return IntrospectionInterface
     */
    public function setRequestParameterToVerify(string $token = self::PARAM_TOKEN, string $tokenTypeHint = null, array $optional = []) : IntrospectionInterface;

    /**
     * Set top-level members of introspection response
     * Must follow RFC 7662 Section 2.2
     *
     * @param array $members => must be standardized response parameters
     * @param string[] $optional => is non-standardized response parameters
     * @return IntrospectionInterface
     */
    public function setResponseParameter(array $members = [self::RESP_ACTIVE], array $optional = []) : IntrospectionInterface;

    /**
     * Add username and client id member to introspection response
     * Must follow RFC 7662 Section 2.2
     *
     * @param string|null $username
     * @param int|null $clientId
     * @return IntrospectionInterface
     */
    public function addUserInformation(string $username = null, int $clientId = null) : IntrospectionInterface;

    /**
     * Introspect the given token and return true if the token is well formed
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request => PSR7 request who contains OAuth 2.0 token who need to be introspected
     * @param string $secretKey
     * @param string $keyType
     * @return bool => the result of introspection process
     */
    public function introspectToken(\Psr\Http\Message\ServerRequestInterface $request, string $secretKey, string $keyType) : bool;

    /**
     * Return an appropriate json object response
     *
     * @return string
     */
    public function getJsonResponse() : string;

    /**
     * Return an array with all invalid claims
     *
     * @return array
     */
    public function getInvalidClaims() : array;
}
