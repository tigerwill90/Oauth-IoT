<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 3:15 PM
 */

namespace Oauth\Services;

use Jose\Component\Core\JWKSet;

/**
 * OAuth 2.0 Token Introspection RFC 7662
 *
 * Interface IntrospectionInterface
 * @package Oauth\services\Introspection
 * @see https://tools.ietf.org/html/rfc7662
 *
 */
interface IntrospectionInterface extends \JsonSerializable
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
     * Inject a ClaimsCheckerInterface instance to process verification of claims
     *
     * @param string $aliasChecker
     * @return IntrospectionInterface
     */
    public function withChecker(string $aliasChecker) : IntrospectionInterface;

    /**
     * Set claim who MUST be in the token and who need to be verified
     * Must follow RFC 7662 Section 2
     *
     * @param string[] $claims => must be standardized claims
     * @return IntrospectionInterface
     */
    public function setMandatoryClaims(array $claims = [self::CLAIM_ISS, self::CLAIM_EXP, self::CLAIM_JTI]) : IntrospectionInterface;

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
     * Set top-level members of active introspection response
     * Must follow RFC 7662 Section 2.2
     *
     * @param string[] $parameters => must be standardized response parameters
     * @param string|null $username
     * @param int|null $clientId
     * @param array[string]string $optional => non-standardized response parameters
     * @return IntrospectionInterface
     */
    public function setActiveResponseParameter(array $parameters = [], string $username = null, int $clientId = null, array $optional = []) : IntrospectionInterface;

    /**
     * Set top-level members of inactive introspection response
     * An inactive response SHOULD NOT give more information than an active=false response
     * Must follow RFC 7662 Section 2.2
     *
     * @param string[] $parameters
     * @param array[string]string $optional
     * @return IntrospectionInterface
     */
    public function setInactiveResponseParameter(array $parameters = [], array $optional = []) : IntrospectionInterface;

    /**
     * Introspect the given token and return true if the token is well formed
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request => PSR7 request who contains OAuth 2.0 token who need to be introspected
     * @param JWKSet $jwkSet
     * @param bool $onlyMandatoryClaims
     * @return bool => the result of introspection process
     */
    public function introspectToken(\Psr\Http\Message\ServerRequestInterface $request, JWKSet $jwkSet, bool $onlyMandatoryClaims = false) : bool;

    /**
     * Return an appropriate response array
     *
     * @return array
     */
    public function getResponseArray() : array ;

    /**
     * Return an array with all invalid claims
     *
     * @return array[string]string|int
     */
    public function getInvalidClaims() : array;
}
