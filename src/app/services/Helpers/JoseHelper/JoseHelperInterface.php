<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/28/18
 * Time: 3:30 PM
 */

namespace Oauth\Services\Helpers;

use Jose\Component\Core\JWK;

interface JoseHelperInterface
{
    // JoseHelper : token type
    public const JWT = 'JWT';
    public const JWE = 'JWE';

    // Key types
    public const OCT = 'oct';
    public const RSA = 'RSA';
    public const EC = 'EC';
    public const OKP = 'OKP';

    /**
     * Set JWK
     * @param string $key
     * @param string $keyType
     * @return JoseHelperInterface
     * @throws
     */
    public function setJwkKey(string $key, string $keyType =  self::OCT) : JoseHelperInterface;

    /**
     * Set a JWK object
     * @param JWK $jwk
     * @return JoseHelperInterface
     */
    public function setJwk(JWK $jwk) : JoseHelperInterface;

    /**
     * Set JoseHelper type
     * @param string $joseType
     * @return JoseHelperInterface
     */
    public function setType(string $joseType = self::JWT) : JoseHelperInterface;

    /**
     * Set token
     * @param string $token
     * @return JoseHelperInterface
     */
    public function setToken(string $token) : JoseHelperInterface;

    /**
     * Set algorithm
     * @param string $keyAlg
     * @param string|null $keyContent
     * @param int $sig
     * @return JoseHelperInterface
     */
    public function setAlgorithm(string $keyAlg, string $keyContent = null, int $sig = 0) : JoseHelperInterface;

    /**
     * Create a new JWS/JWE token
     * @param array $payload
     * @return string
     * @throws \Exception
     */
    public function createToken(array $payload) : string;

    /**
     * Return true if the token is correctly signed, throw an exception if the token is invalid
     * @return bool
     * @throws \Exception
     */
    public function verifyToken() : bool;

    /**
     * Return an array with all headers of JOSE, throw and exception if token is invalid
     * @return array
     * @throws \Exception
     */
    public function getHeaders() : array;

    /**
     * Return a an array with all claims of JOSE, throw an exception if token is invalid
     * or if the JWE can not be decrypted
     * @return array
     * @throws \Exception
     */
    public function getClaims() : array;
}
