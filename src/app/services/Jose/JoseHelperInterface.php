<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/28/18
 * Time: 3:30 PM
 */

namespace Oauth\Services\Jose;

interface JoseHelperInterface
{
    public const JWT = 'JWT';
    public const JWE = 'JWE';
    public const OCT = 'oct';
    public const CL_SIGNATURE = 'Signature';
    public const CL_KEY_ENCRYPTION = 'KeyEncryption';
    public const CL_CONTENT_ENCRYPTION = 'ContentEncryption';

    /**
     * Set JWK
     * @param string $key
     * @param string $keyType
     * @return JoseHelperInterface
     * @throws
     */
    public function setJwkKey(string $key, string $keyType =  self::OCT) : JoseHelperInterface;

    /**
     * Set Jose type
     * @param string $joseType
     * @return JoseHelperInterface
     */
    public function setJoseType(string $joseType = self::JWT) : JoseHelperInterface;

    /**
     * Set token
     * @param string $token
     * @return JoseHelperInterface
     */
    public function setJoseToken(string $token) : JoseHelperInterface;

    /**
     * Set algorithm
     * @param string $keyAlg
     * @param string|null $keyContent
     * @param int $sig
     * @return JoseHelperInterface
     */
    public function setJoseAlgorithm(string $keyAlg, string $keyContent = null, int $sig = 0) : JoseHelperInterface;

    /**
     * Create a new JWS/JWE token
     * @param array $payload
     * @return string
     * @throws \Exception
     */
    public function createJoseToken(array $payload) : string;

    /**
     * Return true if the token is correctly signed, throw an exception if the token is invalid
     * @return bool
     * @throws \Exception
     */
    public function verifyJoseToken() : bool;

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

    /**
     * Return a list of all supported algorithm alias
     * @return string[]
     */
    public function getAllAlgorithmAlias() : array;

    /**
     * Return a list of all supported signature alias
     * @return string[]
     */
    public function getSignatureAlgorithmAlias() : array;

    /**
     * Return a list of all supported key encryption algorithm
     * @return string[]
     */
    public function getKeyEncryptionAlgorithmAlias() : array;

    /**
     * Return a list of all supported content key encryption algorithm
     * @return string[]
     */
    public function getContentEncryptionAlgorithmAlias() : array;
}
