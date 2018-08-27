<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/27/18
 * Time: 12:48 PM
 */

namespace Oauth\Services\Jose;

interface JoseInterface
{

    /**
     * Get the string token
     * @return string
     */
    public function getToken() : string;

    /**
     * Set the string token
     * @param string $token
     * @return JoseInterface
     */
    public function setToken(string $token) : JoseInterface;

    /**
     * Get claims array
     * @return array
     */
    public function getClaims() : array;

    /**
     * Get headers array
     * @return array
     */
    public function getHeaders() : array;

    /**
     * Create a Json web signed object
     * @param array $payload
     * @param array $headers
     * @return JoseInterface
     */
    public function createJwsObject(array $payload, array $headers) : JoseInterface;

    /**
     * Verify a Json web signed object
     * @param int $signatureIndex
     * @return bool
     */
    public function verifyJwsObject(int $signatureIndex = 0) : bool;

    /**
     * Decode a Json web signed object
     * @return JoseInterface
     */
    public function decodeJwsObject() : JoseInterface;

    /**
     * Create an new instance of algorithm manager
     * @param array $alias
     * @return JoseInterface
     */
    public function createAlgorithmManager(array $alias) : JoseInterface;

    /**
     * Create a new instance of Json web key
     * @param string $key
     * @param string $keyType
     * @return JoseInterface
     */
    public function createKey(string $key, string $keyType) : JoseInterface;

    /**
     * Serialize the token
     * @param int $signatureIndex
     * @return JoseInterface
     */
    public function serializeToken(int $signatureIndex = 0) : JoseInterface;

    /**
     * Deserialize token
     * @return JoseInterface
     */
    public function deserializeToken() : JoseInterface;

    /**
     * Check if token is well formed
     * @return bool
     */
    public function isValidToken() : bool;

}
