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

    public function getToken() : string;

    public function setToken(string $token) : JoseInterface;

    public function getClaims() : array;

    public function getHeaders() : array;

    public function createJwsObject(array $payload, array $headers) : JoseInterface;

    public function verifyJwsObject(int $signatureIndex = 0) : bool;

    public function decodeJwsObject() : JoseInterface;

    public function createAlgorithmManager(array $alias) : JoseInterface;

    public function createKey(string $key) : JoseInterface;

    public function serializeToken(int $signatureIndex = 0) : JoseInterface;

    public function unserializeToken() : JoseInterface;

    public function isValidToken() : bool;

}
