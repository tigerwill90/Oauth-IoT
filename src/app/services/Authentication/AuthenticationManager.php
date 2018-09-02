<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 21:49
 */

namespace Oauth\Services\Authentication;

class AuthenticationManager implements \JsonSerializable
{
    /** @var GrantType */
    private $grantType;

    public function __construct()
    {
    }

    /**
     * @param string $grantTypeAlias
     * @param GrantType $grantType
     * @return AuthenticationManager
     */
    public function add(string $grantTypeAlias, GrantType $grantType) : self
    {
        $this->grantType[$grantTypeAlias] = $grantType;
        return $this;
    }

    /**
     * @param string $grantTypeAlias
     * @param GrantType $grantType
     * @return bool
     */
    public function authenticate(string $grantTypeAlias, GrantType $grantType) : bool
    {
        return false;
    }

    public function getMessages() : array
    {

    }

    /**
     * Specify data which should be serialized to JSON
     * @link https://php.net/manual/en/jsonserializable.jsonserialize.php
     * @return mixed data which can be serialized by <b>json_encode</b>,
     * which is a value of any type other than a resource.
     * @since 5.4.0
     */
    public function jsonSerialize() : array
    {
        // TODO: Implement jsonSerialize() method.
    }
}