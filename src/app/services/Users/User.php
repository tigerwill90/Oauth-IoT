<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 21:10
 */

namespace Oauth\Services\Users;

class User implements UserInterface
{
    /** @var int */
    private $id;

    /** @var string */
    private $username;

    /** @var string */
    private $email;

    /** @var string */
    private $password;

    /** @var bool */
    private $refreshTokenValidity;

    public function __construct(array $user)
    {
        if (!empty($user['id'])) {
            $this->id = $user['id'];
        }
        $this->username = $user['username'];
        $this->email = $user['email'];
        $this->password = $user['password'];
        if (!empty($user['refresh_token_validity'])) {
            $this->refreshTokenValidity = $user['refresh_token_validity'];
        }
    }

    /**
     * @return int
     */
    public function getId(): int
    {
        return $this->id;
    }

    /**
     * @return bool
     */
    public function isRefreshTokenValidity(): bool
    {
        return $this->refreshTokenValidity;
    }

    /**
     * @param bool $refreshTokenValidity
     * @return User
     */
    public function setRefreshTokenValidity(bool $refreshTokenValidity): self
    {
        $this->refreshTokenValidity = $refreshTokenValidity;
        return $this;
    }

    /**
     * @param int $id
     */
    public function setId(int $id): void
    {
        $this->id = $id;
    }

    /**
     * @return string
     */
    public function getUsername(): string
    {
        return $this->username;
    }

    /**
     * @param string $username
     * @return User
     */
    public function setUsername(string $username): self
    {
        $this->username = $username;
        return $this;
    }

    /**
     * @return string
     */
    public function getEmail(): string
    {
        return $this->email;
    }

    /**
     * @param string $email
     * @return User
     */
    public function setEmail(string $email): self
    {
        $this->email = $email;
        return $this;
    }

    /**
     * @return string
     */
    public function getPassword(): string
    {
        return $this->password;
    }

    /**
     * @param string $password
     * @return User
     */
    public function setPassword(string $password): self
    {
        $this->password = $password;
        return $this;
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
       return  [
           'username' => $this->username,
           'email' => $this->email,
           'password' => $this->password,
           'refresh_token_validity' => $this->refreshTokenValidity
        ];
    }
}
