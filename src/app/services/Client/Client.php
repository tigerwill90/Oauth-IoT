<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 7:02 PM
 */

namespace Oauth\Services\ClientService;

class Client implements ClientInterface
{
    /** @var int */
    private $clientId;

    /** @var string */
    private $clientSecret;

    /** @var string */
    private $clientName;

    /** @var string[] */
    private $grantType;

    /** @var string */
    private $clientType;

    /** @var string[] */
    private $redirectUri;

    /** @var  array */
    private $scope;

    /** @var string */
    private $registrationDate;



    /**
     * Client constructor.
     * @param array $client
     */
    public function __construct(array $client)
    {
    }

    /**
     * @return int
     */
    public function getClientId(): int
    {
        return $this->clientId;
    }

    /**
     * @param int $clientId
     * @return Client
     */
    public function setClientId(int $clientId): self
    {
        $this->clientId = $clientId;
        return $this;
    }

    /**
     * @return string
     */
    public function getClientSecret(): string
    {
        return $this->clientSecret;
    }

    /**
     * @param string $clientSecret
     * @return Client
     */
    public function setClientSecret(string $clientSecret): self
    {
        $this->clientSecret = $clientSecret;
        return $this;
    }

    /**
     * @return string
     */
    public function getClientName(): string
    {
        return $this->clientName;
    }

    /**
     * @param string $clientName
     * @return Client
     */
    public function setClientName(string $clientName): self
    {
        $this->clientName = $clientName;
        return $this;
    }

    /**
     * @return string[]
     */
    public function getGrantType(): array
    {
        return $this->grantType;
    }

    /**
     * @param string[] $grantType
     * @return Client
     */
    public function setGrantType(array $grantType): self
    {
        $this->grantType = $grantType;
        return $this;
    }

    /**
     * @return array
     */
    public function getRedirectUri(): array
    {
        return $this->redirectUri;
    }

    /**
     * @param array $redirectUri
     * @return Client
     */
    public function setRedirectUri(array $redirectUri): self
    {
        $this->redirectUri = $redirectUri;
        return $this;
    }

    /**
     * @return array
     */
    public function getScope(): array
    {
        return $this->scope;
    }

    /**
     * @param array $scope
     * @return Client
     */
    public function setScope(array $scope): self
    {
        $this->scope = $scope;
        return $this;
    }

    /**
     * @return string
     */
    public function getClientType(): string
    {
        return $this->clientType;
    }

    /**
     * @param string $clientType
     * @return Client
     */
    public function setClientType(string $clientType): self
    {
        $this->clientType = $clientType;
        return $this;
    }

    /**
     * @return string
     */
    public function getRegistrationDate(): string
    {
        return $this->registrationDate;
    }

    /**
     * @param string $registrationDate
     * @return Client
     */
    public function setRegistrationDate(string $registrationDate): self
    {
        $this->registrationDate = $registrationDate;
        return $this;
    }


    /**
     * Return an array with registration response details
     * @return array
     */
    public function getRegistrationInformation(): array
    {
        // TODO: Implement getRegistrationInformation() method.
    }
}