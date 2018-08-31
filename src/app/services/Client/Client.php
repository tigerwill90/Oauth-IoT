<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 7:02 PM
 */

namespace Oauth\Services\Clients;

use DateTime;

class Client implements ClientInterface
{
    /** @var int */
    private $id;

    /** @var int */
    private $clientId;

    /** @var string */
    private $clientSecret;

    /** @var string */
    private $clientName;

    /** @var string */
    private $grantType;

    /** @var string */
    private $clientType;

    /** @var string[] */
    private $redirectUri;

    /** @var  array */
    private $scope;

    /** @var DateTime */
    private $registrationDate;

    /**
     * Client constructor.
     * @param array $client
     */
    public function __construct(array $client)
    {
        if (!empty($client['id'])) {
            $this->id = (int)$client['id'];
        }
        if (!empty($client['client_id'])) {
            $this->clientId = $client['client_id'];
        }
        if (!empty($client['client_secret'])) {
            $this->clientSecret = $client['client_secret'];
        }
        if (!empty($client['registration_date'])) {
            $this->registrationDate = $client['registration_date'];
        }
        $this->clientName = $client['client_name'];
        $this->grantType = $client['grant_type'];
        $this->clientType = $client['client_type'];
        $this->redirectUri = $client['redirect_uri'];
        $this->scope = $client['scope'];
    }

    /**
     * @return int
     */
    public function getId() : int
    {
        return $this->id;
    }

    /**
     * @param int $id
     * @return Client
     */
    public function setId(int $id) : self
    {
        $this->id = $id;
        return $this;
    }

    /**
     * @return string
     */
    public function getClientId() : string
    {
        return $this->clientId;
    }

    /**
     * @param string $clientId
     * @return Client
     */
    public function setClientId(string $clientId) : ClientInterface
    {
        $this->clientId = $clientId;
        return $this;
    }

    /**
     * @return string
     */
    public function getClientSecret() : string
    {
        return $this->clientSecret;
    }

    /**
     * @param string $clientSecret
     * @return Client
     */
    public function setClientSecret(string $clientSecret) : ClientInterface
    {
        $this->clientSecret = $clientSecret;
        return $this;
    }

    /**
     * @return string
     */
    public function getClientName() : string
    {
        return $this->clientName;
    }

    /**
     * @param string $clientName
     * @return Client
     */
    public function setClientName(string $clientName) : self
    {
        $this->clientName = $clientName;
        return $this;
    }

    /**
     * @return string
     */
    public function getGrantType() : string
    {
        return $this->grantType;
    }

    /**
     * @param string $grantType
     * @return Client
     */
    public function setGrantType(string $grantType) : self
    {
        $this->grantType = $grantType;
        return $this;
    }

    /**
     * @return array
     */
    public function getRedirectUri() : array
    {
        return $this->redirectUri;
    }

    /**
     * @param array $redirectUri
     * @return Client
     */
    public function setRedirectUri(array $redirectUri) : self
    {
        $this->redirectUri = $redirectUri;
        return $this;
    }

    /**
     * @return array
     */
    public function getScope() : array
    {
        return $this->scope;
    }

    /**
     * @param array $scope
     * @return Client
     */
    public function setScope(array $scope) : ClientInterface
    {
        $this->scope = $scope;
        return $this;
    }

    /**
     * @return string
     */
    public function getClientType() : string
    {
        return $this->clientType;
    }

    /**
     * @param string $clientType
     * @return Client
     */
    public function setClientType(string $clientType) : self
    {
        $this->clientType = $clientType;
        return $this;
    }

    /**
     * @return string
     */
    public function getRegistrationDate() : string
    {
        return $this->registrationDate->format('Y-m-d H:i:s');
    }

    /**
     * @param DateTime $registrationDate
     * @return Client
     */
    public function setRegistrationDate(DateTime $registrationDate) : ClientInterface
    {
        $this->registrationDate = $registrationDate;
        return $this;
    }


    /**
     * Return an array with registration response details
     * @return array
     */
    public function getRegistrationInformation() : array
    {
        return [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'client_name' => $this->clientName,
            'client_type' => $this->clientType,
            'grant_type' => $this->grantType,
            'registration_date' => $this->getRegistrationDate(),
            'scope' => $this->scope,
            'redirect_url' => $this->redirectUri
        ];
    }

    /**
     * Specify data which should be serialized to JSON
     * @link https://php.net/manual/en/jsonserializable.jsonserialize.php
     * @return mixed data which can be serialized by <b>json_encode</b>,
     * which is a value of any type other than a resource.
     * @since 5.4.0
     */
    public function jsonSerialize()
    {
        return [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'client_name' => $this->clientName,
            'client_type' => $this->clientType,
            'grant_type' => $this->grantType,
            'registration_date' => $this->getRegistrationDate()
        ];
    }
}