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
    private $clientIdentification;

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
    private $scopes;

    /** @var DateTime */
    private $registrationDate;

    /**
     * Clients constructor.
     * @param array $client
     */
    public function __construct(array $client)
    {
        if (!empty($client['id'])) {
            $this->id = (int)$client['id'];
        }
        if (!empty($client['client_identification'])) {
            $this->clientIdentification = $client['client_identification'];
        }
        if (!empty($client['client_secret'])) {
            $this->clientSecret = $client['client_secret'];
        }
        if (!empty($client['registration_date'])) {
            $this->registrationDate = new DateTime($client['registration_date']);
        }
        $this->clientName = $client['client_name'];
        $this->grantType = $client['grant_type'];
        $this->clientType = $client['client_type'];
        if (!empty($client['redirect_uri'])) {
            $this->redirectUri = $client['redirect_uri'];
        }
        if (!empty( $client['scope'])) {
            $this->scopes = $client['scope'];
        }
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
    public function getClientIdentification() : string
    {
        return $this->clientIdentification;
    }

    /**
     * @param string $clientIdentification
     * @return Client
     */
    public function setClientIdentification(string $clientIdentification) : ClientInterface
    {
        $this->clientIdentification = $clientIdentification;
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
    public function setRedirectUri(array $redirectUri) : ClientInterface
    {
        $this->redirectUri = $redirectUri;
        return $this;
    }

    /**
     * @return array
     */
    public function getScope() : array
    {
        return $this->scopes;
    }

    /**
     * @param array $scopes
     * @return Client
     */
    public function setScope(array $scopes) : ClientInterface
    {
        $this->scopes = $scopes;
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
            'client_id' => $this->clientIdentification,
            'client_secret' => $this->clientSecret,
            'client_name' => $this->clientName,
            'client_type' => $this->clientType,
            'grant_type' => $this->grantType,
            'registration_date' => $this->getRegistrationDate(),
            'scope' => $this->scopes,
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
    public function jsonSerialize() : array
    {
        return [
            'client_id' => $this->clientIdentification,
            'client_secret' => $this->clientSecret,
            'client_name' => $this->clientName,
            'client_type' => $this->clientType,
            'grant_type' => $this->grantType,
            'registration_date' => $this->getRegistrationDate()
        ];
    }
}