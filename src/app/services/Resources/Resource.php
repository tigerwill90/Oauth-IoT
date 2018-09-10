<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 01.09.2018
 * Time: 15:56
 */

namespace Oauth\Services\Resources;


class Resource implements ResourceInterface
{
    /** @var int */
    private $id;

    /** @var string */
    private $resourceIdentification;

    /** @var string */
    private $resourceSecret;

    /** @var string */
    private $audience;

    /** @var \DateTime */
    private $registrationDate;

    /** @var string */
    private $popMethod;

    /** @var ScopeInterface[] */
    private $scope;

    /** @var int */
    private $keySize;

    /** @var string */
    private $sharedKeyAlgorithm;

    /** @var bool */
    private $tls;

    /** @var mixed  */
    private $transmissionAlgorithm;

    public  function __construct(array $resource)
    {
        if (!empty($resource['id'])) {
            $this->id = $resource['id'];
        }
        $this->resourceIdentification = $resource['resource_identification'];
        $this->resourceSecret = $resource['resource_secret'];
        $this->audience = $resource['resource_audience'];
        $this->registrationDate = new \DateTime($resource['resource_registration_date']);
        $this->popMethod = $resource['resource_pop_method'];
        $this->keySize = (int)$resource['key_size'];
        $this->sharedKeyAlgorithm = $resource['shared_key_algorithm'];
        $this->tls = (bool)$resource['tls'];
        $this->transmissionAlgorithm = $resource['transmission_algorithm'];
    }

    /**
     * @return int
     */
    public function getId(): int
    {
        return $this->id;
    }

    /**
     * @param int $id
     * @return Resource
     */
    public function setId(int $id): self
    {
        $this->id = $id;
        return $this;
    }

    /**
     * @return string
     */
    public function getResourceIdentification(): string
    {
        return $this->resourceIdentification;
    }

    /**
     * @param string $resourceIdentification
     * @return Resource
     */
    public function setResourceIdentification(string $resourceIdentification): self
    {
        $this->resourceIdentification = $resourceIdentification;
        return $this;
    }

    /**
     * @return string
     */
    public function getResourceSecret(): string
    {
        return $this->resourceSecret;
    }

    /**
     * @param string $resourceSecret
     * @return Resource
     */
    public function setResourceSecret(string $resourceSecret): self
    {
        $this->resourceSecret = $resourceSecret;
        return $this;
    }

    /**
     * @return string
     */
    public function getAudience(): string
    {
        return $this->audience;
    }

    /**
     * @param string $audience
     * @return Resource
     */
    public function setAudience(string $audience): self
    {
        $this->audience = $audience;
        return $this;
    }

    /**
     * @return \DateTime
     */
    public function getRegistrationDate(): \DateTime
    {
        return $this->registrationDate;
    }

    /**
     * @param \DateTime $registrationDate
     * @return Resource
     */
    public function setRegistrationDate(\DateTime $registrationDate): self
    {
        $this->registrationDate = $registrationDate;
        return $this;
    }

    /**
     * @return string
     */
    public function getPopMethod(): string
    {
        return $this->popMethod;
    }

    /**
     * @param string $popMethod
     * @return Resource
     */
    public function setPopMethod(string $popMethod): self
    {
        $this->popMethod = $popMethod;
        return $this;
    }

    /**
     * @return ScopeInterface[]
     */
    public function getScope(): array
    {
        return $this->scope;
    }

    /**
     * @param ScopeInterface[] $scope
     * @return Resource
     */
    public function setScope(array $scope): ResourceInterface
    {
        $this->scope = $scope;
        return $this;
    }

    /**
     * @return int
     */
    public function getKeySize(): int
    {
        return $this->keySize;
    }

    /**
     * @param int $keySize
     * @return Resource
     */
    public function setKeySize(int $keySize): self
    {
        $this->keySize = $keySize;
        return $this;
    }

    /**
     * @return string
     */
    public function getSharedKeyAlgorithm(): string
    {
        return $this->sharedKeyAlgorithm;
    }

    /**
     * @param string $sharedKeyAlgorithm
     * @return Resource
     */
    public function setSharedKeyAlgorithm(string $sharedKeyAlgorithm): self
    {
        $this->sharedKeyAlgorithm = $sharedKeyAlgorithm;
        return $this;
    }

    /**
     * @return bool
     */
    public function isTls(): bool
    {
        return $this->tls;
    }

    /**
     * @param bool $tls
     * @return Resource
     */
    public function setTls(bool $tls): self
    {
        $this->tls = $tls;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getTransmissionAlgorithm()
    {
        return $this->transmissionAlgorithm;
    }

    /**
     * @param mixed $transmissionAlgorithm
     * @return Resource
     */
    public function setTransmissionAlgorithm($transmissionAlgorithm): self
    {
        $this->transmissionAlgorithm = $transmissionAlgorithm;
        return $this;
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
        // TODO: Implement jsonSerialize() method.
    }
}