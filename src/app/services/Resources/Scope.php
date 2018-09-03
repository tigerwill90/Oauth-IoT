<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 9/3/18
 * Time: 6:04 PM
 */

namespace Oauth\Services\Resources;


class Scope
{
    /** @var int */
    private $id;

    /** @var string */
    private $service;

    /** @var string */
    private $name;

    /** @var string */
    private $description;

    /** @var string */
    private $uri;

    public function __construct(array $scope)
    {
        if (!empty($scope['id'])) {
            $this->id = $scope['id'];
        }
        $this->service = $scope['scope_service'];
        $this->name = $scope['scope_name'];
        $this->description = $scope['scope_description'];
        $this->uri = $scope['scope_uri'];
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
     * @return Scope
     */
    public function setId(int $id): self
    {
        $this->id = $id;
        return $this;
    }

    /**
     * @return string
     */
    public function getService(): string
    {
        return $this->service;
    }

    /**
     * @param string $service
     * @return Scope
     */
    public function setService(string $service): self
    {
        $this->service = $service;
        return $this;
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * @param string $name
     * @return Scope
     */
    public function setName(string $name): self
    {
        $this->name = $name;
        return $this;
    }

    /**
     * @return string
     */
    public function getDescription(): string
    {
        return $this->description;
    }

    /**
     * @param string $description
     * @return Scope
     */
    public function setDescription(string $description): self
    {
        $this->description = $description;
        return $this;
    }

    /**
     * @return string
     */
    public function getUri(): string
    {
        return $this->uri;
    }

    /**
     * @param string $uri
     * @return Scope
     */
    public function setUri(string $uri): self
    {
        $this->uri = $uri;
        return $this;
    }


}