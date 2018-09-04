<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 11:28 PM
 */

namespace Oauth\Services\Clients;

interface ClientInterface extends \JsonSerializable
{

    public function getId() : int;

    /**
     * @param string $clientIdentification
     * @return ClientInterface
     */
    public function setClientIdentification(string $clientIdentification) : ClientInterface;

    /**
     * @return string
     */
    public function getClientSecret() : string;

    /**
     * @return string
     */
    public function getClientIdentification() : string ;

    /**
     * @return string
     */
    public function getClientName() : string;

    /**
     * @param string $registrationDate
     * @return ClientInterface
     */
    public function setClientSecret(string $registrationDate) : ClientInterface;

    /**
     * @param \DateTime $date
     * @return ClientInterface
     */
    public function setRegistrationDate(\DateTime $date) : ClientInterface;

    /**
     * @return string
     */
    public function getRegistrationDate() : string;

    /**
     * @return array
     */
    public function getRedirectUri() : array;

    /**
     * @param array $redirectUri
     * @return ClientInterface
     */
    public function setRedirectUri(array $redirectUri) : ClientInterface;

    /**
     * @param array $scope
     * @return ClientInterface
     */
    public function setScope(array $scope) : ClientInterface;

    /**
     * @return array
     */
    public function getScope() : array;

    /**
     * @return string
     */
    public function getGrantType() : string;

    /**
     * Return an array with registration response details
     * @return array
     */
    public function getRegistrationInformation() : array;
}