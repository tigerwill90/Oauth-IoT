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
     * @param string $registrationDate
     * @return ClientInterface
     */
    public function setClientSecret(string $registrationDate) : ClientInterface;

    /**
     * @param \DateTime $date
     * @return ClientInterface
     */
    public function setRegistrationDate(\DateTime $date) : ClientInterface;

    public function getRegistrationDate() : string;

    public function getRedirectUri() : array;

    public function setRedirectUri(array $redirectUri) : ClientInterface;

    public function setScope(array $scope) : ClientInterface;

    public function getScope() : array;

    /**
     * Return an array with registration response details
     * @return array
     */
    public function getRegistrationInformation() : array;
}