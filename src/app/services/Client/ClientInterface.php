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
    /**
     * Return an unique client id
     * @return string
     */
    public function getClientId() : string;

    public function setClientId(string $clientId) : ClientInterface;

    public function getClientSecret() : string;

    public function setClientSecret(string $registrationDate) : ClientInterface;

    public function setRegistrationDate(\DateTime $date) : ClientInterface;

    public function getRegistrationDate() : string;

    /**
     * Return an array with registration response details
     * @return array
     */
    public function getRegistrationInformation() : array;
}