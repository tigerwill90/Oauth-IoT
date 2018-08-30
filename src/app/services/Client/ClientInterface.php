<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 11:28 PM
 */

namespace Oauth\Services\ClientService;

interface ClientInterface
{
    /**
     * Return an array with registration response details
     * @return array
     */
    public function getRegistrationInformation() : array;
}