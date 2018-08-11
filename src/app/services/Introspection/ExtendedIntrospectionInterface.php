<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/11/18
 * Time: 5:28 PM
 */

namespace Oauth\Services\Introspection;


interface ExtendedIntrospectionInterface
{

    /**
     * A custom function to retrieve user
     * Return null if not needed
     * @param array $claims
     * @return null|string
     */
    public function getUserInformation(array $claims) : ?string;

    public function verifySub(string $sub) : bool;

    public function verifyAud(string $aud) : bool;

    public function verifyIss(string $iss) : bool;

    public function verifyJti(string $jti) : bool;

    public function verifyScope(string $scope) : bool;

}