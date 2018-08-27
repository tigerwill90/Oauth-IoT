<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/11/18
 * Time: 5:28 PM
 */

namespace Oauth\Services\Introspection;


interface ClaimsCheckerInterface
{

    /**
     * A custom function to retrieve user
     * Return null if not needed
     * @param array $claims
     * @return null|string
     */
    public function getUserInformation(array $claims) : string;

    /**
     * Return false is sub don't match
     * @param string $sub
     * @return bool
     */
    public function verifySub(string $sub) : bool;

    /**
     * Return false if aud don't match
     * @param string $aud
     * @return bool
     */
    public function verifyAud(string $aud) : bool;

    /**
     * Return false if iss don't match
     * @param string $iss
     * @return bool
     */
    public function verifyIss(string $iss) : bool;

    /**
     * Return false if jti operation check is invalid
     * @param string $jti
     * @return bool
     */
    public function verifyJti(string $jti) : bool;

    /**
     * Return false if permission don't match
     * @param string $scope
     * @return bool
     */
    public function verifyScope(string $scope) : bool;

}