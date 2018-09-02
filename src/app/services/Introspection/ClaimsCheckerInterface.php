<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/11/18
 * Time: 5:28 PM
 */

namespace Oauth\Services;

interface ClaimsCheckerInterface
{
    /**
     * Return false is sub don't match
     * @param array $claims
     * @return bool
     */
    public function verifySub(array $claims) : bool;

    /**
     * Return false if aud don't match
     * @param array $claims
     * @return bool
     */
    public function verifyAud(array $claims) : bool;

    /**
     * Return false if iss don't match
     * @param array $claims
     * @return bool
     */
    public function verifyIss(array $claims) : bool;

    /**
     * Return false if jti operation check is invalid
     * @param array $claims
     * @return bool
     */
    public function verifyJti(array $claims) : bool;

    /**
     * Return false if permission don't match
     * @param array $claims
     * @return bool
     */
    public function verifyScope(array $claims) : bool;
}
