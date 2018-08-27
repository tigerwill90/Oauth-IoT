<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/27/18
 * Time: 9:43 PM
 */

namespace Oauth\Tests\Introspection;

use Oauth\Services\Introspection\ClaimsCheckerInterface;

class ExtendClaimsTest implements ClaimsCheckerInterface
{
    /**
     * Return false is sub don't match
     * @param string $sub
     * @return bool
     */
    public function verifySub(string $sub): bool
    {
        return $sub === 'subject';
    }

    /**
     * Return false if aud don't match
     * @param string $aud
     * @return bool
     */
    public function verifyAud(string $aud): bool
    {
        return $aud === 'audience';
    }

    /**
     * Return false if iss don't match
     * @param string $iss
     * @return bool
     */
    public function verifyIss(string $iss): bool
    {
        return $iss === 'issuer';
    }

    /**
     * Return false if jti operation check is invalid
     * @param string $jti
     * @return bool
     */
    public function verifyJti(string $jti): bool
    {
        return $jti === 'nonce';
    }

    /**
     * Return false if permission don't match
     * @param string $scope
     * @return bool
     */
    public function verifyScope(string $scope): bool
    {
        return $this->arrayEqual(explode(',', $scope), ['read_rs', 'write_rs']);
    }

    /**
     * Check if two array are equals
     * @param $a
     * @param $b
     * @return bool
     */
    private function arrayEqual($a, $b) : bool
    {
        return (
            \is_array($a)
            && \is_array($b)
            && count($a) === count($b)
            && array_diff($a, $b) === array_diff($b, $a)
        );
    }
}
