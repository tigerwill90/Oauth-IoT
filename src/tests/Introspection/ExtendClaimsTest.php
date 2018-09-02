<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/27/18
 * Time: 9:43 PM
 */

namespace Oauth\Tests\Introspection;

use Oauth\Services\ClaimsCheckerInterface;

class ExtendClaimsTest implements ClaimsCheckerInterface
{
    /**
     * Return false is sub don't match
     * @param array $claims
     * @return bool
     */
    public function verifySub(array $claims): bool
    {
        return $claims['sub'] === 'subject';
    }

    /**
     * Return false if aud don't match
     * @param array $claims
     * @return bool
     */
    public function verifyAud(array $claims): bool
    {
        return $claims['aud'] === 'audience';
    }

    /**
     * Return false if iss don't match
     * @param array $claims
     * @return bool
     */
    public function verifyIss(array $claims): bool
    {
        return $claims['iss'] === 'issuer';
    }

    /**
     * Return false if jti operation check is invalid
     * @param array $claims
     * @return bool
     */
    public function verifyJti(array $claims): bool
    {
        return $claims['jti'] === 'nonce';
    }

    /**
     * Return false if permission don't match
     * @param array $claims
     * @return bool
     */
    public function verifyScope(array $claims): bool
    {
        return $this->arrayEqual(explode(' ', $claims['scope']), ['read_rs', 'write_rs']);
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
