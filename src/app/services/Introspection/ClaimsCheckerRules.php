<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/11/18
 * Time: 5:27 PM
 */

namespace Oauth\Services;

use Memcached;

class ClaimsCheckerRules implements ClaimsCheckerInterface
{
    /** @var Memcached  */
    private $mc;

    // Necessary stuff to perform claims verification
    public function __construct(Memcached $mc)
    {
        $this->mc = $mc;
    }

    public function verifySub(array $claims) : bool
    {
        return false;
    }

    /**
     * Verify than aud match with the RS (use resource identification to perform the check)
     * @param array $claims
     * @return bool
     */
    public function verifyAud(array $claims) : bool
    {
        return $claims['aud'] === 'iot_a';
    }

    public function verifyIss(array $claims) : bool
    {
        return $claims['iss'] === 'My service';
    }

    public function verifyJti(array $claims) : bool
    {
        // jti already used ?
        if (!empty($this->mc->get($claims['jti']))) {
            return false;
        }
        $secondBeforeExpiration = $claims['exp'] - time();

        // Do not save nonce for an expired token (STRICT > 0)
        if ($secondBeforeExpiration > 0) {
            $this->mc->add($claims['jti'], 'nonce', $secondBeforeExpiration);
        }
        return true;
    }

    public function verifyScope(array $claims) : bool
    {
        return false;
    }
}
