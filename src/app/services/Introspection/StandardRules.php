<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/11/18
 * Time: 5:27 PM
 */

namespace Oauth\Services;

use Memcached;

class StandardRules implements ClaimsCheckerInterface
{
    /** @var Memcached  */
    private $mc;

    // Necessary stuff to perform claims verification
    public function __construct(Memcached $mc)
    {
        $this->mc = $mc;
    }

    /**
     * @param array $claims
     * @return bool
     */
    public function verifySub(array $claims) : bool
    {
        return true;
    }

    /**
     * Verify than aud match with the RS (use resource identification to perform the check)
     * @param array $claims
     * @param AudienceInterface $resource
     * @return bool
     */
    public function verifyAud(array $claims, AudienceInterface $resource) : bool
    {
        return $claims['aud'] === $resource->getAudience();
    }

    /**
     * @param array $claims
     * @return bool
     */
    public function verifyIss(array $claims) : bool
    {
        return $claims['iss'] === getenv('APP_NAME');
    }

    /**
     * @param array $claims
     * @return bool
     */
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

    /**
     * @param array $claims
     * @param AudienceInterface $resource
     * @return bool
     */
    public function verifyScope(array $claims, AudienceInterface $resource) : bool
    {
        $tokenScope = explode(' ', $claims['scope']);
        $scopes = $resource->getScopeArray();
        if (!empty(array_diff($tokenScope, $scopes))) {
            return false;
        }
        return true;
    }
}
