<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 29.09.2018
 * Time: 17:52
 */

namespace Oauth\Services;

use Memcached;

class CodeRules implements ClaimsCheckerInterface
{
    /** @var Memcached  */
    private $mc;

    public function __construct(Memcached $mc)
    {
        $this->mc = $mc;
    }

    /**
     * Return false is sub don't match
     * @param array $claims
     * @return bool
     */
    public function verifySub(array $claims): bool
    {
        return $claims['sub'] === 'authorization_code';
    }

    /**
     * Return false if aud don't match
     * @param array $claims
     * @param AudienceInterface $audience
     * @return bool
     */
    public function verifyAud(array $claims, AudienceInterface $audience): bool
    {
        return $claims['aud'] === $audience->getAudience();
    }

    /**
     * Return false if iss don't match
     * @param array $claims
     * @return bool
     */
    public function verifyIss(array $claims): bool
    {
        return $claims['iss'] === getenv('APP_NAME');
    }

    /**
     * Return false if jti operation check is invalid
     * @param array $claims
     * @return bool
     */
    public function verifyJti(array $claims): bool
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
     * Return false if permission don't match
     * @param array $claims
     * @param AudienceInterface $audience
     * @return bool
     */
    public function verifyScope(array $claims, AudienceInterface $audience): bool
    {
        return true;
    }
}