<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 01.10.2018
 * Time: 14:12
 */

namespace Oauth\Services;

class RefreshRules implements ClaimsCheckerInterface
{
    /**
     * Return false is sub don't match
     * @param array $claims
     * @return bool
     */
    public function verifySub(array $claims): bool
    {
        return $claims['sub'] === 'refresh_token';
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