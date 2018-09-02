<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 9/2/18
 * Time: 11:39 AM
 */

namespace Oauth\Services;


class ClaimCheckerManager
{
    /** @var array[string]ClaimsCheckerInterface */
    private $claimsChecker;

    /**
     * @param string $checkerAlias
     * @param ClaimsCheckerInterface $claimChecker
     * @return ClaimCheckerManager
     */
    public function add(string $checkerAlias, ClaimsCheckerInterface $claimChecker) : self
    {
        $this->claimsChecker[$checkerAlias] = $claimChecker;
        return $this;
    }

    /**
     * @param string $checkerAlias
     * @return ClaimsCheckerInterface
     */
    public function getClaimChecker(string $checkerAlias) : ClaimsCheckerInterface
    {
        return $this->claimsChecker[$checkerAlias];
    }
}