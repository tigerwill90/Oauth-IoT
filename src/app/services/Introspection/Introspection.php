<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 3:14 PM
 */

namespace Oauth\Services\Introspection;

use Oauth\Services\Jose\Jose;

class Introspection implements IntrospectionInterface
{
    /** @var Jose  */
    private $joseService;

    /** @var array */
    private $claimsToCheck = [self::CLAIM_ISS, self::CLAIM_EXP, self::CLAIM_JTI];

    /** @var string */
    private $token = self::PARAM_TOKEN;

    /** @var string */
    private $tokenTypeHint;

    /** @var string[] */
    private $optionalParameters;

    /** @var string[] */
    private $optionalMembers;

    /** @var array */
    private $jsonResponse = [
        self::RESP_ACTIVE => null
    ];

    public function __construct(Jose $joseService)
    {
        $this->joseService = $joseService;
    }

    public function setIntrospectClaims(array $claims = [self::CLAIM_ISS, self::CLAIM_EXP, self::CLAIM_JTI]) : IntrospectionInterface
    {
        $this->claimsToCheck = array_intersect($claims, [self::CLAIM_EXP, self::CLAIM_IAT, self::CLAIM_NBF, self::CLAIM_SUB, self::CLAIM_AUD, self::CLAIM_ISS, self::CLAIM_JTI, self::CLAIM_SCOPE]);
        return $this;
    }

    public function setIntrospectParameters(string $token = self::PARAM_TOKEN, string $tokenTypeHint = self::PARAM_TYPE_HINT, array $optional = []) : IntrospectionInterface
    {
        $this->token = $token;
        $this->tokenTypeHint = $tokenTypeHint;
        $this->optionalParameters = $optional;
        return $this;
    }

    public function setIntrospectionResponse(array $members = [self::RESP_ACTIVE], array $optional = []): IntrospectionInterface
    {
        unset($this->jsonResponse);
        $allowedMemberResponse = array_intersect(
            $members,
            [
                self::RESP_ACTIVE,
                self::RESP_SCOPE,
                self::RESP_USERNAME,
                self::RESP_CLIENT_ID,
                self::RESP_TOKEN_TYPE,
                self::RESP_EXP,
                self::RESP_IAT,
                self::RESP_NBF,
                self::RESP_SUB,
                self::RESP_AUD,
                self::RESP_ISS,
                self::RESP_JTI]
        );

        foreach($allowedMemberResponse as $member) {
            $this->jsonResponse[$member] = null;
        }

        $this->optionalMembers = $optional;
        return $this;
    }

    public function introspectToken(\Psr\Http\Message\ServerRequestInterface $request) : bool
    {
        $args = $request->getParsedBody();

        if (isset($args[$this->token])) {
            $isVerified = $this->joseService
                ->createKey('secret')
                ->createAlgorithmManager(['HS256'])
                ->setToken($args[$this->token])
                ->unserializeToken()
                ->decodeJwsObject()
                ->verifyJwsObject();

            if ($isVerified) {
                $claims = $this->joseService->getClaims();

                // Check if mandatory claims are present
                if (\count($this->claimsToCheck) === \count(array_intersect($this->claimsToCheck, array_keys($claims)))) {
                    // For each mandatory claims, check validity
                    foreach ($this->claimsToCheck as $claimToCheck) {
                        if (!$this->{'check' . ucfirst($claimToCheck)}($claims[$claimToCheck])) {
                            error_log($claimToCheck);
                            return false;
                        }
                    }
                }
            }
        }

        // Error response RFC 7662 Section 2.3
        return false;
    }


    public function getJsonResponse(): string
    {
        return json_encode($this->jsonResponse);
    }

    private function checkExp(int $exp) : bool
    {
        return time() < $exp;
    }

    private function checkIat(int $iat) : bool
    {
        return time() >= $iat;
    }

    private function checkNbf(int $nbf) : bool
    {
        return time() > $nbf;
    }

    private function checkSub(string $sub) : bool
    {
        return true;
    }

    private function checkAud(string $aud) : bool
    {
        return true;
    }

    private function checkIss(string $iss) : bool
    {
        return true;
    }

    private function checkJti(string $jti) : bool
    {
        return true;
    }

    private function checkScope(string $scope) : bool
    {
        return true;
    }
}
