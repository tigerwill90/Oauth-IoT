<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 3:14 PM
 */

namespace Oauth\Services;

use Oauth\Services\Helpers\AlgorithmManagerHelperInterface;
use Oauth\Services\Helpers\JoseHelperInterface;

class Introspection implements IntrospectionInterface
{
    /** @var JoseHelperInterface  */
    private $joseHelper;

    /** @var AlgorithmManagerHelperInterface  */
    private $algorithmHelper;

    /** @var array */
    private $claimsToCheck = [self::CLAIM_ISS, self::CLAIM_EXP, self::CLAIM_JTI];

    /** @var array */
    private $invalidClaims = [];

    /** @var string */
    private $token = self::PARAM_TOKEN;

    /** @var string|null */
    private $tokenTypeHint;

    /** @var string */
    private $alg;

    /** @var string[] */
    private $optionalParameters = [];

    /** @var string[] */
    private $optionalMembers = [];

    /** @var array */
    private $jsonResponse = [
        self::RESP_ACTIVE => null
    ];

    /** @var ClaimsCheckerInterface  */
    private $claimsChecker;

    /** @var int */
    private static $time;

    /**
     * Introspection constructor.
     * @param JoseHelperInterface $joseHelper
     */
    public function __construct(JoseHelperInterface $joseHelper, AlgorithmManagerHelperInterface $algorithmHelper)
    {
        $this->joseHelper = $joseHelper;
        $this->algorithmHelper = $algorithmHelper;
    }

    /**
     * Inject a callable class to process verification of claims
     *
     * @param ClaimsCheckerInterface $claimsChecker
     * @return IntrospectionInterface
     */
    public function injectClaimsChecker(ClaimsCheckerInterface $claimsChecker): IntrospectionInterface
    {
        $this->claimsChecker = $claimsChecker;
        return $this;
    }

    /**
     * Set mandatory claim using for introspection
     *
     * @param array $claims
     * @return IntrospectionInterface
     */
    public function setClaimsToVerify(array $claims = [self::CLAIM_ISS, self::CLAIM_EXP, self::CLAIM_JTI]) : IntrospectionInterface
    {
        // take only standardized claims
        $this->claimsToCheck = array_intersect(
            $claims,
            [
                self::CLAIM_EXP,
                self::CLAIM_IAT,
                self::CLAIM_NBF,
                self::CLAIM_SUB,
                self::CLAIM_AUD,
                self::CLAIM_ISS,
                self::CLAIM_JTI,
                self::CLAIM_SCOPE
            ]
        );
        return $this;
    }

    /**
     * Set mandatory and optionally request parameter
     *
     * @param string $token
     * @param string|null $tokenTypeHint
     * @param array $optional
     * @return IntrospectionInterface
     */
    public function setRequestParameterToVerify(string $token = self::PARAM_TOKEN, string $tokenTypeHint = null, array $optional = []) : IntrospectionInterface
    {
        $this->token = $token;
        $this->tokenTypeHint = $tokenTypeHint;
        $this->optionalParameters = $optional;
        return $this;
    }

    /**
     * Set mandatory and optionally response member
     *
     * @param array $members => must be a list of standardized response parameter
     * @param array $optional
     * @return IntrospectionInterface
     */
    public function setResponseParameter(array $members = [self::RESP_ACTIVE], array $optional = []): IntrospectionInterface
    {
        unset($this->jsonResponse);

        // take only standardized response parameters
        $allowedMemberResponse = array_intersect(
            $members,
            [
                self::RESP_ACTIVE,
                self::RESP_SCOPE,
                self::RESP_TOKEN_TYPE,
                self::RESP_EXP,
                self::RESP_IAT,
                self::RESP_NBF,
                self::RESP_SUB,
                self::RESP_AUD,
                self::RESP_ISS,
                self::RESP_JTI
            ]
        );

        foreach ($allowedMemberResponse as $member) {
            $this->jsonResponse[$member] = null;
        }

        $this->optionalMembers = $optional;
        return $this;
    }

    /**
     * Add username and client id member to introspection response
     *
     * @param string|null $username
     * @param int|null $clientId
     * @return IntrospectionInterface
     */
    public function addUserInformation(string $username = null, int $clientId = null) : IntrospectionInterface
    {
        if ($username !== null) {
            $this->jsonResponse[self::RESP_USERNAME] = $username;
        }
        if ($clientId !== null) {
            $this->jsonResponse[self::RESP_CLIENT_ID] = $clientId;
        }
        return $this;
    }

    /**
     * Process a token introspection
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param string $secretKey
     * @param string $keyType
     * @return bool
     */
    public function introspectToken(\Psr\Http\Message\ServerRequestInterface $request, string $secretKey, string $keyType) : bool
    {
        self::$time = time();
        $this->invalidClaims = [];
        $args = $request->getParsedBody();

        // Check if request as mandatory parameter
        if (!isset($args[$this->token])) {
            $this->setErrorResponse();
            return false;
        }

        // Check if request as mandatory optional parameter
        foreach ($this->optionalParameters as $optionalParameter) {
            if (!isset($args[$optionalParameter])) {
                $this->setErrorResponse();
                return false;
            }
        }

        // Check if hint type is a supported algorithm
        if (null !== $this->tokenTypeHint && !\in_array(strtoupper($args[$this->tokenTypeHint]), $this->algorithmHelper->getAllAlgorithmAlias(), true)) {
            error_log($this->tokenTypeHint);
            $this->setErrorResponse();
            return false;
        }

        $this->alg = strtoupper($args[$this->tokenTypeHint]);

        // Retrieve headers parameters, catch an invalid token
        try {
            $headers = $this->joseHelper
                ->setJoseToken($args[$this->token])
                ->getHeaders();
        } catch (\Exception $e) {
            $this->setErrorResponse();
            return false;
        }

        // Check mandatory header typ parameter
        if (!array_key_exists('typ', $headers)) {
            $this->setErrorResponse();
            return false;
        }

        // Check if JoseHelper type is valid
        if (!\in_array($headers['typ'], [JoseHelperInterface::JWT, JoseHelperInterface::JWE], true)) {
            $this->setErrorResponse();
            return false;
        }

        // Check mandatory header alg parameter
        if (!array_key_exists('alg', $headers)) {
            $this->setErrorResponse();
            return false;
        }

        // Check if alg is a supported algorithm for his token type
        if ($headers['typ'] === JoseHelperInterface::JWT && !\in_array($headers['alg'], $this->algorithmHelper->getSignatureAlgorithmAlias(), true)) {
            $this->setErrorResponse();
            return false;
        }

        if ($headers['typ'] === JoseHelperInterface::JWE && !\in_array($headers['alg'], $this->algorithmHelper->getKeyEncryptionAlgorithmAlias(), true)) {
            $this->setErrorResponse();
            return false;
        }

        // If type hint is defined, check if it's value match with header alg
        if (null !== $this->tokenTypeHint && $this->alg !== $headers['alg']) {
            $this->setErrorResponse();
            return false;
        }

        $this->alg = $headers['alg'];

        // Check if JWE has enc parameter
        if ($headers['typ'] === JoseHelperInterface::JWE && !isset($headers['enc'])) {
            $this->setErrorResponse();
            return false;
        }

        // Check if enc is a supported algorithm
        if ($headers['typ'] === JoseHelperInterface::JWE && !\in_array($headers['enc'], $this->algorithmHelper->getContentEncryptionAlgorithmAlias(), true)) {
            error_log('bug with jws');
            $this->setErrorResponse();
            return false;
        }

        // Check the authenticity of the token, catch an invalid token
        try {
            $isVerified = $this->joseHelper
                ->setJwkKey($secretKey, $keyType)
                ->setJoseAlgorithm($this->alg, $headers['enc'])
                ->setJoseType($headers['typ'])
                ->verifyJoseToken();
        } catch (\Exception $e) {
            $this->setErrorResponse();
            return false;
        }

        // Retrieve claims, catch an invalid JWE token
        try {
            $claims = $this->joseHelper->getClaims();
        } catch (\Exception $e) {
            $this->setErrorResponse();
            return false;
        }

        if ($isVerified) {
            $active = true;
            // Check if  all mandatory claims are present
            if (\count($this->claimsToCheck) === \count(array_intersect($this->claimsToCheck, array_keys($claims)))) {
                // For each mandatory claims, check validity
                foreach ($this->claimsToCheck as $claimToCheck) {
                    if (!$this->{'check' . ucfirst($claimToCheck)}($claims[$claimToCheck])) {
                        error_log($claimToCheck);
                        $active = false;
                        $this->invalidClaims[$claimToCheck] = $claims[$claimToCheck];
                    }
                }
            } else {
                $active = false;
            }
        } else {
            $active = false;
        }

        $this->setStandardResponse($claims, $active);
        return true;
    }

    /**
     * Set a standardized json response error for malformed request
     *
     * RFC6749 Section 5.2 & RFC7662 Section 2.3
     * @return Introspection
     */
    private function setErrorResponse() : self
    {
        $this->jsonResponse = [
            self::ERROR => self::ERROR_MSG
        ];
        return $this;
    }

    /**
     * Set a standard introspection response for well formed request
     *
     * RFC7662 Section 2.2
     * @param array $claims
     * @param bool $active
     * @return Introspection
     */
    private function setStandardResponse(array $claims, bool $active) : self
    {
        // Give detail only if token is active
        if ($active) {
            $this->jsonResponse[self::RESP_ACTIVE] = true;
            foreach ($this->jsonResponse as $member => $value) {
                // don't override claims already set
                if ($member !== self::RESP_ACTIVE && $member !== self::RESP_USERNAME && $member !== self::RESP_CLIENT_ID) {
                    $this->jsonResponse[$member] = $claims[$member];
                }
                // process response for token hint type
                if ($member === self::RESP_TOKEN_TYPE && null !== $this->tokenTypeHint) {
                    $this->jsonResponse[$member] = $this->alg;
                }
            }

            // Set optional response parameter
            foreach ($this->optionalMembers as $member => $value) {
                $this->jsonResponse[$member] = $value;
            }
        } else {
            $this->jsonResponse = [self::RESP_ACTIVE => false];
        }

        return $this;
    }

    /**
     * Return a standardized json response
     *
     * @return string
     */
    public function getJsonResponse(): string
    {
        return json_encode($this->jsonResponse, JSON_UNESCAPED_SLASHES);
    }

    /**
     * Return an array with all invalid claims
     *
     * @return array
     */
    public function getInvalidClaims(): array
    {
        return $this->invalidClaims;
    }

    /**
     * Return false if token has expired
     *
     * @param int $exp
     * @return bool
     */
    private function checkExp(int $exp) : bool
    {
        return self::$time < $exp;
    }

    /**
     * Return false if issued time is before now (should use nbf instead)
     *
     * @param int $iat
     * @return bool
     */
    private function checkIat(int $iat) : bool
    {
        return self::$time >= $iat;
    }

    /**
     * Return false if token is not valid now
     *
     * @param int $nbf
     * @return bool
     */
    private function checkNbf(int $nbf) : bool
    {
        return self::$time >= $nbf;
    }

    /**
     * @param string $sub
     * @return bool
     */
    private function checkSub(string $sub) : bool
    {
        return $this->claimsChecker->verifySub($sub);
    }

    /**
     * @param string $aud
     * @return bool
     */
    private function checkAud(string $aud) : bool
    {
        return $this->claimsChecker->verifyAud($aud);
    }

    /**
     * @param string $iss
     * @return bool
     */
    private function checkIss(string $iss) : bool
    {
        return $this->claimsChecker->verifyIss($iss);
    }

    /**
     * @param string $jti
     * @return bool
     */
    private function checkJti(string $jti) : bool
    {
        return $this->claimsChecker->verifyJti($jti);
    }

    /**
     * @param string $scope
     * @return bool
     */
    private function checkScope(string $scope) : bool
    {
        return $this->claimsChecker->verifyScope($scope);
    }
}
