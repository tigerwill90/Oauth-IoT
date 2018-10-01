<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/10/18
 * Time: 3:14 PM
 */

namespace Oauth\Services;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Oauth\Services\Helpers\AesHelperInterface;
use Oauth\Services\Helpers\AlgorithmManagerHelperInterface;
use Oauth\Services\Helpers\JoseHelperInterface;
use phpseclib\Crypt\AES;
use Psr\Log\LoggerInterface;
use Memcached;

class Introspection implements IntrospectionInterface
{
    /** @var JoseHelperInterface  */
    private $joseHelper;

    /** @var AlgorithmManagerHelperInterface  */
    private $algorithmHelper;

    /** @var AesHelperInterface */
    private $aesHelper;

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

    /** @var array */
    private $response = [
        self::RESP_ACTIVE => false
    ];

    /** @var  string[] */
    private $activeResponse = [];

    /** @var array[string]string|int|bool */
    private $optionalActiveResponse = [];

    /** @var array */
    private $inactiveResponse = [];

    /** @var array[string]string|int|bool */
    private $optionalInactiveResponse = [];

    /** @var string */
    private $username;

    /** @var string */
    private $clientId;

    /** @var ClaimsCheckerInterface  */
    private $claimsChecker;

    /** @var ClaimsCheckerManager */
    private $claimsCheckerManager;

    /** @var int */
    private static $time;

    /** @var string */
    private $secret;

    /** @var bool */
    private $pop = false;

    /** @var JWKSet */
    private $jwkSet;

    /** @var AudienceInterface */
    private $audience;

    /** @var array */
    private $claims = [];

    /** @var Memcached  */
    private $mc;

    /** @var LoggerInterface  */
    private $logger;

    /**
     * Introspection constructor.
     * @param JoseHelperInterface $joseHelper
     * @param AlgorithmManagerHelperInterface $algorithmHelper
     * @param ClaimsCheckerManager $claimCheckerManager
     * @param AesHelperInterface $aesHelper
     * @param LoggerInterface|null $logger
     */
    public function __construct(JoseHelperInterface $joseHelper, AlgorithmManagerHelperInterface $algorithmHelper, ClaimsCheckerManager $claimCheckerManager, AesHelperInterface $aesHelper, Memcached $mc ,LoggerInterface $logger = null)
    {
        $this->joseHelper = $joseHelper;
        $this->algorithmHelper = $algorithmHelper;
        $this->claimsCheckerManager = $claimCheckerManager;
        $this->aesHelper = $aesHelper;
        $this->logger = $logger;
        $this->mc = $mc;
    }

    /**
     * Inject a ClaimsCheckerInterface instance to process verification of claims
     *
     * @param string $aliasChecker
     * @return IntrospectionInterface
     */
    public function withChecker(string $aliasChecker) : IntrospectionInterface
    {
        $this->claimsChecker = $this->claimsCheckerManager->getClaimChecker($aliasChecker);
        return $this;
    }

    /**
     * @param bool $tls
     * @param string|null $secret
     * @return IntrospectionInterface
     */
    public function setPopKey(bool $tls = true, string $secret = null) : IntrospectionInterface
    {
        $this->pop = true;
        if (!$tls && $secret === null) {
            throw new \InvalidArgumentException('secret must be given for no tls support resource');
        }

        if (!$tls) {
            $this->secret = $secret;
        }

        return $this;
    }

    /**
     * @param AudienceInterface $audience
     * @return IntrospectionInterface
     */
    public function setAudience(AudienceInterface $audience) : IntrospectionInterface
    {
        $this->audience = $audience;
        return $this;
    }

    /**
     * Set mandatory claim using for introspection
     *
     * @param array $claims
     * @return IntrospectionInterface
     */
    public function setMandatoryClaims(array $claims = [self::CLAIM_ISS, self::CLAIM_EXP, self::CLAIM_JTI]) : IntrospectionInterface
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
     * Set top-level members of active introspection response
     * Must follow RFC 7662 Section 2.2
     *
     * @param string[] $parameters => must be standardized response parameters
     * @param string|null $username
     * @param int|null $clientId
     * @param array[string]string|int|bool $optional => non-standardized response parameters
     * @return IntrospectionInterface
     */
    public function setActiveResponseParameter(array $parameters = [], string $username = null, int $clientId = null, array $optional = []): IntrospectionInterface
    {
        // take only standardized response parameters
        $this->activeResponse = array_intersect(
            $parameters,
            [
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

        if ($username !== null) {
            $this->activeResponse[] = self::RESP_USERNAME;
            $this->username = $username;
        }

        if ($clientId !== null) {
            $this->activeResponse[] = self::RESP_CLIENT_ID;
            $this->clientId = $clientId;
        }

        $this->optionalActiveResponse = $optional;
        return $this;
    }

    /**
     * Set top-level members of inactive introspection response
     * Must follow RFC 7662 Section 2.2
     *
     * @param string[] $parameters
     * @param array[string]string|int|bool $optional
     * @return IntrospectionInterface
     */
    public function setInactiveResponseParameter(array $parameters = [], array $optional = []) : IntrospectionInterface
    {
        // take only standardized response parameters
        $this->inactiveResponse = array_intersect(
            $parameters,
            [
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

        $this->optionalInactiveResponse = $optional;
        return $this;
    }

    /**
     * Process a token introspection
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param JWKSet $jwkSet
     * @param bool $onlyMandatoryClaims
     * @return bool
     */
    public function introspectToken(\Psr\Http\Message\ServerRequestInterface $request, JWKSet $jwkSet = null, bool $onlyMandatoryClaims = false) : bool
    {
        self::$time = time();
        $this->jwkSet = $jwkSet;

        if ($this->claimsChecker === null) {
            throw new \InvalidArgumentException('ClaimCheckerInterface dependency unsatisfied');
        }

        if ($this->audience === null) {
            throw new \InvalidArgumentException('AudienceInterface dependency unsatisfied');
        }

        $this->invalidClaims = [];

        $args = $request->getParsedBody();

        // Get parameter from header if body is empty
        if (empty($args)) {
            $headerArgs = $request->getHeader('HTTP_' . $this->token);
            if (!empty($headerArgs)) {
                $args[$this->token] = $headerArgs[0] ?? null;
                if (null !== $this->tokenTypeHint) {
                    $args[$this->tokenTypeHint] = $request->getHeader('HTTP_' . $this->tokenTypeHint)[0] ?? null;
                }
            } else {
                $args = $request->getQueryParams();
            }
        }

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
            $this->setErrorResponse();
            return false;
        }

        $this->alg = strtoupper($args[$this->tokenTypeHint]);

        /**
         * THE REQUEST IS VALID,
         * Retrieve headers parameters, catch an invalid token
         */
        try {
            $headers = $this->joseHelper
                ->setToken($args[$this->token])
                ->getHeaders();
        } catch (\Exception $e) {
            $this->setStandardResponse(false);
            return true;
        }

        // Check mandatory header kid parameter
        if (!array_key_exists('kid', $headers)) {
            $this->setStandardResponse(false);
            return true;
        }

        // Check mandatory header typ parameter
        if (!array_key_exists('typ', $headers)) {
            $this->setStandardResponse(false);
            return true;
        }

        // Check if Jose typ is valid
        if (!\in_array($headers['typ'], [JoseHelperInterface::JWT, JoseHelperInterface::JWE], true)) {
            $this->setStandardResponse(false);
            return true;
        }

        // Check mandatory header alg parameter
        if (!array_key_exists('alg', $headers)) {
            $this->setStandardResponse(false);
            return true;
        }

        // Check if alg is a supported algorithm for his token type
        if ($headers['typ'] === JoseHelperInterface::JWT && !\in_array($headers['alg'], $this->algorithmHelper->getSignatureAlgorithmAlias(), true)) {
            $this->setStandardResponse(false);
            return true;
        }

        if ($headers['typ'] === JoseHelperInterface::JWE && !\in_array($headers['alg'], $this->algorithmHelper->getKeyEncryptionAlgorithmAlias(), true)) {
            $this->setStandardResponse(false);
            return true;
        }

        // If type hint is defined, check if it's value match with header alg
        if (null !== $this->tokenTypeHint && $this->alg !== $headers['alg']) {
            $this->setStandardResponse(false);
            return true;
        }

        $this->alg = $headers['alg'];

        // Check if JWE has enc parameter
        if ($headers['typ'] === JoseHelperInterface::JWE && !isset($headers['enc'])) {
            $this->setStandardResponse(false);
            return true;
        }

        // Check if enc is a supported algorithm
        if ($headers['typ'] === JoseHelperInterface::JWE && !\in_array($headers['enc'], $this->algorithmHelper->getContentEncryptionAlgorithmAlias(), true)) {
            $this->setStandardResponse(false);
            return true;
        }

        // Search for a pop shared key
        $sharedKey = null;
        if ($this->pop) {
            try {
                if ($this->jwkSet === null) {
                    $sharedKey = $this->mc->get($headers['kid'] . '-s');
                    if (!$sharedKey) {
                        $sharedKey = null;
                    }
                } else {
                    $sharedKey = $this->jwkSet->get($headers['kid'] . '-s')->get('k');
                }
            } catch (\Exception $e) {
                $this->setStandardResponse(false);
                return true;
            }
        }

        // Check the authenticity of the token, catch an invalid token
        $jwk = null;
        try {
            if ($this->jwkSet === null) {
                $jwk = $this->mc->get($headers['kid']);
                if (!$jwk) {
                    $this->setStandardResponse(false);
                    return true;
                }
            } else {
                $jwk = $this->jwkSet->get($headers['kid']);
            }
            $isVerified = $this->joseHelper
                ->setJwk($jwk)
                ->verifyToken();
        } catch (\Exception $e) {
            $this->setStandardResponse(false);
            return true;
        }

        // Retrieve claims, catch an invalid JWE token
        try {
            $this->claims = $this->joseHelper->getClaims();
        } catch (\Exception $e) {
            $this->setStandardResponse(false);
            return true;
        }

        if ($isVerified) {
            $active = true;
            // Check if  all mandatory claims are present
            if (\count($this->claimsToCheck) === \count(array_intersect($this->claimsToCheck, array_keys($this->claims)))) {
                /**
                 * Check the validity of each mandatory claims
                 * Sometimes, you want check only mandatory claims
                 * but sometimes you want check all present claims
                 */
                if ($onlyMandatoryClaims) {
                    $claimsToCheck = $this->claimsToCheck;
                } else {
                    $claimsToCheck = [
                        self::CLAIM_EXP,
                        self::CLAIM_IAT,
                        self::CLAIM_NBF,
                        self::CLAIM_SUB,
                        self::CLAIM_AUD,
                        self::CLAIM_ISS,
                        self::CLAIM_JTI,
                        self::CLAIM_SCOPE
                    ];
                }
                foreach ($claimsToCheck as $claimToCheck) {
                    try {
                        if (array_key_exists($claimToCheck, $this->claims) && !$this->{'check' . ucfirst($claimToCheck)}($this->claims)) {
                            $active = false;
                            $this->invalidClaims[$claimToCheck] = $this->claims[$claimToCheck];
                        }
                    } catch (\InvalidArgumentException $e) {
                        $active = false;
                        $this->invalidClaims[$claimToCheck] = $this->claims[$claimToCheck];
                    }
                }
            } else {
                $active = false;
            }
        } else {
            $active = false;
        }

        $this->setStandardResponse($active, $this->claims, $sharedKey);
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
        $this->response = [
            self::ERROR => self::ERROR_MSG
        ];
        return $this;
    }

    /**
     * Set a standard introspection response for well formed request
     *
     * RFC7662 Section 2.2
     * @param bool $active
     * @param array $claims
     * @param JWK $sharedKey
     * @return Introspection
     */
    private function setStandardResponse(bool $active, array $claims = null, JWK $sharedKey = null) : self
    {
        if ($active) {
            $this->response[self::RESP_ACTIVE] = $active;
            $arrayResponse = $this->activeResponse;
            $arrayOptionalResponse = $this->optionalActiveResponse;

            if (null !== $sharedKey) {
                if ($this->secret === null) {
                    $this->response['key'] = $sharedKey->get('k');
                } else {
                    $encryptedSharedKey = $this->aesHelper
                        ->setMode(AES::MODE_ECB)
                        ->aesEncrypt($this->secret, $sharedKey->get('k'), false);
                    $this->response['key'] = $encryptedSharedKey;
                }
            }

        } else {
            $arrayResponse = $this->inactiveResponse;
            $arrayOptionalResponse = $this->optionalInactiveResponse;
        }

        // Set active/inactive response with claims
        foreach ($arrayResponse as $member) {
            // specific handling for token type hint
            if ($member === self::RESP_TOKEN_TYPE && null !== $this->tokenTypeHint) {
                $this->response[$member] = $this->alg;
                continue;
            }
            // specific handling for username
            if ($active && $member === self::RESP_USERNAME) {
                $this->response[$member] = $this->username;
                continue;
            }
            // specific handling for client id
            if ($active && $member === self::RESP_CLIENT_ID) {
                $this->response[$member] = $this->clientId;
                continue;
            }

            if (null !== $claims && array_key_exists($member, $claims)) {
                $this->response[$member] = $claims[$member];
            }
        }

        // Set optional response parameter
        foreach ($arrayOptionalResponse as $member => $value) {
            $this->response[$member] = $value;
        }

        return $this;
    }

    /**
     * Return a standardized array response
     *
     * @return array
     */
    public function getResponseArray() : array
    {
        return $this->response;
    }

    /**
     * Specify data which should be serialized to JSON
     * @link https://php.net/manual/en/jsonserializable.jsonserialize.php
     * @return mixed data which can be serialized by <b>json_encode</b>,
     * which is a value of any type other than a resource.
     * @since 5.4.0
     */
    public function jsonSerialize() : array
    {
        return $this->response;
    }

    /**
     * Return an array with all invalid claims
     *
     * @return array[string]string|int
     */
    public function getInvalidClaims() : array
    {
        return $this->invalidClaims;
    }

    /**
     * Return an array with all jwt claims
     * @return array[string]string|int
     */
    public function getClaims() : array
    {
        return $this->claims;
    }

    /**
     * Return false if token has expired
     *
     * @param array $claims
     * @return bool
     */
    private function checkExp(array $claims) : bool
    {
        if (!is_numeric($claims['exp'])) {
            throw new \InvalidArgumentException('exp must be a numeric claim');
        }
        return self::$time < (int)$claims['exp'];
    }

    /**
     * Return false if issued time is before now (should use nbf instead)
     *
     * @param array $claims
     * @return bool
     */
    private function checkIat(array $claims) : bool
    {
        if (!is_numeric($claims['iat'])) {
            throw new \InvalidArgumentException('iat must be a numeric claim');
        }
        return self::$time >= (int)$claims['iat'];
    }

    /**
     * Return false if token is not valid now
     *
     * @param array $claims
     * @return bool
     */
    private function checkNbf(array $claims) : bool
    {
        if (!is_numeric($claims['nbf'])) {
            throw new \InvalidArgumentException('nbf must be a numeric claim');
        }
        return self::$time >= (int)$claims['nbf'];
    }

    /**
     * @param array $claims
     * @return bool
     */
    private function checkSub(array $claims) : bool
    {
        return $this->claimsChecker->verifySub($claims);
    }

    /**
     * @param array $claims
     * @return bool
     */
    private function checkAud(array $claims) : bool
    {
        return $this->claimsChecker->verifyAud($claims, $this->audience);
    }

    /**
     * @param array $claims
     * @return bool
     */
    private function checkIss(array $claims) : bool
    {
        return $this->claimsChecker->verifyIss($claims);
    }

    /**
     * @param array $claims
     * @return bool
     */
    private function checkJti(array $claims) : bool
    {
        return $this->claimsChecker->verifyJti($claims);
    }

    /**
     * @param array $claims
     * @return bool
     */
    private function checkScope(array $claims) : bool
    {
        return $this->claimsChecker->verifyScope($claims, $this->audience);
    }

    /**
     * @param string $message
     * @param array $context
     * @return Introspection
     */
    private function log(string $message, array $context = []) : self
    {
        if (null !== $this->logger) {
            $this->logger->debug($message, $context);
        }
        return $this;
    }
}
