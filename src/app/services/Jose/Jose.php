<?php

namespace Oauth\Services\Jose;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;


class Jose
{
    /** @var AlgorithmManagerFactory */
    private $algorithmManagerFactory;

    /** @var AlgorithmManager */
    private $algorithmManager;

    /** @var JWK */
    private $jwk;

    /** @var StandardConverter */
    private $jsonConverter;

    /** @var JWS */
    private $jws;

    /** @var array */
    private $claims;

    /** @var CompactSerializer */
    private $serializer;

    /** @var string */
    private $token;

    public function __construct(AlgorithmManagerFactory $algorithmManagerFactory)
    {
        $this->algorithmManagerFactory = $algorithmManagerFactory;
        $this->jsonConverter = new StandardConverter();
        $this->serializer = new CompactSerializer($this->jsonConverter);
    }

    /**
     * Get the string token
     *
     * @return string
     */
    public function getToken() : string {
        return $this->token;
    }

    /**
     * Set the string token
     *
     * @param string $token
     * @return Jose
     */
    public function setToken(string $token) : self {
        unset($this->token);
        $this->token = $token;
        return $this;
    }

    /**
     * Get claims array
     *
     * @return array
     */
    public function getClaims() : array
    {
        if (null !== $this->claims) {
            return $this->claims;
        }

        return [];
    }

    /**
     * Create and return a new Jwt Object
     *
     * @param array $payload
     * @param array $headers
     * @return Jose
     */
    public function createJwsObject(array $payload, array $headers) : self
    {
        $encodedPayload = $this->jsonConverter->encode($payload);

        $this->jws = $this->createJwsBuilder($this->algorithmManager, $this->jsonConverter)
            ->create()
            ->withPayload($encodedPayload)
            ->addSignature($this->jwk, $headers)
            ->build();

        return $this;
    }

    /**
     * Check the validity of signature
     *
     * @param int $signatureIndex
     * @return bool
     */
    public function verifyJwsObject(int $signatureIndex = 0) : bool
    {
        if (null !== $this->jws) {
            return $this->createJwsVerifier($this->algorithmManager)->verifyWithKey($this->jws, $this->jwk, $signatureIndex);
        }
        return false;
    }

    /**
     * Decode the jws object payload
     *
     * @return Jose
     */
    public function decodeJwsObject() : self
    {
        if (null !== $this->jws) {
            $this->claims = $this->jsonConverter->decode($this->jws->getPayload());
        }
        return $this;
    }

    /**
     * Create a new algorithm manager
     *
     * @param array $alias
     * @return Jose
     */
    public function createAlgorithmManager(array $alias) : self
    {
        $this->algorithmManager = $this->algorithmManagerFactory->create($alias);
        return $this;
    }

    /**
     * Create a new key
     *
     * @param string $key
     * @return Jose
     */
    public function createKey(string $key) : self
    {
        $this->jwk = JWK::create([
            'kty' => 'oct',
            'k' => $key
        ]);
        return $this;
    }

    /**
     * Serialize the jws object
     *
     * @param int $signatureIndex
     * @return Jose
     */
    public function serializeToken(int $signatureIndex = 0) : self {
        try {
            $this->token = $this->serializer->serialize($this->jws, $signatureIndex);
        } catch (\Exception $e) {
            error_log($e->getMessage());
        }
        return $this;
    }

    /**
     * Unserialize the token into jws object
     *
     * @return Jose
     */
    public function unserializeToken() : self
    {
        unset($this->jws);
        try {
            $this->jws = $this->serializer->unserialize($this->token);
        } catch (\Exception $e) {
            error_log($e->getMessage());
        }
        return $this;
    }

    /**
     * Create a new jws builder
     *
     * @param AlgorithmManager $algorithmManager
     * @param StandardConverter $standardConverter
     * @return JWSBuilder
     */
    private function createJwsBuilder(AlgorithmManager $algorithmManager, StandardConverter $standardConverter) : JWSBuilder
    {
        return new JWSBuilder($standardConverter, $algorithmManager);
    }

    /**
     * Create a new jws verifier
     *
     * @param AlgorithmManager $algorithmManager
     * @return JWSVerifier
     */
    private function createJwsVerifier(AlgorithmManager $algorithmManager) : JWSVerifier
    {
        return new JWSVerifier($algorithmManager);
    }

}
