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
use Jose\Component\Signature\Signature;


class Jose implements JoseInterface
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

    /** @var Signature */
    private $signatures;

    /** @var array */
    private $headers;

    /** @var array */
    private $claims;

    /** @var CompactSerializer */
    private $serializer;

    /** @var string */
    private $token;

    public function __construct(AlgorithmManagerFactory $algorithmManagerFactory, StandardConverter $jsonConverter, CompactSerializer $serializer)
    {
        $this->algorithmManagerFactory = $algorithmManagerFactory;
        $this->jsonConverter = $jsonConverter;
        $this->serializer = $serializer;
    }

    /**
     * Get the string token
     *
     * @return string
     */
    public function getToken() : string
    {
        return $this->token;
    }

    /**
     * Set the string token
     *
     * @param string $token
     * @return Jose
     */
    public function setToken(string $token) : JoseInterface
    {
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
     * Get headers
     *
     * @return array
     */
    public function getHeaders() : array
    {
        if (null !== $this->headers) {
            return $this->headers[0];
        }

        return [];
    }

    /**
     * Create a new Jwt Object
     *
     * @param array $payload
     * @param array $headers
     * @return Jose
     */
    public function createJwsObject(array $payload, array $headers) : JoseInterface
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
    public function decodeJwsObject() : JoseInterface
    {
        if (null !== $this->jws) {
            $this->claims = $this->jsonConverter->decode($this->jws->getPayload());
            $this->signatures = $this->jws->getSignatures();
            foreach ($this->signatures as $signature) {
                $this->headers[] = $signature->getProtectedHeader();
            }
        }
        return $this;
    }

    /**
     * Create a new algorithm manager
     *
     * @param array $alias
     * @return JoseInterface
     */
    public function createAlgorithmManager(array $alias) : JoseInterface
    {
        $this->algorithmManager = $this->algorithmManagerFactory->create($alias);
        return $this;
    }

    /**
     * Create a new key
     *
     * @param string $key
     * @param string $keyType
     * @return JoseInterface
     */
    public function createKey(string $key, string $keyType) : JoseInterface
    {
        $this->jwk = JWK::create([
            'kty' => $keyType,
            'k' => $key
        ]);
        return $this;
    }

    /**
     * Serialize the jws object
     *
     * @param int $signatureIndex
     * @return JoseInterface
     */
    public function serializeToken(int $signatureIndex = 0) : JoseInterface
    {
        try {
            $this->token = $this->serializer->serialize($this->jws, $signatureIndex);
        } catch (\Exception $e) {
            error_log($e->getMessage());
        }
        return $this;
    }

    /**
     * Deserialize the token into jws object
     *
     * @return JoseInterface
     */
    public function deserializeToken() : JoseInterface
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
     * Check if jws object is null (a null object is invalid object)
     * @return bool
     */
    public function isValidToken() : bool
    {
        return null !== $this->jws;
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
