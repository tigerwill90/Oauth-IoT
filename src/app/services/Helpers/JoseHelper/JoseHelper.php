<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/28/18
 * Time: 3:32 PM
 */

namespace Oauth\Services\Helpers;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\JWESerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\JWSSerializer;

class JoseHelper implements JoseHelperInterface
{
    /** @var JWK */
    private $jwk;

    /** @var JWE */
    private $jwe;

    /** @var JWS */
    private $jws;

    /** @var string */
    private $token;

    /** @var string */
    private $joseType = self::JWT;

    /** @var string  */
    private $keyAlg;

    /** @var  */
    private $keyContent;

    /** @var int */
    private $sig;

    /** @var array */
    private $headers;

    /** @var StandardConverter */
    private $jsonConverter;

    /** @var AlgorithmManagerFactory */
    private $algorithmManagerFactory;

    /** @var CompressionMethodManager */
    private $compressionMethodManager;

    /**
     * JoseHelper constructor.
     * @param AlgorithmManagerFactory $algorithmManagerFactory
     * @param CompressionMethodManager $compressionMethodManager
     */
    public function __construct(AlgorithmManagerFactory $algorithmManagerFactory, CompressionMethodManager $compressionMethodManager)
    {
        $this->jsonConverter = new StandardConverter();
        $this->algorithmManagerFactory = $algorithmManagerFactory;
        $this->compressionMethodManager = $compressionMethodManager;
    }

    /**
     * Set JWK
     * @param string $key
     * @param string $keyType
     * @return JoseHelperInterface
     * @throws
     */
    public function setJwkKey(string $key, string $keyType = self::OCT): JoseHelperInterface
    {
        $this->jwk = JWK::create([
            'kty' => $keyType,
            'k' => $key
        ]);
        return $this;
    }

    /**
     * Set a JWK object
     * @param JWK $jwk
     * @return JoseHelperInterface
     */
    public function setJwk(JWK $jwk) : JoseHelperInterface
    {
        $this->jwk = $jwk;
        return $this;
    }

    /**
     * Set JoseHelper type
     * @param string $joseType
     * @return JoseHelperInterface
     */
    public function setType(string $joseType = self::JWT): JoseHelperInterface
    {
        if (!\in_array(strtoupper($joseType), [self::JWT, self::JWE], true)) {
            throw new \InvalidArgumentException('Only JWE and JWT are supported yet');
        }
        $this->joseType = strtoupper($joseType);
        return $this;
    }

    /**
     * Set token
     * @param string $token
     * @return JoseHelperInterface
     */
    public function setToken(string $token): JoseHelperInterface
    {
        $this->token = $token;
        return $this;
    }

    /**
     * Set algorithm
     * @param string $keyAlg
     * @param string|null $keyContent
     * @param int $sig
     * @return JoseHelperInterface
     */
    public function setAlgorithm(string $keyAlg, string $keyContent = null, int $sig = 0) : JoseHelperInterface
    {
        $this->keyAlg = $keyAlg;
        $this->keyContent = $keyContent;
        $this->sig = $sig;
        return $this;
    }


    /**
     * Create a new JWS/JWE token
     * @param array $payload
     * @return string
     * @throws \Exception
     */
    public function createToken(array $payload): string
    {
        $encodedPayload = $this->jsonConverter->encode($payload);
        if ($this->joseType === self::JWT) {
            $serializer = $this->getJwsCompactSerializerInterface();
            $jose = $this->createJwsBuilder($this->createAlgorithmManager([$this->keyAlg]))
                ->create()
                ->withPayload($encodedPayload)
                ->addSignature($this->jwk, ['alg' => $this->keyAlg, 'typ' => $this->joseType])
                ->build();
        } else {
            $serializer = $this->getJweCompactSerializerInterface();
            if ($this->keyContent === null) {
                throw new \InvalidArgumentException('Key for content must be set in JWE mode');
            }
            // temp
            $jose = $this->createJweBuilder($this->createAlgorithmManager(array($this->keyAlg)), $this->createAlgorithmManager(array($this->keyContent)))
                ->create()
                ->withPayload($encodedPayload)
                ->withSharedProtectedHeader([
                    'alg' => $this->keyAlg,
                    'enc' => $this->keyContent,
                    'zip' => 'DEF',
                    'typ' => $this->joseType
                ])
                ->addRecipient($this->jwk)
                ->build();
        }
        try {
            $this->token = $serializer->serialize($jose, 0);
            return $this->token;
        } catch (\Exception $e) {
            throw $e;
        }
    }

    /**
     * Return true if the token is correctly signed, throw an exception if the token is invalid
     * @return bool
     * @throws \Exception
     */
    public function verifyToken(): bool
    {
        unset($this->jwe, $this->jws);
        if ($this->joseType === self::JWT)  {
            try {
                $this->jws = $this->decodeJwsToken($this->token);
            } catch (\Exception $e) {
                throw $e;
            }
            return $this->createJwsVerifier($this->createAlgorithmManager([$this->keyAlg]))->verifyWithKey($this->jws, $this->jwk, $this->sig);
        }
        try {
            $this->jwe = $this->decodeJweToken($this->token);
        } catch (\Exception $e) {
            throw $e;
        }
        return $this->createJweDecrypter($this->createAlgorithmManager([$this->keyAlg]), $this->createAlgorithmManager([$this->keyContent]))->decryptUsingKey($this->jwe, $this->jwk, $this->sig);
    }

    /**
     * Return an array with all headers of JOSE, throw and exception if token is invalid
     * A JWE is invalid if certain part of signature or the header is invalid
     * A JWS is invalid if the payload ord the header is invalid
     * @return array
     * @throws \Exception
     */
    public function getHeaders(): array
    {
        try {
            $this->jws = $this->decodeJwsToken($this->token);
        } catch (\Exception $e) {
            try {
                $this->jwe = $this->decodeJweToken($this->token);
            } catch (\Exception $e) {
                throw $e;
            }
            return $this->jwe->getSharedProtectedHeader();
        }
        $signatures = $this->jws->getSignatures();
        foreach ($signatures as $signature) {
            $this->headers[] = $signature->getProtectedHeader();
        }
        return $this->headers[0];
    }

    /**
     * Return a an array with all claims of JOSE, throw an exception if token is invalid
     * or if the JWE can not be decrypted
     * @return array
     * @throws \Exception
     */
    public function getClaims() : array
    {
        if ($this->joseType === self::JWT) {
            if ($this->jws === null) {
                try {
                    $this->jws = $this->decodeJwsToken($this->token);
                } catch (\Exception $e) {
                    throw $e;
                }
            }
            return (array)$this->jsonConverter->decode($this->jws->getPayload(), true);
        }
        try {
            $this->jwe = $this->createJweLoader($this->createAlgorithmManager([$this->keyAlg]), $this->createAlgorithmManager([$this->keyContent]))
                ->loadAndDecryptWithKey($this->token, $this->jwk, $this->sig);
        } catch (\Exception $e) {
            throw $e;
        }
        return (array)$this->jsonConverter->decode($this->jwe->getPayload(), true);
    }

    //public function getSupportedAlgorithmJwsK

    /**
     * Decode de JWS token, throw an exception if the token is invalid
     * @param string $jwsToken
     * @return JWS
     * @throws \Exception
     */
    private function decodeJwsToken(string $jwsToken) : JWS
    {
        $serializer = $this->getJwsCompactSerializerInterface();
        try {
            return $serializer->unserialize($jwsToken);
        } catch (\Exception $e) {
            throw $e;
        }
    }

    /**
     * Decode a JWE token, throw and exception if the token is invalid
     * @param string $jweToken
     * @return JWE
     * @throws \Exception
     */
    private function decodeJweToken(string $jweToken) : JWE
    {
        $serializer = $this->getJweCompactSerializerInterface();
        try {
            return $serializer->unserialize($jweToken);
        } catch (\Exception $e) {
            throw $e;
        }
    }

    /**
     * Get an instance who implement a JWSSerializer
     * @return JWSSerializer
     */
    private function getJwsCompactSerializerInterface(): JWSSerializer
    {
        return new \Jose\Component\Signature\Serializer\CompactSerializer($this->jsonConverter);
    }

    /**
     * Get an instance who implement a JWESerializer
     * @return JWESerializer
     */
    private function getJweCompactSerializerInterface(): JWESerializer
    {
        return new \Jose\Component\Encryption\Serializer\CompactSerializer($this->jsonConverter);
    }

    /**
     * Create a JWESerializerManager
     * @return JWESerializerManager
     */
    private function createJweSerializerManager(): JWESerializerManager
    {
        return JWESerializerManager::create([$this->getJweCompactSerializerInterface()]);
    }

    /**
     * Create an AlgorithmManager
     * @param array $alias
     * @return AlgorithmManager
     */
    private function createAlgorithmManager(array $alias) : AlgorithmManager
    {
        return $this->algorithmManagerFactory->create($alias);
    }

    /**
     * Create a JWSBuilder
     * @param AlgorithmManager $algorithmManager
     * @return JWSBuilder
     */
    private function createJwsBuilder(AlgorithmManager $algorithmManager) : JWSBuilder
    {
        return new JWSBuilder($this->jsonConverter, $algorithmManager);
    }

    /**
     * Create a JWEBuilder
     * @param AlgorithmManager $keyEncryptionAlgorithmManager
     * @param AlgorithmManager $contentEncryptionAlgorithmManager
     * @return JWEBuilder
     */
    private function createJweBuilder(AlgorithmManager $keyEncryptionAlgorithmManager, AlgorithmManager $contentEncryptionAlgorithmManager) : JWEBuilder
    {
        return new JWEBuilder($this->jsonConverter, $keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $this->compressionMethodManager);
    }

    /**
     * Create a JWSVerifier
     * @param AlgorithmManager $algorithmManager
     * @return JWSVerifier
     */
    private function createJwsVerifier(AlgorithmManager $algorithmManager) : JWSVerifier
    {
        return new JWSVerifier($algorithmManager);
    }

    /**
     * Create a JWEDecrypter
     * @param AlgorithmManager $keyEncryptionAlgorithmManager
     * @param AlgorithmManager $contentEncryptionAlgorithmManager
     * @return JWEDecrypter
     */
    private function createJweDecrypter(AlgorithmManager $keyEncryptionAlgorithmManager, AlgorithmManager $contentEncryptionAlgorithmManager) : JWEDecrypter
    {
        return new JWEDecrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $this->compressionMethodManager);
    }

    /**
     * Create a JWELoader
     * @param AlgorithmManager $keyEncryptionAlgorithmManager
     * @param AlgorithmManager $contentEncryptionAlgorithmManager
     * @return JWELoader
     */
    private function createJweLoader(AlgorithmManager $keyEncryptionAlgorithmManager, AlgorithmManager $contentEncryptionAlgorithmManager) : JWELoader
    {
        return new JWELoader($this->createJweSerializerManager(), $this->createJweDecrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager), null);
    }
}
