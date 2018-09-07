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
use Psr\Log\LoggerInterface;

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

    /** @var array */
    private $headers;

    /** @var StandardConverter */
    private $jsonConverter;

    /** @var AlgorithmManagerFactory */
    private $algorithmManagerFactory;

    /** @var CompressionMethodManager */
    private $compressionMethodManager;

    /** @var LoggerInterface  */
    private $logger;

    /**
     * JoseHelper constructor.
     * @param AlgorithmManagerFactory $algorithmManagerFactory
     * @param CompressionMethodManager $compressionMethodManager
     * @param LoggerInterface|null $logger
     */
    public function __construct(AlgorithmManagerFactory $algorithmManagerFactory, CompressionMethodManager $compressionMethodManager, LoggerInterface $logger = null)
    {
        $this->jsonConverter = new StandardConverter();
        $this->algorithmManagerFactory = $algorithmManagerFactory;
        $this->compressionMethodManager = $compressionMethodManager;
        $this->logger = $logger;
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
     * Create a new JWS/JWE token
     * @param array $payload
     * @return string
     * @throws \Exception
     */
    public function createToken(array $payload): string
    {
        $encodedPayload = $this->jsonConverter->encode($payload);
        // Check mandatory JWK parameter
        if (!$this->jwk->has('use')) {
            throw new \InvalidArgumentException('The JWK must have the "use" parameter');
        }
        if (!$this->jwk->has('alg')) {
            throw new \InvalidArgumentException('The JWK must have the "alg" parameter');
        }
        if (!$this->jwk->has('kid') || empty($this->jwk->get('kid'))) {
            throw new \InvalidArgumentException('The JWK must have a no empty "kid" parameter');
        }

        if ($this->jwk->get('use') === 'sig') {
            $serializer = $this->getJwsCompactSerializerInterface();
            $jose = $this->createJwsBuilder($this->createAlgorithmManager([$this->jwk->get('alg')]))
                ->create()
                ->withPayload($encodedPayload)
                ->addSignature($this->jwk, ['alg' => $this->jwk->get('alg'), 'typ' => 'JWT', 'kid' => $this->jwk->get('kid')])
                ->build();
        } else {
            $serializer = $this->getJweCompactSerializerInterface();
            if (!$this->jwk->has('enc')) {
                throw new \InvalidArgumentException('The JWK must have the "enc" parameter to encrypt parameter');
            }
            // temp
            $jose = $this->createJweBuilder($this->createAlgorithmManager(array($this->jwk->get('alg'))), $this->createAlgorithmManager(array($this->jwk->get('enc'))))
                ->create()
                ->withPayload($encodedPayload)
                ->withSharedProtectedHeader([
                    'alg' => $this->jwk->get('alg'),
                    'enc' => $this->jwk->get('enc'),
                    'zip' => 'DEF',
                    'typ' => 'JWE',
                    'kid' => $this->jwk->get('kid')
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

        if (!$this->jwk->has('use')) {
            throw new \InvalidArgumentException('The JWK must have the "use" parameter');
        }
        if (!$this->jwk->has('alg')) {
            throw new \InvalidArgumentException('The JWK must have the "alg" parameter');
        }

        if ($this->jwk->get('use') === 'sig')  {
            try {
                $this->jws = $this->decodeJwsToken($this->token);
            } catch (\Exception $e) {
                throw $e;
            }

            return $this->createJwsVerifier($this->createAlgorithmManager([$this->jwk->get('alg')]))->verifyWithKey($this->jws, $this->jwk, 0);
        }

        if (!$this->jwk->has('enc')) {
            throw new \InvalidArgumentException('The JWK must have the "enc" parameter');
        }

        try {
            $this->jwe = $this->decodeJweToken($this->token);
        } catch (\Exception $e) {
            throw $e;
        }
        return $this->createJweDecrypter($this->createAlgorithmManager([$this->jwk->get('alg')]), $this->createAlgorithmManager([$this->jwk->get('enc')]))->decryptUsingKey($this->jwe, $this->jwk, 0);
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
        if (!$this->jwk->has('use')) {
            throw new \InvalidArgumentException('The JWK must have the "use" parameter');
        }

        if ($this->jwk->get('use') === 'sig') {
            if ($this->jws === null) {
                try {
                    $this->jws = $this->decodeJwsToken($this->token);
                } catch (\Exception $e) {
                    throw $e;
                }
            }
            return (array)$this->jsonConverter->decode($this->jws->getPayload(), true);
        }
        if (!$this->jwk->has('alg')) {
            throw new \InvalidArgumentException('The JWK must have the "alg" parameter');
        }
        if (!$this->jwk->has('enc')) {
            throw new \InvalidArgumentException('The JWK must have the "enc" parameter');
        }
        try {
            $recipient = 0;
            $this->jwe = $this->createJweLoader($this->createAlgorithmManager([$this->jwk->get('alg')]), $this->createAlgorithmManager([$this->jwk->get('enc')]))
                ->loadAndDecryptWithKey($this->token, $this->jwk, $recipient);
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

    /**
     * @param string $message
     * @param array $context
     * @return JoseHelper
     */
    private function log(string $message, array $context = []) : self
    {
        if (null !== $this->logger) {
            $this->logger->debug($message, $context);
        }
        return $this;
    }
}
