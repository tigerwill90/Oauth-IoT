<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 1:18 PM
 */

namespace Oauth\Services\Helpers;


use Jose\Component\Core\AlgorithmManagerFactory;

class AlgorithmManagerHelper implements AlgorithmManagerHelperInterface
{
    private const CL_SIGNATURE = 'Signature';
    private const CL_KEY_ENCRYPTION = 'KeyEncryption';
    private const CL_CONTENT_ENCRYPTION = 'ContentEncryption';

    /** @var AlgorithmManagerFactory  */
    private $algorithmManagerFactory;

    public function __construct(AlgorithmManagerFactory $algorithmManagerFactory)
    {
        $this->algorithmManagerFactory = $algorithmManagerFactory;
    }

    /**
     * Return a list of all supported algorithm alias
     * @return string[]
     */
    public function getAllAlgorithmAlias() : array
    {
        return $this->algorithmManagerFactory->aliases();
    }

    /**
     * Return a list of all supported signature alias
     * @return string[]
     */
    public function getSignatureAlgorithmAlias() : array
    {
        return $this->createAlgorithmAliasArray($this->algorithmManagerFactory->all(), self::CL_SIGNATURE);
    }

    /**
     * Return a list of all supported key encryption algorithm
     * @return string[]
     */
    public function getKeyEncryptionAlgorithmAlias() : array
    {
        return $this->createAlgorithmAliasArray($this->algorithmManagerFactory->all(), self::CL_KEY_ENCRYPTION);
    }

    /**
     * Return a list of all supported content key encryption algorithm
     * @return string[]
     */
    public function getContentEncryptionAlgorithmAlias() : array
    {
        return $this->createAlgorithmAliasArray($this->algorithmManagerFactory->all(), self::CL_CONTENT_ENCRYPTION);
    }

    /**
     * Create an an array of alias algorithm for a given type
     * @param array $algorithms
     * @param string $type
     * @return string[]
     */
    private function createAlgorithmAliasArray(array $algorithms, string $type) : array
    {
        $aliases = [];
        foreach ($algorithms as $alias => $algorithm) {
            if (strpos(str_replace('\\', '',  \get_class($algorithm)), $type) !== false) {
                $aliases[] = $alias;
            }
        }
        return $aliases;
    }
}