<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 1:16 PM
 */

namespace Oauth\Services\Helpers;

interface AlgorithmManagerHelperInterface
{
    /**
     * Return a list of all supported algorithm alias
     * @return string[]
     */
    public function getAllAlgorithmAlias() : array;

    /**
     * Return a list of all supported signature alias
     * @return string[]
     */
    public function getSignatureAlgorithmAlias() : array;

    /**
     * Return a list of all supported key encryption algorithm
     * @return string[]
     */
    public function getKeyEncryptionAlgorithmAlias() : array;

    /**
     * Return a list of all supported content key encryption algorithm
     * @return string[]
     */
    public function getContentEncryptionAlgorithmAlias() : array;
}
