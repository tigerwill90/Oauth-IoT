<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/28/18
 * Time: 1:54 PM
 */

namespace Oauth\Services\AesHelper;

interface AesHelperInterface
{
    /**
     * Set AES mode
     *
     * @param int $mode
     * @return AesHelperInterface
     */
    public function setMode(int $mode) : AesHelperInterface;

    /**
     * Set a custom padding algorithm
     *
     * @param string $noPaddedString
     * @param callable $ops
     * @return AesHelperInterface
     */
    public function setCustomPaddingMethod(string $noPaddedString, callable $ops) : AesHelperInterface;

    /**
     * Encrypt and encode plaintext
     *
     * @param string $key
     * @param string $plaintext
     * @param bool $autoPadding
     * @return string
     */
    public function aesEncrypt(string $key, string $plaintext, bool $autoPadding = true) : string;

    /**
     * Decode and decrypt encoded/encrypted text
     *
     * @param string $key
     * @param string $encoded
     * @param bool $autoPadding
     * @return string
     */
    public function aesDecrypt(string $key, string $encoded, bool $autoPadding = true) : string;
}
