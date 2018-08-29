<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/28/18
 * Time: 2:07 PM
 */

namespace Oauth\Services\Helpers;

use phpseclib\Crypt\AES;

class AesHelper implements AesHelperInterface
{
    /** @var AES */
    private $cipher;

    /** @var int */
    private $mode;

    /**
     * Set AES mode
     *
     * @param int $mode
     * @return AesHelperInterface
     */
    public function setMode(int $mode): AesHelperInterface
    {
        $this->mode = $mode;
        $this->cipher = new AES($mode);
        return $this;
    }

    /**
     * Set a custom padding algorithm
     *
     * @param string $noPaddedString
     * @param callable $ops
     * @return AesHelperInterface
     */
    public function setCustomPaddingMethod(string $noPaddedString, callable $ops): AesHelperInterface
    {
        // TODO: Implement setCustomPaddingMethod() method.
        return $this;
    }

    /**
     * Encrypt and encode plaintext
     *
     * @param string $key
     * @param string $plaintext
     * @param bool $autoPadding
     * @return string
     */
    public function aesEncrypt(string $key, string $plaintext, bool $autoPadding = true): string
    {
        $this->cipher->setKey($key);
        if (!$autoPadding) {
            $this->cipher->disablePadding();
        }
        return base64_encode($this->cipher->encrypt($plaintext));
    }

    /**
     * Decode and decrypt encoded/encrypted text
     *
     * @param string $key
     * @param string $encoded
     * @param bool $autoPadding
     * @return string
     */
    public function aesDecrypt(string $key, string $encoded, bool $autoPadding = true): string
    {
        $this->cipher->setKey($key);
        $encrypted = base64_decode($encoded);
        if (!$autoPadding) {
            $this->cipher->disablePadding();
        }
        return $this->cipher->decrypt($encrypted);
    }
}
