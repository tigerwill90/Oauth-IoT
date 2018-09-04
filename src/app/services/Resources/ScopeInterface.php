<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 9/3/18
 * Time: 6:04 PM
 */

namespace Oauth\Services\Resources;

interface ScopeInterface extends \JsonSerializable
{
    /**
     * @return string
     */
    public function getService(): string;

    /**
     * @return string
     */
    public function getName(): string;

    /**
     * @return string
     */
    public function getDescription(): string;
}
