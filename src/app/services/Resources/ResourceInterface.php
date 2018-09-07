<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 9/3/18
 * Time: 6:00 PM
 */

namespace Oauth\Services\Resources;


interface ResourceInterface extends \JsonSerializable
{
    /**
     * @return ScopeInterface[]
     */
    public function getScope(): array;

    /**
     * @param array $scope
     * @return ResourceInterface
     */
    public function setScope(array $scope): ResourceInterface;

    /**
     * @return string
     */
    public function getPopMethod(): string;

    /**
     * @return string
     */
    public function getAudience(): string;
}