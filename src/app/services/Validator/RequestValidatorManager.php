<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 7:57 PM
 */

namespace Oauth\Services\Validators;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Responsibility : Manage and call all request validator
 * Class RequestValidatorManager
 * @package Oauth\Services\Validators
 */
class RequestValidatorManager
{
    /**
     * <code>
     * $validators = [
     *      'client' => RequestValidator(),
     *      'alias' => RequestValidator();
     * ]
     * @var array[string]RequestValidator
     */
    private $validators;

    /**
     * Register all RequestValidator
     * RequestValidatorManager constructor.
     * @param array[string]RequestValidator $validators
     */
    public function __construct(array $validators)
    {
        $this->validators = $validators;
    }

    /**
     * Validate the request for all RequestValidator
     * @param array $validatorsAlias
     * @param ServerRequestInterface $request
     * @return bool
     */
    public function validate(array $validatorsAlias, ServerRequestInterface $request) : bool
    {
        foreach ($validatorsAlias as $alias) {
            $this->validators[$alias]->validateParameters($request);
        }
     }


}