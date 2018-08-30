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
     *      'client' => ClientRegistrationValidator(),
     *      'alias' => RequestValidator();
     * ]
     * @var array
     */
    private $validators;

    /**
     * Register all RequestValidator
     * RequestValidatorManager constructor.
     * @param array $validators
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
        return false;
    }


}