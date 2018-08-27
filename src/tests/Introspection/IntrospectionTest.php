<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/27/18
 * Time: 7:38 PM
 */

namespace Oauth\Tests\Introspection;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Oauth\Services\Introspection\Introspection;
use Oauth\Services\Jose\Jose;
use Oauth\Services\Jose\JoseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Http\Body;
use Slim\Http\Headers;
use Slim\Http\Request;
use PHPUnit\Framework\TestCase;
use Slim\Http\Uri;

class IntrospectionTest extends TestCase
{
    private const KEY = 'supersecretkeythatshouldnotbecommittogithub';

    private function requestFactory(string $method = 'POST') : ServerRequestInterface
    {
        $uri = Uri::createFromString('http://oauth/introspect');
        $headers = new Headers();
        $cookies = [];
        $serverParams = [];
        $body = new Body(fopen('php://temp', 'rb+'));
        return new Request($method, $uri, $headers, $cookies, $serverParams, $body);
    }

    private function getAlgorithmManager() : AlgorithmManagerFactory
    {
        $algorithmManagerFactory = new AlgorithmManagerFactory();
        return $algorithmManagerFactory
            ->add('HS256', new \Jose\Component\Signature\Algorithm\HS256())
            ->add('HS384', new \Jose\Component\Signature\Algorithm\HS384())
            ->add('HS512', new \Jose\Component\Signature\Algorithm\HS512());
    }

    private function getJoseService() : JoseInterface
    {
        $standardConvertor = new StandardConverter();
        $compactSerializer = new CompactSerializer($standardConvertor);
        $algorithmManager = $this->getAlgorithmManager();
        return new Jose($algorithmManager, $standardConvertor, $compactSerializer);
    }

    private function getJwsObject(string $key, int $iat, int $nbf, int $exp, string $keyType = 'oct', string $alg = 'HS256') : string
    {
        $payload = [
            Introspection::CLAIM_IAT => $iat,
            Introspection::CLAIM_NBF => $nbf,
            Introspection::CLAIM_EXP => $exp, // + 1 min
            Introspection::CLAIM_ISS => 'issuer',
            Introspection::CLAIM_AUD => 'audience',
            Introspection::CLAIM_SUB => 'subject',
            Introspection::CLAIM_JTI => 'nonce',
            Introspection::CLAIM_SCOPE => 'write_rs,read_rs'
        ];

        $joseService = $this->getJoseService();

        return $joseService
            ->createKey($key, $keyType)
            ->createAlgorithmManager([$alg])
            ->createJwsObject($payload, ['alg' => $alg, 'typ' => 'JWT'])
            ->serializeToken()
            ->getToken();
    }

    public function testShouldBeTrue() : void
    {
        $this->assertTrue(true);
    }

    /** This method implement a full test protocol token introspection for a valid PSR-7 request with valid signature */
    public function testIntrospectionShouldReturnActiveJsonResponse() : void
    {
        $introspection = new Introspection($this->getJoseService());
        $token = $this->getJwsObject(self::KEY, time(), time(), time() + 60);
        $request = $this->requestFactory()->withParsedBody([Introspection::PARAM_TOKEN => $token, Introspection::PARAM_TYPE_HINT => 'HS256', 'foo' => 'foo', 'bar' => 'bar']);
        $isValid = $introspection
            ->injectClaimsChecker(new ExtendClaimsTest())
            ->setClaimsToVerify([Introspection::CLAIM_EXP, Introspection::CLAIM_IAT, Introspection::CLAIM_NBF, Introspection::CLAIM_SUB, Introspection::CLAIM_AUD, Introspection::CLAIM_ISS, Introspection::CLAIM_JTI, Introspection::CLAIM_SCOPE])
            ->setRequestParameterToVerify(Introspection::PARAM_TOKEN, Introspection::PARAM_TYPE_HINT, ['foo', 'bar'])
            ->setResponseParameter([Introspection::RESP_ACTIVE, Introspection::RESP_AUD, Introspection::RESP_EXP, Introspection::RESP_IAT, Introspection::RESP_ISS, Introspection::RESP_JTI, Introspection::RESP_NBF, Introspection::RESP_SCOPE, Introspection::RESP_SUB, Introspection::RESP_TOKEN_TYPE], ['key' => '/super/secret/'])
            ->addUserInformation('John Doe', 10)
            ->introspectToken($request, self::KEY, 'oct');


        $arrayResponse = json_decode($introspection->getJsonResponse(), true);
        $this->assertTrue($isValid);
        $this->assertArrayHasKey(Introspection::RESP_ACTIVE, $arrayResponse);
        $this->assertTrue($arrayResponse[Introspection::RESP_ACTIVE]);
        $this->assertArrayHasKey(Introspection::RESP_USERNAME, $arrayResponse);
        $this->assertArrayHasKey(Introspection::RESP_CLIENT_ID, $arrayResponse);
        $this->assertArrayHasKey(Introspection::RESP_AUD, $arrayResponse);
        $this->assertArrayHasKey(Introspection::RESP_EXP, $arrayResponse);
        $this->assertArrayHasKey(Introspection::RESP_IAT, $arrayResponse);
        $this->assertArrayHasKey(Introspection::RESP_ISS, $arrayResponse);
        $this->assertArrayHasKey(Introspection::RESP_JTI, $arrayResponse);
        $this->assertArrayHasKey(Introspection::RESP_NBF, $arrayResponse);
        $this->assertArrayHasKey(Introspection::RESP_SCOPE, $arrayResponse);
        $this->assertArrayHasKey(Introspection::RESP_SUB, $arrayResponse);
        $this->assertArrayHasKey('key', $arrayResponse);
    }

    /** This method implement a full test protocol token introspection for a valid PSR-7 request with invalid signature */
    public function testIntrospectionShouldReturnInactiveJsonResponse() : void
    {
        $introspection = new Introspection($this->getJoseService());
        $token = $this->getJwsObject('thisisawrongkey', time(), time(), time() + 60);
        $request = $this->requestFactory()->withParsedBody([Introspection::PARAM_TOKEN => $token, Introspection::PARAM_TYPE_HINT => 'HS256', 'foo' => 'foo', 'bar' => 'bar']);
        $isValid = $introspection
            ->injectClaimsChecker(new ExtendClaimsTest())
            ->setClaimsToVerify([Introspection::CLAIM_EXP, Introspection::CLAIM_IAT, Introspection::CLAIM_NBF, Introspection::CLAIM_SUB, Introspection::CLAIM_AUD, Introspection::CLAIM_ISS, Introspection::CLAIM_JTI, Introspection::CLAIM_SCOPE])
            ->setRequestParameterToVerify(Introspection::PARAM_TOKEN, Introspection::PARAM_TYPE_HINT, ['foo', 'bar'])
            ->setResponseParameter([Introspection::RESP_ACTIVE, Introspection::RESP_AUD, Introspection::RESP_EXP, Introspection::RESP_IAT, Introspection::RESP_ISS, Introspection::RESP_JTI, Introspection::RESP_NBF, Introspection::RESP_SCOPE, Introspection::RESP_SUB, Introspection::RESP_TOKEN_TYPE], ['key' => '/super/secret/'])
            ->addUserInformation('John Doe', 10)
            ->introspectToken($request, self::KEY, 'oct');

        $this->assertTrue($isValid);
        $arrayResponse = json_decode($introspection->getJsonResponse(), true);
        $this->assertArrayHasKey(Introspection::RESP_ACTIVE, $arrayResponse);
        $this->assertFalse($arrayResponse[Introspection::RESP_ACTIVE]);
    }

    /** This method implement a full test protocol token introspection for an invalid PSR-7 request (invalid token) */
    public function testIntrospectionShouldReturnError() : void
    {
        $introspection = new Introspection($this->getJoseService());
        $request = $this->requestFactory()->withParsedBody([Introspection::PARAM_TOKEN => 'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MzU0MDcxNDAIm5iZiI6MTUzNTQwNzA4MCwiZXhwIjoxNTM1NDA4MDgwLCJpc3MiOiJNeSBzZXJ2aWNlIiwiYXVkIjoiWW91ciBhcHBsaWNhdGlvbiJ9.j4YUbyDgTMCojCQ2kE1NYg_gUckj73Rs-nD7rqKAWKNuIMjx10EpeQIXy1zhnd9u', Introspection::PARAM_TYPE_HINT => 'HS384', 'foo' => 'foo', 'bar' => 'bar']);

        $isValid = $introspection
            ->injectClaimsChecker(new ExtendClaimsTest())
            ->setClaimsToVerify([Introspection::CLAIM_EXP, Introspection::CLAIM_IAT, Introspection::CLAIM_NBF, Introspection::CLAIM_SUB, Introspection::CLAIM_AUD, Introspection::CLAIM_ISS, Introspection::CLAIM_JTI, Introspection::CLAIM_SCOPE])
            ->setRequestParameterToVerify(Introspection::PARAM_TOKEN, Introspection::PARAM_TYPE_HINT, ['foo', 'bar'])
            ->setResponseParameter([Introspection::RESP_ACTIVE, Introspection::RESP_AUD, Introspection::RESP_EXP, Introspection::RESP_IAT, Introspection::RESP_ISS, Introspection::RESP_JTI, Introspection::RESP_NBF, Introspection::RESP_SCOPE, Introspection::RESP_SUB, Introspection::RESP_TOKEN_TYPE], ['key' => '/super/secret/'])
            ->addUserInformation('John Doe', 10)
            ->introspectToken($request, self::KEY, 'oct');

        $this->assertFalse($isValid);
        $arrayResponse = json_decode($introspection->getJsonResponse(), true);
        $this->assertEquals([Introspection::ERROR => Introspection::ERROR_MSG], $arrayResponse);
    }
}
