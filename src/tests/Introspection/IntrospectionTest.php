<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/27/18
 * Time: 7:38 PM
 */

namespace Oauth\Tests\Introspection;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Oauth\Services\Helpers\AlgorithmManagerHelper;
use Oauth\Services\Helpers\AlgorithmManagerHelperInterface;
use Oauth\Services\Introspection;
use Oauth\Services\Helpers\JoseHelper;
use Oauth\Services\Helpers\JoseHelperInterface;
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
            ->add('HS512', new \Jose\Component\Signature\Algorithm\HS512())
            // JWE Key algorithm
            ->add('A128KW', new \Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW())
            ->add('A192KW', new \Jose\Component\Encryption\Algorithm\KeyEncryption\A192KW())
            ->add('A256KW', new \Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW())
            ->add('A128GCMKW', new \Jose\Component\Encryption\Algorithm\KeyEncryption\A128GCMKW())
            ->add('A192GCMKW', new \Jose\Component\Encryption\Algorithm\KeyEncryption\A192GCMKW())
            ->add('A256GCMKW', new \Jose\Component\Encryption\Algorithm\KeyEncryption\A256GCMKW())
            // JWE Content key algorithm
            ->add('A128CBC-HS256', new \Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256())
            ->add('A192CBC-HS384', new \Jose\Component\Encryption\Algorithm\ContentEncryption\A192CBCHS384())
            ->add('A256CBC-HS512', new \Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512())
            ->add('A128GCM', new \Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM())
            ->add('A192GCM', new \Jose\Component\Encryption\Algorithm\ContentEncryption\A192GCM())
            ->add('A256GCM', new \Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM());
    }

    private function getAlogrithmManagerHelper() : AlgorithmManagerHelperInterface
    {
        return new AlgorithmManagerHelper($this->getAlgorithmManager());
    }

    private function getJoseHelper() : JoseHelperInterface
    {
        $compressionMethodManager = CompressionMethodManager::create([
            new \Jose\Component\Encryption\Compression\Deflate()
        ]);
        return new JoseHelper($this->getAlgorithmManager(), $compressionMethodManager);
    }

    private function getJwsObject(string $key, int $iat, int $nbf, int $exp, string $keyType = 'oct', string $alg = 'HS256') : string
    {
        $payload = [
            Introspection::CLAIM_IAT => $iat,
            Introspection::CLAIM_NBF => $nbf,
            Introspection::CLAIM_EXP => $exp,
            Introspection::CLAIM_ISS => 'issuer',
            Introspection::CLAIM_AUD => 'audience',
            Introspection::CLAIM_SUB => 'subject',
            Introspection::CLAIM_JTI => 'nonce',
            Introspection::CLAIM_SCOPE => 'write_rs read_rs'
        ];

        $joseHelper = $this->getJoseHelper();

        return $joseHelper
            ->setJwk(JWK::create(['kty' => $keyType, 'k' => $key]))
            ->setJoseType(JoseHelperInterface::JWT)
            ->setJoseAlgorithm($alg)
            ->createJoseToken($payload);
    }

    public function testShouldBeTrue() : void
    {
        $this->assertTrue(true);
    }

    /** This method implement a full test for token introspection protocol with a valid PSR-7 request with valid signature */
    public function testIntrospectionShouldReturnActiveJsonResponse() : void
    {
        $introspection = new Introspection($this->getJoseHelper(), $this->getAlogrithmManagerHelper());
        $token = $this->getJwsObject(self::KEY, time(), time(), time() + 60);
        $request = $this->requestFactory()->withParsedBody([Introspection::PARAM_TOKEN => $token, Introspection::PARAM_TYPE_HINT => 'HS256', 'foo' => 'foo', 'bar' => 'bar']);
        $isValid = $introspection
            ->injectClaimsChecker(new ExtendClaimsTest())
            ->setClaimsToVerify([Introspection::CLAIM_EXP, Introspection::CLAIM_IAT, Introspection::CLAIM_NBF, Introspection::CLAIM_SUB, Introspection::CLAIM_AUD, Introspection::CLAIM_ISS, Introspection::CLAIM_JTI, Introspection::CLAIM_SCOPE])
            ->setRequestParameterToVerify(Introspection::PARAM_TOKEN, Introspection::PARAM_TYPE_HINT, ['foo', 'bar'])
            ->setActiveResponseParameter([Introspection::RESP_AUD, Introspection::RESP_EXP, Introspection::RESP_IAT, Introspection::RESP_ISS, Introspection::RESP_JTI, Introspection::RESP_NBF, Introspection::RESP_SCOPE, Introspection::RESP_SUB, Introspection::RESP_TOKEN_TYPE], 'John Doe', 10, ['key' => '/super/secret/'])
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

    /** This method implement a full test for token introspection protocol with a valid PSR-7 request with invalid signature */
    public function testIntrospectionShouldReturnInactiveJsonResponse() : void
    {
        $introspection = new Introspection($this->getJoseHelper(), $this->getAlogrithmManagerHelper());
        $token = $this->getJwsObject('thisisawrongkey', time(), time(), time() + 60);
        $request = $this->requestFactory()->withParsedBody([Introspection::PARAM_TOKEN => $token, Introspection::PARAM_TYPE_HINT => 'HS256', 'foo' => 'foo', 'bar' => 'bar']);
        $isValid = $introspection
            ->injectClaimsChecker(new ExtendClaimsTest())
            ->setClaimsToVerify([Introspection::CLAIM_EXP, Introspection::CLAIM_IAT, Introspection::CLAIM_NBF, Introspection::CLAIM_SUB, Introspection::CLAIM_AUD, Introspection::CLAIM_ISS, Introspection::CLAIM_JTI, Introspection::CLAIM_SCOPE])
            ->setRequestParameterToVerify(Introspection::PARAM_TOKEN, Introspection::PARAM_TYPE_HINT, ['foo', 'bar'])
            ->setActiveResponseParameter([Introspection::RESP_AUD, Introspection::RESP_EXP, Introspection::RESP_IAT, Introspection::RESP_ISS, Introspection::RESP_JTI, Introspection::RESP_NBF, Introspection::RESP_SCOPE, Introspection::RESP_SUB, Introspection::RESP_TOKEN_TYPE], 'John Doe', 10, ['key' => '/super/secret/'])
            ->introspectToken($request, self::KEY, 'oct');

        $this->assertTrue($isValid);
        $arrayResponse = json_decode($introspection->getJsonResponse(), true);
        $this->assertArrayHasKey(Introspection::RESP_ACTIVE, $arrayResponse);
        $this->assertFalse($arrayResponse[Introspection::RESP_ACTIVE]);
    }

    /** This method implement a full test for token introspection protocol with an invalid PSR-7 request (invalid token) */
    public function testIntrospectionShouldReturnError() : void
    {
        $introspection = new Introspection($this->getJoseHelper(), $this->getAlogrithmManagerHelper());
        $request = $this->requestFactory()->withParsedBody([Introspection::PARAM_TOKEN => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MzU1NDY1MTMsImp0aSI6IjAxMjM0NY3ODkifQ.cKadPlZjIhlHmc1_ltuAjvoWEjMBdr3grips3dpjv2w', Introspection::PARAM_TYPE_HINT => 'HS256', 'foo' => 'foo', 'bar' => 'bar']);

        $isValid = $introspection
            ->injectClaimsChecker(new ExtendClaimsTest())
            ->setClaimsToVerify([Introspection::CLAIM_EXP, Introspection::CLAIM_IAT, Introspection::CLAIM_NBF, Introspection::CLAIM_SUB, Introspection::CLAIM_AUD, Introspection::CLAIM_ISS, Introspection::CLAIM_JTI, Introspection::CLAIM_SCOPE])
            ->setRequestParameterToVerify(Introspection::PARAM_TOKEN, Introspection::PARAM_TYPE_HINT, ['foo', 'bar'])
            ->setActiveResponseParameter([Introspection::RESP_AUD, Introspection::RESP_EXP, Introspection::RESP_IAT, Introspection::RESP_ISS, Introspection::RESP_JTI, Introspection::RESP_NBF, Introspection::RESP_SCOPE, Introspection::RESP_SUB, Introspection::RESP_TOKEN_TYPE], 'John Doe', 10, ['key' => '/super/secret/'])
            ->introspectToken($request, self::KEY, 'oct');

        $this->assertFalse($isValid);
        $arrayResponse = json_decode($introspection->getJsonResponse(), true);
        $this->assertEquals([Introspection::ERROR => Introspection::ERROR_MSG], $arrayResponse);
    }

    /** This method implement multiple test for token introspection with invalid claim time */
    public function testIntrospectionShouldReturnInactiveJsonResponseWithTimeClaim() : void
    {
        $introspection = new Introspection($this->getJoseHelper(), $this->getAlogrithmManagerHelper());
        $nbf = time() + 10;
        $iat = time() + 15;
        $exp = time() - 60;
        $token1 = $this->getJwsObject(self::KEY, $iat, time(), time() + 20);
        $token2 = $this->getJwsObject(self::KEY, time(), $nbf, time() + 20);
        $token3 = $this->getJwsObject(self::KEY, time(), time(), $exp);
        $token4 = $this->getJwsObject(self::KEY, $iat, $nbf, $exp);
        $request1 = $this->requestFactory()->withParsedBody([Introspection::PARAM_TOKEN => $token1, Introspection::PARAM_TYPE_HINT => 'HS256', 'foo' => 'foo', 'bar' => 'bar']);
        $request2 = $this->requestFactory()->withParsedBody([Introspection::PARAM_TOKEN => $token2, Introspection::PARAM_TYPE_HINT => 'HS256', 'foo' => 'foo', 'bar' => 'bar']);
        $request3 = $this->requestFactory()->withParsedBody([Introspection::PARAM_TOKEN => $token3, Introspection::PARAM_TYPE_HINT => 'HS256', 'foo' => 'foo', 'bar' => 'bar']);
        $request4 = $this->requestFactory()->withParsedBody([Introspection::PARAM_TOKEN => $token4, Introspection::PARAM_TYPE_HINT => 'HS256', 'foo' => 'foo', 'bar' => 'bar']);

        $isValid1 = $introspection
            ->injectClaimsChecker(new ExtendClaimsTest())
            ->setClaimsToVerify([Introspection::CLAIM_EXP, Introspection::CLAIM_IAT, Introspection::CLAIM_NBF, Introspection::CLAIM_SUB, Introspection::CLAIM_AUD, Introspection::CLAIM_ISS, Introspection::CLAIM_JTI, Introspection::CLAIM_SCOPE])
            ->setRequestParameterToVerify(Introspection::PARAM_TOKEN, Introspection::PARAM_TYPE_HINT, ['foo', 'bar'])
            ->setActiveResponseParameter([Introspection::RESP_AUD, Introspection::RESP_EXP, Introspection::RESP_IAT, Introspection::RESP_ISS, Introspection::RESP_JTI, Introspection::RESP_NBF, Introspection::RESP_SCOPE, Introspection::RESP_SUB, Introspection::RESP_TOKEN_TYPE], 'John Doe', 10, ['key' => '/super/secret/'])
            ->introspectToken($request1, self::KEY, 'oct');

        $this->assertTrue($isValid1);
        $arrayResponse = json_decode($introspection->getJsonResponse(), true);
        $this->assertEquals($arrayResponse, [Introspection::RESP_ACTIVE => false]);
        $this->assertEquals($introspection->getInvalidClaims(), ['iat' => $iat]);

        $isValid2 = $introspection
            ->injectClaimsChecker(new ExtendClaimsTest())
            ->setClaimsToVerify([Introspection::CLAIM_EXP, Introspection::CLAIM_IAT, Introspection::CLAIM_NBF, Introspection::CLAIM_SUB, Introspection::CLAIM_AUD, Introspection::CLAIM_ISS, Introspection::CLAIM_JTI, Introspection::CLAIM_SCOPE])
            ->setRequestParameterToVerify(Introspection::PARAM_TOKEN, Introspection::PARAM_TYPE_HINT, ['foo', 'bar'])
            ->setActiveResponseParameter([Introspection::RESP_AUD, Introspection::RESP_EXP, Introspection::RESP_IAT, Introspection::RESP_ISS, Introspection::RESP_JTI, Introspection::RESP_NBF, Introspection::RESP_SCOPE, Introspection::RESP_SUB, Introspection::RESP_TOKEN_TYPE], 'John Doe', 10, ['key' => '/super/secret/'])
            ->introspectToken($request2, self::KEY, 'oct');

        $this->assertTrue($isValid2);
        $arrayResponse = json_decode($introspection->getJsonResponse(), true);
        $this->assertEquals($arrayResponse, [Introspection::RESP_ACTIVE => false]);
        $this->assertEquals($introspection->getInvalidClaims(), ['nbf' => $nbf]);

        $isValid3 = $introspection
            ->injectClaimsChecker(new ExtendClaimsTest())
            ->setClaimsToVerify([Introspection::CLAIM_EXP, Introspection::CLAIM_IAT, Introspection::CLAIM_NBF, Introspection::CLAIM_SUB, Introspection::CLAIM_AUD, Introspection::CLAIM_ISS, Introspection::CLAIM_JTI, Introspection::CLAIM_SCOPE])
            ->setRequestParameterToVerify(Introspection::PARAM_TOKEN, Introspection::PARAM_TYPE_HINT, ['foo', 'bar'])
            ->setActiveResponseParameter([Introspection::RESP_AUD, Introspection::RESP_EXP, Introspection::RESP_IAT, Introspection::RESP_ISS, Introspection::RESP_JTI, Introspection::RESP_NBF, Introspection::RESP_SCOPE, Introspection::RESP_SUB, Introspection::RESP_TOKEN_TYPE], 'John Doe', 10, ['key' => '/super/secret/'])
            ->introspectToken($request3, self::KEY, 'oct');

        $this->assertTrue($isValid3);
        $arrayResponse = json_decode($introspection->getJsonResponse(), true);
        $this->assertEquals($arrayResponse, [Introspection::RESP_ACTIVE => false]);
        $this->assertEquals($introspection->getInvalidClaims(), ['exp' => $exp]);

        $isValid4 = $introspection
            ->injectClaimsChecker(new ExtendClaimsTest())
            ->setClaimsToVerify([Introspection::CLAIM_EXP, Introspection::CLAIM_IAT, Introspection::CLAIM_NBF, Introspection::CLAIM_SUB, Introspection::CLAIM_AUD, Introspection::CLAIM_ISS, Introspection::CLAIM_JTI, Introspection::CLAIM_SCOPE])
            ->setRequestParameterToVerify(Introspection::PARAM_TOKEN, Introspection::PARAM_TYPE_HINT, ['foo', 'bar'])
            ->setActiveResponseParameter([Introspection::RESP_AUD, Introspection::RESP_EXP, Introspection::RESP_IAT, Introspection::RESP_ISS, Introspection::RESP_JTI, Introspection::RESP_NBF, Introspection::RESP_SCOPE, Introspection::RESP_SUB, Introspection::RESP_TOKEN_TYPE], 'John Doe', 10, ['key' => '/super/secret/'])
            ->introspectToken($request4, self::KEY, 'oct');

        $this->assertTrue($isValid4);
        $arrayResponse = json_decode($introspection->getJsonResponse(), true);
        $this->assertEquals($arrayResponse, [Introspection::RESP_ACTIVE => false]);
        $this->assertEquals($introspection->getInvalidClaims(), ['exp' => $exp, 'iat' => $iat, 'nbf' => $nbf]);
    }
}
