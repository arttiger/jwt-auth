<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Algorithms;

use ArtTiger\JWTAuth\Algorithms\AlgorithmRegistry;
use ArtTiger\JWTAuth\Algorithms\Es256;
use ArtTiger\JWTAuth\Algorithms\Es384;
use ArtTiger\JWTAuth\Algorithms\Es512;
use ArtTiger\JWTAuth\Algorithms\Hs256;
use ArtTiger\JWTAuth\Algorithms\Hs384;
use ArtTiger\JWTAuth\Algorithms\Hs512;
use ArtTiger\JWTAuth\Algorithms\Rs256;
use ArtTiger\JWTAuth\Algorithms\Rs384;
use ArtTiger\JWTAuth\Algorithms\Rs512;
use ArtTiger\JWTAuth\Exceptions\JWTException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;

class AlgorithmRegistryTest extends AbstractTestCase
{
    public function testAllReturnsNineAlgorithms(): void
    {
        $algorithms = AlgorithmRegistry::all();

        $this->assertCount(9, $algorithms);
    }

    public function testAllReturnsCorrectAlgorithmKeys(): void
    {
        $algorithms = AlgorithmRegistry::all();
        $keys = array_keys($algorithms);

        $this->assertSame(
            ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
            $keys
        );
    }

    public function testAllReturnsHs256Instance(): void
    {
        $this->assertInstanceOf(Hs256::class, AlgorithmRegistry::all()['HS256']);
    }

    public function testAllReturnsHs384Instance(): void
    {
        $this->assertInstanceOf(Hs384::class, AlgorithmRegistry::all()['HS384']);
    }

    public function testAllReturnsHs512Instance(): void
    {
        $this->assertInstanceOf(Hs512::class, AlgorithmRegistry::all()['HS512']);
    }

    public function testAllReturnsRs256Instance(): void
    {
        $this->assertInstanceOf(Rs256::class, AlgorithmRegistry::all()['RS256']);
    }

    public function testAllReturnsRs384Instance(): void
    {
        $this->assertInstanceOf(Rs384::class, AlgorithmRegistry::all()['RS384']);
    }

    public function testAllReturnsRs512Instance(): void
    {
        $this->assertInstanceOf(Rs512::class, AlgorithmRegistry::all()['RS512']);
    }

    public function testAllReturnsEs256Instance(): void
    {
        $this->assertInstanceOf(Es256::class, AlgorithmRegistry::all()['ES256']);
    }

    public function testAllReturnsEs384Instance(): void
    {
        $this->assertInstanceOf(Es384::class, AlgorithmRegistry::all()['ES384']);
    }

    public function testAllReturnsEs512Instance(): void
    {
        $this->assertInstanceOf(Es512::class, AlgorithmRegistry::all()['ES512']);
    }

    public function testFindReturnsHs256(): void
    {
        $this->assertInstanceOf(Hs256::class, AlgorithmRegistry::find('HS256'));
    }

    public function testFindReturnsHs384(): void
    {
        $this->assertInstanceOf(Hs384::class, AlgorithmRegistry::find('HS384'));
    }

    public function testFindReturnsHs512(): void
    {
        $this->assertInstanceOf(Hs512::class, AlgorithmRegistry::find('HS512'));
    }

    public function testFindReturnsRs256(): void
    {
        $this->assertInstanceOf(Rs256::class, AlgorithmRegistry::find('RS256'));
    }

    public function testFindReturnsRs384(): void
    {
        $this->assertInstanceOf(Rs384::class, AlgorithmRegistry::find('RS384'));
    }

    public function testFindReturnsRs512(): void
    {
        $this->assertInstanceOf(Rs512::class, AlgorithmRegistry::find('RS512'));
    }

    public function testFindReturnsEs256(): void
    {
        $this->assertInstanceOf(Es256::class, AlgorithmRegistry::find('ES256'));
    }

    public function testFindReturnsEs384(): void
    {
        $this->assertInstanceOf(Es384::class, AlgorithmRegistry::find('ES384'));
    }

    public function testFindReturnsEs512(): void
    {
        $this->assertInstanceOf(Es512::class, AlgorithmRegistry::find('ES512'));
    }

    public function testFindThrowsForLowercaseNone(): void
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('none');

        AlgorithmRegistry::find('none');
    }

    public function testFindThrowsForUppercaseNone(): void
    {
        $this->expectException(JWTException::class);

        AlgorithmRegistry::find('NONE');
    }

    public function testFindThrowsForMixedCaseNone(): void
    {
        $this->expectException(JWTException::class);

        AlgorithmRegistry::find('NoNe');
    }

    public function testFindThrowsForUnknownAlgorithm(): void
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('UNKNOWN');

        AlgorithmRegistry::find('UNKNOWN');
    }

    public function testFindThrowsWithMessageListingSupportedAlgorithms(): void
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('HS256');

        AlgorithmRegistry::find('UNSUPPORTED');
    }

    public function testFindThrowsForEmptyString(): void
    {
        $this->expectException(JWTException::class);

        AlgorithmRegistry::find('');
    }

    public function testSupportsReturnsTrueForKnownAlgorithms(): void
    {
        $this->assertTrue(AlgorithmRegistry::supports('HS256'));
        $this->assertTrue(AlgorithmRegistry::supports('HS384'));
        $this->assertTrue(AlgorithmRegistry::supports('HS512'));
        $this->assertTrue(AlgorithmRegistry::supports('RS256'));
        $this->assertTrue(AlgorithmRegistry::supports('RS384'));
        $this->assertTrue(AlgorithmRegistry::supports('RS512'));
        $this->assertTrue(AlgorithmRegistry::supports('ES256'));
        $this->assertTrue(AlgorithmRegistry::supports('ES384'));
        $this->assertTrue(AlgorithmRegistry::supports('ES512'));
    }

    public function testSupportsReturnsFalseForNone(): void
    {
        $this->assertFalse(AlgorithmRegistry::supports('none'));
        $this->assertFalse(AlgorithmRegistry::supports('NONE'));
    }

    public function testSupportsReturnsFalseForUnknownAlgorithm(): void
    {
        $this->assertFalse(AlgorithmRegistry::supports('UNKNOWN'));
        $this->assertFalse(AlgorithmRegistry::supports(''));
        $this->assertFalse(AlgorithmRegistry::supports('hs256')); // lowercase
    }
}
